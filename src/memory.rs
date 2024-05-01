use bitflags::bitflags;
use core::fmt::Debug;
use core::ops::{Index, IndexMut};
use limine::memory_map::EntryType;
use limine::response::MemoryMapResponse;
use snafu::Snafu;
use x86_64::instructions::tlb;

pub const PAGE_SIZE: usize = 4096;
pub const FRAME_SIZE: usize = 4096;

pub struct MemoryManager {
    frame_allocator: FrameAllocator,
    physical_memory_offset: u64,
}

impl MemoryManager {
    pub fn new(frame_allocator: FrameAllocator, physical_memory_offset: u64) -> Self {
        Self {
            frame_allocator,
            physical_memory_offset,
        }
    }

    pub fn allocate_frame(&mut self) -> Option<Frame> {
        self.frame_allocator.allocate()
    }

    pub unsafe fn map(
        &mut self,
        page: &Page,
        frame: &Frame,
        page_flags: PageFlags,
    ) -> Result<(), MemoryError> {
        self.map_inner(page, frame, page_flags)
    }

    pub unsafe fn map_temporary(
        &mut self,
        page: &Page,
        frame: &Frame,
        page_flags: PageFlags,
        f: impl FnOnce(),
    ) -> Result<(), MemoryError> {
        self.map(page, frame, page_flags)?;

        f();

        self.unmap(page)
    }

    pub unsafe fn map_identity(
        &mut self,
        page: &Page,
        page_flags: PageFlags,
    ) -> Result<(), MemoryError> {
        self.map(
            page,
            &Frame::new(PhysicalAddress::new(page.address().as_u64())),
            page_flags,
        )
    }

    pub unsafe fn map_identity_temporary(
        &mut self,
        page: &Page,
        page_flags: PageFlags,
        f: impl FnOnce(),
    ) -> Result<(), MemoryError> {
        self.map_identity(page, page_flags)?;

        f();

        self.unmap(page)
    }

    pub unsafe fn map_any(&mut self, frame: &Frame, page_flags: PageFlags) -> Page {
        self.map_any_inner(frame, page_flags)
    }

    pub unsafe fn map_any_temporary(
        &mut self,
        frame: &Frame,
        page_flags: PageFlags,
        f: impl FnOnce(Page),
    ) -> Result<(), MemoryError> {
        let page = self.map_any(frame, page_flags);

        f(page);

        self.unmap(&page)
    }

    pub unsafe fn unmap(&self, page: &Page) -> Result<(), MemoryError> {
        self.unmap_inner(page)
    }

    pub fn translate_virtual_address_to_physical(
        &self,
        address: VirtualAddress,
    ) -> Option<PhysicalAddress> {
        // | 63 | ... | 49 | 48 | ... | 40 | 39 | ... | 31 | 30 | ... | 22 | 21 | ... | 12 | 11 | ... | 0 |
        // | Unused        | Page level 4  | Page level 3  | Page level 2  | Page level 1  | 4 KiB offset |
        let offset = address.as_u64() & 0b1111_1111_1111;
        let level_1_page_table_entry_index = ((address.as_u64() >> 12) & 0b1_1111_1111) as usize;
        let level_2_page_table_entry_index = ((address.as_u64() >> 21) & 0b1_1111_1111) as usize;
        let level_3_page_table_entry_index = ((address.as_u64() >> 30) & 0b1_1111_1111) as usize;
        let level_4_page_table_entry_index = ((address.as_u64() >> 39) & 0b1_1111_1111) as usize;

        let level_4_page_table = unsafe { current_page_table(self.physical_memory_offset) };
        let level_4_page_table_entry =
            &mut unsafe { &mut *level_4_page_table }[level_4_page_table_entry_index];

        if !level_4_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return None;
        }

        // Addresses in page table entries are all physical,
        // otherwise they'd need to get translated as well and that would not only be terribly slow
        // but could also lead to infinite recursion of translations.
        // As we can't access physical memory directly when we are in long mode,
        // we need to translate them manually to virtual addresses.
        // We can do that easily because of the way limine mapped them for us - using higher half direct mapping.
        // Which means we only need to add/subtract the offset we got from limine to convert addresses
        // from physical to virtual and vice versa.
        let level_3_page_table: *mut PageTable = VirtualAddress(
            level_4_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_3_page_table_entry =
            &mut unsafe { &mut *level_3_page_table }[level_3_page_table_entry_index];

        if !level_3_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return None;
        }

        // Same as `level_3_page_table`
        let level_2_page_table: *mut PageTable = VirtualAddress(
            level_3_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_2_page_table_entry =
            &mut unsafe { &mut *level_2_page_table }[level_2_page_table_entry_index];

        if !level_2_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return None;
        }

        // Same as `level_3_page_table`
        let level_1_page_table: *mut PageTable = VirtualAddress(
            level_2_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_1_page_table_entry =
            &mut unsafe { &mut *level_1_page_table }[level_1_page_table_entry_index];

        if !level_1_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return None;
        }

        Some(PhysicalAddress(
            level_1_page_table_entry.address().as_u64() + offset,
        ))
    }

    fn map_inner(
        &mut self,
        page: &Page,
        frame: &Frame,
        page_flags: PageFlags,
    ) -> Result<(), MemoryError> {
        let address = page.address();

        // | 63 | ... | 49 | 48 | ... | 40 | 39 | ... | 31 | 30 | ... | 22 | 21 | ... | 12 | 11 | ... | 0 |
        // | Unused        | Page level 4  | Page level 3  | Page level 2  | Page level 1  | 4 KiB offset |
        let offset = address.as_u64() & 0b1111_1111_1111;
        let level_1_page_table_entry_index = ((address.as_u64() >> 12) & 0b1_1111_1111) as usize;
        let level_2_page_table_entry_index = ((address.as_u64() >> 21) & 0b1_1111_1111) as usize;
        let level_3_page_table_entry_index = ((address.as_u64() >> 30) & 0b1_1111_1111) as usize;
        let level_4_page_table_entry_index = ((address.as_u64() >> 39) & 0b1_1111_1111) as usize;

        assert_eq!(offset, 0);

        let level_4_page_table = unsafe { current_page_table(self.physical_memory_offset) };
        let level_4_page_table_entry =
            &mut unsafe { &mut *level_4_page_table }[level_4_page_table_entry_index];

        if !level_4_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            self.allocate_lower_level_page_table(level_4_page_table_entry)
                .expect("Failed to allocate L3 page table");
        }

        self.assign_propagable_page_flags_to_page_table_entry(level_4_page_table_entry, page_flags);

        // Addresses in page table entries are all physical,
        // otherwise they'd need to get translated as well and that would not only be terribly slow
        // but could also lead to infinite recursion of translations.
        // As we can't access physical memory directly when we are in long mode,
        // we need to translate them manually to virtual addresses.
        // We can do that easily because of the way limine mapped them for us - using higher half direct mapping.
        // Which means we only need to add/subtract the offset we got from limine to convert addresses
        // from physical to virtual and vice versa.
        let level_3_page_table: *mut PageTable = VirtualAddress(
            level_4_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_3_page_table_entry =
            &mut unsafe { &mut *level_3_page_table }[level_3_page_table_entry_index];

        if !level_3_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            self.allocate_lower_level_page_table(level_3_page_table_entry)
                .expect("Failed to allocate L2 page table");
        }

        self.assign_propagable_page_flags_to_page_table_entry(level_3_page_table_entry, page_flags);

        // Same as `level_3_page_table`
        let level_2_page_table: *mut PageTable = VirtualAddress(
            level_3_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_2_page_table_entry =
            &mut unsafe { &mut *level_2_page_table }[level_2_page_table_entry_index];

        if !level_2_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            self.allocate_lower_level_page_table(level_2_page_table_entry)
                .expect("Failed to allocate L1 page table");
        }

        self.assign_propagable_page_flags_to_page_table_entry(level_2_page_table_entry, page_flags);

        // Same as `level_3_page_table`
        let level_1_page_table: *mut PageTable = VirtualAddress(
            level_2_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_1_page_table_entry =
            &mut unsafe { &mut *level_1_page_table }[level_1_page_table_entry_index];

        if level_1_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return Err(MemoryError::AlreadyMapped);
        }

        level_1_page_table_entry.set_address(frame.address());
        level_1_page_table_entry.set_flags(PageTableFlags::PRESENT);

        self.assign_propagable_page_flags_to_page_table_entry(level_1_page_table_entry, page_flags);

        if !page_flags.contains(PageFlags::EXECUTABLE) {
            level_1_page_table_entry
                .set_flags(level_1_page_table_entry.flags() | PageTableFlags::NO_EXECUTE);
        }

        if page_flags.contains(PageFlags::WRITE_THROUGH) {
            level_1_page_table_entry
                .set_flags(level_1_page_table_entry.flags() | PageTableFlags::WRITE_THROUGH);
        }

        if page_flags.contains(PageFlags::DISABLE_CACHING) {
            level_1_page_table_entry
                .set_flags(level_1_page_table_entry.flags() | PageTableFlags::NO_CACHE);
        }

        // The TLB (translation lookaside buffer) holds results of previous translations and
        // allows the CPU to skip a lot of additional work in case it was already computed before and
        // is present in the cache.
        // Hence, after each page table modification, we need to flush all relevant TLB entries.
        // If we didn't, there would be **horrible**, hard to track bugs.
        //
        // TODO: TLB misses are really inefficient, thus flushing the entire TLB is non optimal.
        //       Optimizing this at the moment doesn't make much sense,
        //       but it needs to be done in the future.
        tlb::flush_all();

        Ok(())
    }

    fn map_any_inner(&mut self, frame: &Frame, page_flags: PageFlags) -> Page {
        let level_4_page_table = unsafe { current_page_table(self.physical_memory_offset) };

        for level_4_page_table_entry_index in 0..512 {
            let level_4_page_table_entry =
                &mut unsafe { &mut *level_4_page_table }[level_4_page_table_entry_index];

            if !level_4_page_table_entry
                .flags()
                .contains(PageTableFlags::PRESENT)
            {
                self.allocate_lower_level_page_table(level_4_page_table_entry)
                    .expect("Failed to allocate L3 page table");
            }

            // Addresses in page table entries are all physical,
            // otherwise they'd need to get translated as well and that would not only be terribly slow
            // but could also lead to infinite recursion of translations.
            // As we can't access physical memory directly when we are in long mode,
            // we need to translate them manually to virtual addresses.
            // We can do that easily because of the way limine mapped them for us - using higher half direct mapping.
            // Which means we only need to add/subtract the offset we got from limine to convert addresses
            // from physical to virtual and vice versa.
            let level_3_page_table: *mut PageTable = VirtualAddress(
                level_4_page_table_entry.address().as_u64() + self.physical_memory_offset,
            )
            .as_mut_ptr();

            for level_3_page_table_entry_index in 0..512 {
                let level_3_page_table_entry =
                    &mut unsafe { &mut *level_3_page_table }[level_3_page_table_entry_index];

                if !level_3_page_table_entry
                    .flags()
                    .contains(PageTableFlags::PRESENT)
                {
                    self.allocate_lower_level_page_table(level_3_page_table_entry)
                        .expect("Failed to allocate L2 page table");
                }

                // Same as `level_3_page_table`
                let level_2_page_table: *mut PageTable = VirtualAddress(
                    level_3_page_table_entry.address().as_u64() + self.physical_memory_offset,
                )
                .as_mut_ptr();

                for level_2_page_table_entry_index in 0..512 {
                    let level_2_page_table_entry =
                        &mut unsafe { &mut *level_2_page_table }[level_2_page_table_entry_index];

                    if !level_2_page_table_entry
                        .flags()
                        .contains(PageTableFlags::PRESENT)
                    {
                        self.allocate_lower_level_page_table(level_2_page_table_entry)
                            .expect("Failed to allocate L1 page table");
                    }

                    // Same as `level_3_page_table`
                    let level_1_page_table: *mut PageTable = VirtualAddress(
                        level_2_page_table_entry.address().as_u64() + self.physical_memory_offset,
                    )
                    .as_mut_ptr();

                    for level_1_page_table_entry_index in 0..512 {
                        let level_1_page_table_entry = &mut unsafe { &mut *level_1_page_table }
                            [level_1_page_table_entry_index];

                        if level_1_page_table_entry
                            .flags()
                            .contains(PageTableFlags::PRESENT)
                        {
                            continue;
                        }

                        level_1_page_table_entry.set_address(frame.address());
                        level_1_page_table_entry.set_flags(PageTableFlags::PRESENT);

                        self.assign_propagable_page_flags_to_page_table_entry(
                            level_4_page_table_entry,
                            page_flags,
                        );
                        self.assign_propagable_page_flags_to_page_table_entry(
                            level_3_page_table_entry,
                            page_flags,
                        );
                        self.assign_propagable_page_flags_to_page_table_entry(
                            level_2_page_table_entry,
                            page_flags,
                        );
                        self.assign_propagable_page_flags_to_page_table_entry(
                            level_1_page_table_entry,
                            page_flags,
                        );

                        if !page_flags.contains(PageFlags::EXECUTABLE) {
                            level_1_page_table_entry.set_flags(
                                level_1_page_table_entry.flags() | PageTableFlags::NO_EXECUTE,
                            );
                        }

                        if page_flags.contains(PageFlags::WRITE_THROUGH) {
                            level_1_page_table_entry.set_flags(
                                level_1_page_table_entry.flags() | PageTableFlags::WRITE_THROUGH,
                            );
                        }

                        if page_flags.contains(PageFlags::DISABLE_CACHING) {
                            level_1_page_table_entry.set_flags(
                                level_1_page_table_entry.flags() | PageTableFlags::NO_CACHE,
                            );
                        }

                        let address = ((level_4_page_table_entry_index as u64) << 39)
                            | ((level_3_page_table_entry_index as u64) << 30)
                            | ((level_2_page_table_entry_index as u64) << 21)
                            | ((level_1_page_table_entry_index as u64) << 12);

                        return Page::new(VirtualAddress::new(address));
                    }
                }
            }
        }

        panic!("The entire page table is occupied");
    }

    fn unmap_inner(&self, page: &Page) -> Result<(), MemoryError> {
        // TODO: Deallocate unused page tables.

        let address = page.address();

        // | 63 | ... | 49 | 48 | ... | 40 | 39 | ... | 31 | 30 | ... | 22 | 21 | ... | 12 | 11 | ... | 0 |
        // | Unused        | Page level 4  | Page level 3  | Page level 2  | Page level 1  | 4 KiB offset |
        let offset = address.as_u64() & 0b1111_1111_1111;
        let level_1_page_table_entry_index = ((address.as_u64() >> 12) & 0b1_1111_1111) as usize;
        let level_2_page_table_entry_index = ((address.as_u64() >> 21) & 0b1_1111_1111) as usize;
        let level_3_page_table_entry_index = ((address.as_u64() >> 30) & 0b1_1111_1111) as usize;
        let level_4_page_table_entry_index = ((address.as_u64() >> 39) & 0b1_1111_1111) as usize;

        assert_eq!(offset, 0);

        let level_4_page_table = unsafe { current_page_table(self.physical_memory_offset) };
        let level_4_page_table_entry =
            &mut unsafe { &mut *level_4_page_table }[level_4_page_table_entry_index];

        if !level_4_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return Err(MemoryError::NonExistentMapping);
        }

        // Addresses in page table entries are all physical,
        // otherwise they'd need to get translated as well and that would not only be terribly slow
        // but could also lead to infinite recursion of translations.
        // As we can't access physical memory directly when we are in long mode,
        // we need to translate them manually to virtual addresses.
        // We can do that easily because of the way limine mapped them for us - using higher half direct mapping.
        // Which means we only need to add/subtract the offset we got from limine to convert addresses
        // from physical to virtual and vice versa.
        let level_3_page_table: *mut PageTable = VirtualAddress(
            level_4_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_3_page_table_entry =
            &mut unsafe { &mut *level_3_page_table }[level_3_page_table_entry_index];

        if !level_3_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return Err(MemoryError::NonExistentMapping);
        }

        // Same as `level_3_page_table`
        let level_2_page_table: *mut PageTable = VirtualAddress(
            level_3_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_2_page_table_entry =
            &mut unsafe { &mut *level_2_page_table }[level_2_page_table_entry_index];

        if !level_2_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return Err(MemoryError::NonExistentMapping);
        }

        // Same as `level_3_page_table`
        let level_1_page_table: *mut PageTable = VirtualAddress(
            level_2_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_1_page_table_entry =
            &mut unsafe { &mut *level_1_page_table }[level_1_page_table_entry_index];

        if !level_1_page_table_entry
            .flags()
            .contains(PageTableFlags::PRESENT)
        {
            return Err(MemoryError::NonExistentMapping);
        }

        level_1_page_table_entry.set_address(PhysicalAddress::new(0));
        level_1_page_table_entry.set_flags(PageTableFlags::empty());

        // The TLB (translation lookaside buffer) holds results of previous translations and
        // allows the CPU to skip a lot of additional work in case it was already computed before and
        // is present in the cache.
        // Hence, after each page table modification, we need to flush all relevant TLB entries.
        // If we didn't, there would be **horrible**, hard to track bugs.
        //
        // TODO: TLB misses are really inefficient, thus flushing the entire TLB is non optimal.
        //       Optimizing this at the moment doesn't make much sense,
        //       but it needs to be done in the future.
        tlb::flush_all();

        Ok(())
    }

    fn allocate_lower_level_page_table(
        &mut self,
        page_table_entry: &mut PageTableEntry,
    ) -> Result<(), ()> {
        let frame = self.allocate_frame().ok_or(())?;

        let lower_level_page_table =
            (frame.address().as_u64() + self.physical_memory_offset) as *mut [PageTableEntry; 512];

        unsafe { *lower_level_page_table = [PageTableEntry::default(); 512] };

        page_table_entry.set_address(frame.address());
        page_table_entry.set_flags(PageTableFlags::PRESENT);

        Ok(())
    }

    fn assign_propagable_page_flags_to_page_table_entry(
        &self,
        page_table_entry: &mut PageTableEntry,
        page_flags: PageFlags,
    ) {
        if page_flags.contains(PageFlags::WRITABLE) {
            page_table_entry.set_flags(page_table_entry.flags() | PageTableFlags::WRITABLE);
        }

        if page_flags.contains(PageFlags::USER_MODE_ACCESSIBLE) {
            page_table_entry.set_flags(page_table_entry.flags() | PageTableFlags::USER_ACCESSIBLE);
        }
    }
}

pub struct FrameAllocator {
    memory_map_response: &'static MemoryMapResponse,
    n: usize,
}

// TODO: Implement more advanced frame allocator
impl FrameAllocator {
    pub fn new(memory_map_response: &'static MemoryMapResponse) -> Self {
        Self {
            memory_map_response,
            n: 0,
        }
    }

    pub fn allocate(&mut self) -> Option<Frame> {
        let frame = self
            .memory_map_response
            .entries()
            .iter()
            .filter(|entry| entry.entry_type == EntryType::USABLE)
            .map(|entry| entry.base..(entry.base + entry.length))
            .flat_map(|range| range.step_by(FRAME_SIZE))
            .map(|address| Frame::new(PhysicalAddress(address)))
            .nth(self.n);

        self.n += 1;

        frame
    }
}

#[repr(C)]
#[repr(align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; 512],
}

impl PageTable {
    pub fn new() -> Self {
        Self {
            entries: [PageTableEntry::default(); 512],
        }
    }
}

impl Index<usize> for PageTable {
    type Output = PageTableEntry;

    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl IndexMut<usize> for PageTable {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.entries[index]
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    #[inline]
    pub fn address(&self) -> PhysicalAddress {
        PhysicalAddress(self.0 & 0x000f_ffff_ffff_f000)
    }

    pub fn set_address(&mut self, address: PhysicalAddress) {
        self.0 = address.as_u64() | self.flags().bits();
    }

    #[inline]
    pub fn flags(&self) -> PageTableFlags {
        PageTableFlags::from_bits_truncate(self.0)
    }

    pub fn set_flags(&mut self, flags: PageTableFlags) {
        self.0 = self.address().as_u64() | flags.bits();
    }
}

impl Default for PageTableEntry {
    fn default() -> Self {
        Self::new(0)
    }
}

bitflags! {
    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct PageFlags : u8 {
        const WRITABLE = 1 << 1;
        const EXECUTABLE = 1 << 2;
        const USER_MODE_ACCESSIBLE = 1 << 3;
        const WRITE_THROUGH = 1 << 4;
        const DISABLE_CACHING = 1 << 5;
        const GLOBAL = 1 << 6;
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Clone, Copy)]
    pub struct PageTableFlags: u64 {
        const PRESENT = 1;
        const WRITABLE = 1 << 1;
        const USER_ACCESSIBLE = 1 << 2;
        const WRITE_THROUGH = 1 << 3;
        const NO_CACHE = 1 << 4;
        const ACCESSED = 1 << 5;
        const DIRTY = 1 << 6;
        const HUGE_PAGE = 1 << 7;
        const GLOBAL = 1 << 8;
        const NO_EXECUTE = 1 << 63;
        const _ = !0;
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Page {
    address: VirtualAddress,
}

impl Page {
    pub fn new(address: VirtualAddress) -> Self {
        assert!(address.is_aligned_to(PAGE_SIZE as u64));

        Self { address }
    }

    #[inline]
    pub fn address(&self) -> VirtualAddress {
        self.address
    }
}

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Frame {
    address: PhysicalAddress,
}

impl Frame {
    pub fn new(address: PhysicalAddress) -> Self {
        assert!(address.is_aligned_to(FRAME_SIZE as u64));

        Self { address }
    }

    #[inline]
    pub fn address(&self) -> PhysicalAddress {
        self.address
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct VirtualAddress(u64);

impl VirtualAddress {
    pub fn new(address: u64) -> Self {
        Self(address)
    }

    pub fn is_aligned_to(&self, alignment: u64) -> bool {
        self.0 % alignment == 0
    }

    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.0
    }

    #[inline]
    pub fn as_ptr<T>(&self) -> *const T {
        self.0 as *const T
    }

    #[inline]
    pub fn as_mut_ptr<T>(&self) -> *mut T {
        self.0 as *mut T
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct PhysicalAddress(u64);

impl PhysicalAddress {
    pub fn new(address: u64) -> Self {
        Self(address)
    }

    pub fn is_aligned_to(&self, alignment: u64) -> bool {
        self.0 % alignment == 0
    }

    #[inline]
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

#[derive(Debug, Snafu)]
pub enum MemoryError {
    #[snafu(display("Already mapped"))]
    AlreadyMapped,
    #[snafu(display("Non-existent mapping"))]
    NonExistentMapping,
}

pub unsafe fn current_page_table(physical_memory_offset: u64) -> *mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let physical_address = level_4_table_frame.start_address();
    let virtual_address = physical_memory_offset + physical_address.as_u64();
    let page_table_ptr = virtual_address as *mut PageTable;

    page_table_ptr
}

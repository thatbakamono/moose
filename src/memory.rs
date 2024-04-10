use bitflags::bitflags;
use core::ops::{Index, IndexMut};
use limine::memory_map::EntryType;
use limine::response::MemoryMapResponse;

pub struct MemoryManager<'a> {
    physical_memory_offset: u64,
    frame_allocator: FrameAllocator<'a>,
}

impl<'a> MemoryManager<'a> {
    pub fn new(physical_memory_offset: u64, frame_allocator: FrameAllocator<'a>) -> Self {
        Self {
            physical_memory_offset,
            frame_allocator,
        }
    }

    pub unsafe fn map(&mut self, page: &Page, frame: &Frame) -> Result<(), ()> {
        self.map_inner(page, frame)
    }

    fn map_inner(&mut self, page: &Page, frame: &Frame) -> Result<(), ()> {
        let address = page.address();

        let offset = address.as_u64() & 0b1111_1111_1111;

        assert_eq!(offset, 0);

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
            self.allocate_lower_level_page_table(level_4_page_table_entry)?;
        }

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
            self.allocate_lower_level_page_table(level_3_page_table_entry)?;
        }

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
            self.allocate_lower_level_page_table(level_2_page_table_entry)?;
        }

        let level_1_page_table: *mut PageTable = VirtualAddress(
            level_2_page_table_entry.address().as_u64() + self.physical_memory_offset,
        )
        .as_mut_ptr();
        let level_1_page_table_entry =
            &mut unsafe { &mut *level_1_page_table }[level_1_page_table_entry_index];

        level_1_page_table_entry.set_address(frame.address());
        level_1_page_table_entry.set_flags(PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

        Ok(())
    }

    fn allocate_lower_level_page_table(
        &mut self,
        page_table_entry: &mut PageTableEntry,
    ) -> Result<(), ()> {
        let frame = self.frame_allocator.allocate().ok_or(())?;

        let lower_level_page_table =
            (frame.address().as_u64() + self.physical_memory_offset) as *mut [PageTableEntry; 512];

        unsafe { *lower_level_page_table = [PageTableEntry::default(); 512] };

        page_table_entry.set_address(frame.address());
        page_table_entry.set_flags(PageTableFlags::PRESENT | PageTableFlags::WRITABLE);

        Ok(())
    }
}

pub struct FrameAllocator<'a> {
    memory_map_response: &'a MemoryMapResponse,
    n: usize,
}

impl<'a> FrameAllocator<'a> {
    pub fn new(memory_map_response: &'a MemoryMapResponse) -> Self {
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
            .flat_map(|range| range.step_by(4096))
            .map(|address| Frame::new(PhysicalAddress(address))) // TODO
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

pub struct Page {
    address: VirtualAddress,
}

impl Page {
    pub fn new(address: VirtualAddress) -> Self {
        assert!(address.is_aligned_to(4096));

        Self { address }
    }

    #[inline]
    pub fn address(&self) -> VirtualAddress {
        self.address
    }
}

pub struct Frame {
    address: PhysicalAddress,
}

impl Frame {
    pub fn new(address: PhysicalAddress) -> Self {
        assert!(address.is_aligned_to(4096));

        Self { address }
    }

    #[inline]
    pub fn address(&self) -> PhysicalAddress {
        self.address
    }
}

#[derive(Clone, Copy)]
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

#[derive(Clone, Copy)]
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

pub unsafe fn current_page_table(physical_memory_offset: u64) -> *mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let physical_address = level_4_table_frame.start_address();
    let virtual_address = physical_memory_offset + physical_address.as_u64();
    let page_table_ptr = virtual_address as *mut PageTable;

    page_table_ptr
}

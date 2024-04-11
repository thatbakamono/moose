use crate::memory::{
    FrameAllocator, MemoryError, MemoryManager, Page, PageFlags, VirtualAddress, PAGE_SIZE,
};
use linked_list_allocator::LockedHeap;

const HEAP_START: usize = 0x4444_4444_0000;
const HEAP_SIZE: usize = 128 * 1024;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init_heap(memory_manager: &mut MemoryManager) -> Result<(), MemoryError> {
    for i in 0..(HEAP_SIZE / PAGE_SIZE) {
        let page = Page::new(VirtualAddress::new((HEAP_START + (i * PAGE_SIZE)) as u64));
        let frame = memory_manager.allocate_frame().expect("Failed to allocate");

        unsafe { memory_manager.map(&page, &frame, PageFlags::WRITABLE)? };
    }

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}

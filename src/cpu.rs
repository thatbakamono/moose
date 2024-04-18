use alloc::alloc::alloc_zeroed;
use core::alloc::Layout;
use x86_64::registers::segmentation::{Segment64, GS};
use x86_64::VirtAddr;

pub struct ProcessorControlBlock {
    pub apic_processor_id: u16,
}

impl ProcessorControlBlock {
    pub unsafe fn create_pcb_for_current_processor(apic_processor_id: u16) {
        let layout = Layout::new::<ProcessorControlBlock>();
        let ptr = alloc_zeroed(layout) as *mut ProcessorControlBlock;

        GS::write_base(VirtAddr::new(ptr as u64));

        (*ProcessorControlBlock::get_pcb_for_current_processor()).apic_processor_id =
            apic_processor_id;
    }

    // @TODO: SWAPGS

    // PCB is created
    //   - if current processor is BSP, just after memory manager initialization,
    //   - if current processor is AP, just after jump from assembly code to kernel's initialization
    //     routine,
    // so GS will be properly initialized nearly always, and it's safe function.
    pub fn get_pcb_for_current_processor() -> *mut ProcessorControlBlock {
        unsafe { GS::read_base().as_u64() as *mut ProcessorControlBlock }
    }
}

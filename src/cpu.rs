use alloc::alloc::alloc;
use core::alloc::Layout;
use x86_64::instructions::segmentation::Segment64;
use x86_64::registers::segmentation::GS;
use x86_64::VirtAddr;

pub struct ProcessorControlBlock {
    pub apic_processor_id: u16,
}

impl ProcessorControlBlock {
    pub unsafe fn create_pcb_for_current_processor(apic_processor_id: u16) {
        let layout = Layout::new::<ProcessorControlBlock>();
        let ptr = alloc(layout) as *mut ProcessorControlBlock;

        GS::write_base(VirtAddr::new(ptr as u64));

        (*ProcessorControlBlock::get_pcb_for_current_processor()).apic_processor_id =
            apic_processor_id;
    }

    // This function assumes that PCB has already been created
    pub fn get_pcb_for_current_processor() -> *mut ProcessorControlBlock {
        GS::read_base().as_u64() as *mut ProcessorControlBlock
    }
}

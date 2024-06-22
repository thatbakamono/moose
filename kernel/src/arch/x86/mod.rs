pub mod asm;
pub mod idt;

use x86_64::{
    instructions::tlb,
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::KERNEL_PAGE_TABLE;

pub fn perform_arch_initialization() {
    // @TODO: GDT
    idt::init_idt();
}

pub fn use_kernel_page_table(closure: impl FnOnce()) {
    let (previous_page_table_frame, previous_page_table_flags) = Cr3::read();

    unsafe {
        Cr3::write(
            PhysFrame::<Size4KiB>::from_start_address(PhysAddr::new(KERNEL_PAGE_TABLE as u64))
                .unwrap(),
            Cr3Flags::empty(),
        );

        tlb::flush_all();
    }

    closure();

    unsafe {
        Cr3::write(previous_page_table_frame, previous_page_table_flags);

        tlb::flush_all();
    }
}

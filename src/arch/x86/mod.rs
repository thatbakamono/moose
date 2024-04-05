pub mod asm;
mod gdt;
pub mod idt;

pub fn perform_arch_initialization() {
    // @TODO: Fix GDT (null segment?)
    //gdt::init_gdt();
    idt::init_idt();
}

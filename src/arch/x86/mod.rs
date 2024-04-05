pub mod asm;
pub mod idt;

pub fn perform_arch_initialization() {
    // @TODO: GDT
    idt::init_idt();
}

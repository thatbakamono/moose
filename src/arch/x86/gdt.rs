use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};

static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new();

pub fn init_gdt() {
    unsafe {
        GDT.append(Descriptor::kernel_code_segment());
        GDT.load();
    }
}

use crate::driver::acpi::Acpi;
use crate::driver::apic::Apic;
use alloc::sync::Arc;
use spin::RwLock;
use x86_64::structures::DescriptorTablePointer;

pub struct Kernel {
    pub acpi: Arc<Acpi>,
    pub apic: Arc<RwLock<Apic>>,
    pub gdt: DescriptorTablePointer,
}

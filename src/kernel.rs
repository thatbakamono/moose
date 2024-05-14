use crate::arch::irq::IrqAllocator;
use crate::driver::acpi::Acpi;
use crate::driver::apic::Apic;
use alloc::sync::Arc;
use spin::{Mutex, RwLock};
use x86_64::structures::DescriptorTablePointer;

pub struct Kernel {
    pub acpi: Arc<Acpi>,
    pub apic: Arc<RwLock<Apic>>,
    pub gdt: DescriptorTablePointer,
    pub timer_irq: u8,
    pub irq_allocator: Arc<Mutex<IrqAllocator>>,
}

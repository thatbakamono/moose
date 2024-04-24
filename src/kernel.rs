use crate::driver::acpi::Acpi;
use crate::driver::apic::Apic;
use crate::memory::MemoryManager;
use alloc::sync::Arc;
use core::cell::RefCell;
use x86_64::structures::DescriptorTablePointer;

pub struct Kernel {
    pub acpi: Arc<RefCell<Acpi>>,
    pub apic: Arc<RefCell<Apic>>,
    pub memory_manager: Arc<RefCell<MemoryManager>>,
    pub gdt: DescriptorTablePointer,
}

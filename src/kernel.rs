use crate::driver::acpi::Acpi;
use crate::driver::apic::Apic;
use crate::memory::MemoryManager;
use alloc::rc::Rc;
use core::cell::RefCell;

pub struct Kernel<'a> {
    pub acpi: Rc<RefCell<Acpi<'a>>>,
    pub apic: Rc<RefCell<Apic<'a>>>,
    pub memory_manager: Rc<RefCell<MemoryManager<'a>>>,
}

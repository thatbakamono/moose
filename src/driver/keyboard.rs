use alloc::sync::Arc;
use log::debug;
use spin::RwLock;
use x86_64::structures::idt::InterruptStackFrame;
use crate::arch::irq::IrqLevel;
use crate::arch::x86::asm::inb;
use crate::arch::x86::idt::IDT;
use crate::cpu::ProcessorControlBlock;
use crate::driver::apic::{DeliveryMode, DestinationMode, PinPolarity, RedirectionEntry, TriggerMode};
use crate::kernel::Kernel;

pub struct KeyboardDriver {
    irq: u8,
    kernel: Arc<RwLock<Kernel>>,
}

impl KeyboardDriver {
    pub fn new(kernel: Arc<RwLock<Kernel>>) -> Self {
        let irq = kernel.write().irq_allocator.get_mut().allocate_irq(IrqLevel::HumanInterfaceDevices);

        Self {
            irq,
            kernel
        }
    }

    pub fn init(&self) {
        unsafe { IDT[self.irq].set_handler_fn(ps2_keyboard_interrupt_handler); }

        let redirection_entry = RedirectionEntry::new()
            .with_delivery_mode(DeliveryMode::Fixed)
            .with_destination(0) // BSP, @TODO: Maybe interrupts load balancing?
            .with_mask(false)
            .with_destination_mode(DestinationMode::Physical)
            .with_interrupt_vector(self.irq)
            .with_pin_polarity(PinPolarity::ActiveHigh)
            .with_trigger_mode(TriggerMode::Edge);

        // PS/2 keyboard has IRQ#1
        self.kernel.read().apic.read().redirect_interrupt(redirection_entry, 1);
    }
}

extern "x86-interrupt" fn ps2_keyboard_interrupt_handler(_interrupt_stack_frame: InterruptStackFrame) {
    if (inb(0x64) & 0x1) != 0 {
        debug!("Key pressed: {}", inb(0x60) as char);
    }

    unsafe {
        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
    }
}
use crate::serial::{Port, Serial};
use x86_64::structures::idt::{Entry, InterruptDescriptorTable, InterruptStackFrame};

pub static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

pub fn init_idt() {
    unsafe {
        IDT.breakpoint.set_handler_fn(breakpoint_handler);
        IDT.double_fault.set_handler_fn(double_fault);

        // @TODO: CPU Exception handling?
        for i in 32..=255 {
            IDT[i] = Entry::missing();

            // set_handler_fn sets the PRESENT bit in IDT entry
            IDT[i].set_handler_fn(unknown_interrupt_handler);
        }

        IDT.load();
    }
}

extern "x86-interrupt" fn double_fault(_isf: InterruptStackFrame, _error_code: u64) -> ! {
    Serial::writeln(Port::COM1, "Double fault");

    loop {}
}

extern "x86-interrupt" fn breakpoint_handler(_interrupt_stack_frame: InterruptStackFrame) {
    Serial::writeln(Port::COM1, "Breakpoint handler");
}

extern "x86-interrupt" fn unknown_interrupt_handler(_interrupt_stack_frame: InterruptStackFrame) {
    Serial::writeln(Port::COM1, "Unknown interrupt handler");
}

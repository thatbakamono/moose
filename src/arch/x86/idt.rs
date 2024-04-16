use log::{error, info, warn};
use x86_64::{
    registers::control::Cr2,
    structures::idt::{Entry, InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
};

pub static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

pub fn init_idt() {
    unsafe {
        IDT.divide_error.set_handler_fn(division_error_handler);
        IDT.debug.set_handler_fn(debug_handler);
        IDT.non_maskable_interrupt
            .set_handler_fn(non_maskable_interrupt_handler);
        IDT.breakpoint.set_handler_fn(breakpoint_handler);
        IDT.overflow.set_handler_fn(overflow_handler);
        IDT.bound_range_exceeded
            .set_handler_fn(bound_range_exceeded_handler);
        IDT.invalid_opcode.set_handler_fn(invalid_opcode_handler);
        IDT.device_not_available
            .set_handler_fn(device_not_available_handler);
        IDT.double_fault.set_handler_fn(double_fault_handler);
        // Coprocessor segment overrun
        IDT.invalid_tss.set_handler_fn(invalid_tss_handler);
        IDT.segment_not_present
            .set_handler_fn(segment_not_present_handler);
        IDT.stack_segment_fault
            .set_handler_fn(stack_segment_fault_handler);
        IDT.general_protection_fault
            .set_handler_fn(general_protection_fault_handler);
        IDT.page_fault.set_handler_fn(page_fault_handler);
        // Reserved
        IDT.x87_floating_point
            .set_handler_fn(x87_floating_point_exception_handler);
        IDT.alignment_check.set_handler_fn(alignment_check_handler);
        IDT.machine_check.set_handler_fn(machine_check_handler);
        IDT.simd_floating_point
            .set_handler_fn(simd_floating_point_exception_handler);
        IDT.virtualization
            .set_handler_fn(virtualization_exception_handler);
        IDT.cp_protection_exception
            .set_handler_fn(control_protection_exception_handler);
        // Reserved
        // Hypervisor injection exception
        IDT.vmm_communication_exception
            .set_handler_fn(vmm_communication_exception_handler);
        IDT.security_exception
            .set_handler_fn(security_exception_handler);
        // Reserved
        // FPU error interrupt

        // @TODO: CPU Exception handling?
        for i in 32..=255 {
            IDT[i] = Entry::missing();

            // set_handler_fn sets the PRESENT bit in IDT entry
            IDT[i].set_handler_fn(unknown_interrupt_handler);
        }

        IDT.load();
    }
}

extern "x86-interrupt" fn division_error_handler(interrupt_stack_frame: InterruptStackFrame) {
    warn!("Division error");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn debug_handler(interrupt_stack_frame: InterruptStackFrame) {
    info!("Debug");

    info!("Stack frame: {interrupt_stack_frame:?}");
}

extern "x86-interrupt" fn non_maskable_interrupt_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    info!("Non-maskable interrupt");

    info!("Stack frame: {interrupt_stack_frame:?}");
}

extern "x86-interrupt" fn breakpoint_handler(interrupt_stack_frame: InterruptStackFrame) {
    info!("Breakpoint");

    info!("Stack frame: {interrupt_stack_frame:?}");
}

extern "x86-interrupt" fn overflow_handler(interrupt_stack_frame: InterruptStackFrame) {
    warn!("Overflow");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn bound_range_exceeded_handler(interrupt_stack_frame: InterruptStackFrame) {
    warn!("Bound range exceeded");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(interrupt_stack_frame: InterruptStackFrame) {
    warn!("Invalid opcode");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn device_not_available_handler(interrupt_stack_frame: InterruptStackFrame) {
    warn!("Device not available");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn double_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    error!("Double fault");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_tss_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("Invalid TSS");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn segment_not_present_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("Segment not present");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("Stack segment fault");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("General protection fault");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    error!("Page fault");

    if let Ok(address) = Cr2::read() {
        error!("Accessed virtual address: {:#0x}", address.as_u64());
    } else {
        error!("Accessed unknown virtual address");
    }

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn x87_floating_point_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    warn!("x87 floating point exception");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn alignment_check_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("Alignment check");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn machine_check_handler(interrupt_stack_frame: InterruptStackFrame) -> ! {
    warn!("Machine check");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn simd_floating_point_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    warn!("SIMD floating point exception");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn virtualization_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    warn!("Virtualization exception");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn control_protection_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("Control protection exception");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn vmm_communication_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("VMM communication exception");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn security_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    warn!("Security exception");

    info!("Stack frame: {interrupt_stack_frame:?}");
    info!("Error code: {error_code}");

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn unknown_interrupt_handler(interrupt_stack_frame: InterruptStackFrame) {
    info!("Unknown interrupt");

    info!("Stack frame: {interrupt_stack_frame:?}");

    loop {
        x86_64::instructions::hlt();
    }
}

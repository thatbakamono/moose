use log::{error, info, warn};
use x86_64::{
    registers::control::Cr2,
    structures::{
        gdt::SegmentSelector,
        idt::{Entry, InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode},
    },
};

use super::use_kernel_page_table;

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

        IDT[0x80] = Entry::missing();
        IDT[0x80]
            .set_handler_fn(syscall_handler)
            .set_code_selector(SegmentSelector::new(5, x86_64::PrivilegeLevel::Ring0))
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);

        // @TODO: CPU Exception handling?
        for i in 32..=255 {
            if i == 0x80 {
                continue;
            }

            IDT[i] = Entry::missing();

            // set_handler_fn sets the PRESENT bit in IDT entry
            IDT[i].set_handler_fn(unknown_interrupt_handler);
        }

        IDT.load();
    }
}

extern "x86-interrupt" fn division_error_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Division error");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn debug_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Debug");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });
}

extern "x86-interrupt" fn non_maskable_interrupt_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        info!("Non-maskable interrupt");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });
}

extern "x86-interrupt" fn breakpoint_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Breakpoint");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });
}

extern "x86-interrupt" fn overflow_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Overflow");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn bound_range_exceeded_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Bound range exceeded");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_opcode_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Invalid opcode");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn device_not_available_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        warn!("Device not available");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn double_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    use_kernel_page_table(|| {
        error!("Double fault");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn invalid_tss_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Invalid TSS");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn segment_not_present_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Segment not present");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn stack_segment_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Stack segment fault");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn general_protection_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("General protection fault");

        info!("Stack frame: {interrupt_stack_frame:#?}");

        if error_code != 0 {
            info!("Is external: {}", error_code & 1 == 1);
            info!("GDT/IDT/LDT/IDT: {}", (error_code >> 1) & 0b11);
            info!("Segment selector index: {}", error_code >> 3);
        }
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn page_fault_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use_kernel_page_table(|| {
        error!("Page fault");

        if let Ok(address) = Cr2::read() {
            error!("Accessed virtual address: {:#0x}", address.as_u64());
        } else {
            error!("Accessed unknown virtual address");
        }

        info!("Stack frame: {interrupt_stack_frame:#?}");
        info!("Error code: {error_code:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn x87_floating_point_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        warn!("x87 floating point exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn alignment_check_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Alignment check");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn machine_check_handler(interrupt_stack_frame: InterruptStackFrame) -> ! {
    use_kernel_page_table(|| {
        warn!("Machine check");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn simd_floating_point_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        warn!("SIMD floating point exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn virtualization_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
) {
    use_kernel_page_table(|| {
        warn!("Virtualization exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn control_protection_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Control protection exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn vmm_communication_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("VMM communication exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn security_exception_handler(
    interrupt_stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    use_kernel_page_table(|| {
        warn!("Security exception");

        info!("Stack frame: {interrupt_stack_frame:?}");
        info!("Error code: {error_code}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn syscall_handler(_interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Syscall!");
    });
}

extern "x86-interrupt" fn unknown_interrupt_handler(interrupt_stack_frame: InterruptStackFrame) {
    use_kernel_page_table(|| {
        info!("Unknown interrupt");

        info!("Stack frame: {interrupt_stack_frame:?}");
    });

    loop {
        x86_64::instructions::hlt();
    }
}

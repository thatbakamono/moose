pub mod asm;
pub mod idt;

use core::arch;
use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

pub fn perform_arch_initialization() {
    unsafe {
        Cr0::write(
            Cr0::read().difference(Cr0Flags::EMULATE_COPROCESSOR)
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::MONITOR_COPROCESSOR,
        );
        // We don't really need to check whether SSE and SSE2 is present as long mode requires them.
        // We wouldn't even get here without those extensions.
        Cr4::write(Cr4::read() | Cr4Flags::OSFXSR | Cr4Flags::OSXMMEXCPT_ENABLE);

        arch::asm!("fninit");
    }

    // @TODO: GDT
    idt::init_idt();
}

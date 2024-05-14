use crate::arch::x86::idt::IDT;
use crate::driver::acpi::{Acpi, MadtEntryInner};
use crate::driver::apic::io_apic::{IoApic, RedirectionEntry};
use crate::driver::apic::local_apic::{
    ap_start, timer_interrupt_handler, LocalApic, AP_STARTUP_SPINLOCK,
    LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER, LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER,
    STACK_SIZE, TIMER_IRQ, TRAMPOLINE_CODE,
};
use crate::driver::pit::PIT;
use crate::kernel::Kernel;
use crate::memory::{memory_manager, Page, PageFlags, VirtualAddress, PAGE_SIZE};
use alloc::alloc::alloc_zeroed;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::arch::asm;
use core::ptr;
use log::debug;
use raw_cpuid::CpuId;
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;

pub mod io_apic;
pub mod local_apic;

pub struct Apic {
    pub local_apic_timer_ticks_per_second: u64,
    pub acpi: Arc<Acpi>,
    io_apic: Vec<IoApic>,
}

impl Apic {
    pub fn initialize(acpi: Arc<Acpi>) -> Apic {
        // Check if CPU supports APIC
        let cpuid = CpuId::new();
        assert!(
            !cpuid.get_feature_info().unwrap().has_acpi(),
            "CPU does not support APIC"
        );

        unsafe { IDT[TIMER_IRQ as u8].set_handler_fn(timer_interrupt_handler) };

        let mut io_apics = vec![];

        acpi.madt
            .entries
            .clone()
            .into_iter()
            .filter_map(|entry| match entry.inner {
                MadtEntryInner::IoApic(io_apic) => Some(io_apic),
                _ => None,
            })
            .for_each(|ioapic| {
                io_apics.push(IoApic::new(ioapic));
            });

        Apic {
            local_apic_timer_ticks_per_second: 0,
            acpi,
            io_apic: io_apics,
        }
    }

    pub fn redirect_interrupt(&self, redirection_entry: RedirectionEntry, irq: u8) {
        let io_apic: IoApic = self
            .io_apic
            .clone()
            .into_iter()
            .filter(|apic| {
                let start = apic.madt_io_apic.global_system_interrupt_base;
                let end = start + apic.get_redirection_entry_count();

                (start..end).contains(&(irq as u32))
            })
            .next()
            .unwrap();

        io_apic.redirect_interrupt(
            redirection_entry,
            irq - io_apic.madt_io_apic.global_system_interrupt_base as u8,
        );
    }

    pub fn setup_other_application_processors(
        &self,
        kernel: Arc<RwLock<Kernel>>,
        local_apic: &LocalApic,
    ) {
        let args = unsafe {
            // Map 0x8000 into memory. This shouldn't be mapped currently.
            let mut memory_manager = memory_manager().write();

            memory_manager
                .map_identity(
                    &Page::new(VirtualAddress::new(0x8000)),
                    PageFlags::WRITABLE | PageFlags::EXECUTABLE,
                )
                .unwrap();

            // Safety check
            assert!(TRAMPOLINE_CODE.len() <= PAGE_SIZE);

            // Copy AP-startup routine to 0x8000
            ptr::copy_nonoverlapping(
                TRAMPOLINE_CODE.as_ptr(),
                0x8000 as *mut u8,
                TRAMPOLINE_CODE.len(),
            );

            let args = (0x8000 as *mut u64).offset(1);
            // PML4 pointer (we'll reuse current processor's pointer)
            args.write(
                x86_64::registers::control::Cr3::read()
                    .0
                    .start_address()
                    .as_u64(),
            );
            // Address of kernel's AP initialization routine
            args.offset(1).write(ap_start as usize as u64);
            // Address of Kernel instance
            args.offset(2).write(Arc::into_raw(kernel.clone()) as u64);

            args
        };

        let bsp_id = CpuId::new()
            .get_feature_info()
            .unwrap()
            .initial_local_apic_id() as u16;
        self.acpi
            .madt
            .entries
            .iter()
            .filter_map(|entry| {
                if let MadtEntryInner::ProcessorLocalApic(local_apic) = &entry.inner {
                    Some(local_apic)
                } else {
                    None
                }
            })
            .filter(|entry| entry.apic_id != bsp_id as u8)
            .for_each(|entry| {
                if entry.flags & (1 << 0) == 0 {
                    // Processor is not online-capable, so ignore this entry
                    debug!(
                        "Processor {} is not online-capable, skipping...",
                        entry.apic_id
                    );
                    return;
                }

                unsafe {
                    // Create 4MiB stack
                    let stack = {
                        let layout = Layout::array::<u8>(STACK_SIZE).unwrap();

                        alloc_zeroed(layout)
                    };

                    // Set stack address in AP's configuration structure
                    args.offset(3)
                        .write((stack as usize + STACK_SIZE - 8) as u64);
                    // APIC ID
                    args.offset(4).write(entry.apic_id as u64);

                    *AP_STARTUP_SPINLOCK.write() = 0;
                }

                self.boot_processor(local_apic, entry.apic_id);

                unsafe {
                    while without_interrupts(|| *AP_STARTUP_SPINLOCK.read() == 0) {
                        PIT.wait_sixteen_millis()
                    }
                }
            });
    }

    fn boot_processor(&self, bsp_local_apic: &LocalApic, destination_processor_apic_id: u8) {
        bsp_local_apic.reset_error_register();

        // Set the target processor for INIT IPI
        bsp_local_apic.write_register(
            LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER,
            (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER)
                & 0x00FFFFFF)
                | ((destination_processor_apic_id as u32) << 24),
        );

        // Set some options and *actually* send an interrupt
        //
        // 0x00C500 == 0b1100010100000000
        // Bits 0-7 -  Vector number (0)
        // Bits 8-10 - Delivery mode (5 - INIT)
        // Bit 11 - Destination mode (0, physical)
        // Bit 12 - Delivery status (0, it will be set by an APIC)
        bsp_local_apic.write_register(
            LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER,
            bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER & 0xFFF00000)
                | 0x00C500,
        );

        // Wait for interrupt delivery
        while bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER) & (1 << 12) != 0 {
            unsafe { asm!("pause") }
        }

        // Set the target processor for INIT IPI
        bsp_local_apic.write_register(
            LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER,
            (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER)
                & 0x00FFFFFF)
                | ((destination_processor_apic_id as u32) << 24),
        );

        // Set some options and *actually* send an interrupt
        //
        // 0x008500 == 0b1100010100000000
        //               1000010100000000
        // Bits 0-7 -  Vector number (0)
        // Bits 8-10 - Delivery mode (5 - INIT)
        // Bit 11 - Destination mode (0, physical)
        // Bit 12 - Delivery status (0, it will be set by an APIC)
        //
        // This is going to be deassert INIT IPI
        bsp_local_apic.write_register(
            LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER,
            bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER & 0xFFF00000)
                | 0x008500,
        );

        // Wait for interrupt delivery
        while bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER) & (1 << 12) != 0 {
            unsafe { asm!("pause") }
        }

        // Wait for the processor to execute BIOS code
        //
        // We should wait for approx 10ms, but because of low-resolution PIT usage we'll wait ~16ms
        unsafe { PIT.wait_sixteen_millis() };

        // Finally, send STARTUP IPI
        //
        // We need to do it twice for some reason : )
        for _ in 0..2 {
            // Set interrupt target
            bsp_local_apic.write_register(
                LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER,
                (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER)
                    & 0x00FFFFFF)
                    | ((destination_processor_apic_id as u32) << 24),
            );

            // Trigger startup IPI with memory address 0x8000:0000 (we're in 16-bit mode!)
            bsp_local_apic.write_register(
                LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER,
                (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER) & 0xFFF0F800)
                    | 0x608,
            );
            unsafe { PIT.wait_sixteen_millis() }
        }
    }
}

#[repr(transparent)]
pub struct IrqId(u8);

impl IrqId {
    pub const fn new(id: u8) -> IrqId {
        assert!(id < 0b11111, "IrqId needs to be in range [0, 31]");

        Self(id)
    }

    pub const fn try_new(id: u8) -> Result<IrqId, ()> {
        if id > 0b11111 {
            return Err(());
        }

        Ok(Self(id))
    }

    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

#[repr(u8)]
pub enum IrqLevel {
    High = 15,
    InterProcessorInterrupt = 14,
    Clock = 13,
    // 12-1 are free, probably for device drivers use
    Passive = 0,
}

pub const fn to_irq_number(level: IrqLevel, id: IrqId) -> u8 {
    ((level as u8) << 5) | (id.as_u8())
}

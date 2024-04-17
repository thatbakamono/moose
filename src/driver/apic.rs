use crate::driver::pit::PIT;
use crate::kernel::Kernel;
use crate::memory::{
    Frame, MemoryError, MemoryManager, Page, PageFlags, PhysicalAddress, VirtualAddress,
};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::{format, vec};
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::cell::RefCell;
use core::ops::Deref;
use core::ptr;
use core::ptr::NonNull;
use log::{debug, info};
use raw_cpuid::CpuId;
use spin::RwLock;
use volatile::VolatilePtr;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::instructions::segmentation::Segment64;
use x86_64::registers::segmentation::Segment;
use crate::{cpu, driver};
use crate::arch::x86::perform_arch_initialization;
use crate::driver::acpi::{Acpi, MADTEntry, MADTEntryInner, MadtIOAPIC};
use crate::logger::init_serial_logger;
use crate::serial::{Port, Serial};

const LOCAL_APIC_LAPIC_ID_REGISTER: u32 = 0x20;
const LOCAL_APIC_LAPIC_VERSION_REGISTER: u32 = 0x23;
// 0x40-0x70 - Reserved
const LOCAL_APIC_TASK_PRIORITY_REGISTER: u32 = 0x80;
const LOCAL_APIC_ARBITRATION_PRIORITY_REGISTER: u32 = 0x90;
const LOCAL_APIC_PROCESSOR_PRIORITY_REGISTER: u32 = 0xA0;
const LOCAL_APIC_END_OF_INTERRUPT_REGISTER: u32 = 0xB0;
const LOCAL_APIC_REMOTE_READ_REGISTER: u32 = 0xC0;
const LOCAL_APIC_LOGICAL_DESTINATION_REGISTER: u32 = 0xD0;
const LOCAL_APIC_DESTINATION_FORMAT_REGISTER: u32 = 0xE0;
const LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER: u32 = 0xF0;
// ISR
// TMR
// IRR
const LOCAL_APIC_ERROR_STATUS_REGISTER: u32 = 0x280;
const LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER: u32 = 0x300;
const LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER: u32 = 0x310;
const LOCAL_APIC_INITIAL_COUNT_REGISTER: u32 = 0x380;
const LOCAL_APIC_CURRENT_COUNT_REGISTER: u32 = 0x390;
const LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER: u32 = 0x3E0;
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_MSR_BSP_FLAG: u64 = 1 << 8;
const APIC_BASE_MSR_APIC_GLOBAL_ENABLE_FLAG: u64 = 1 << 11;
const APIC_BASE_MSR_APIC_BASE_FIELD_MASK: u64 = 0xFFFFFF000;

static TRAMPOLINE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));
static mut AP_STARTUP_SPINLOCK: RwLock<u8> = RwLock::new(0);

pub unsafe extern "C" fn ap_start(_apic_processor_id: u64) -> ! {
    Serial::writeln(Port::COM1, "Processor started");

    unsafe { *AP_STARTUP_SPINLOCK.write() = 1 };

    // @TODO: PCB initialization with apic_processor_id?

    loop { }
}

pub struct Apic<'a> {
    pub lapic_timer_ticks_per_second: u64,
    pub io_apic: Box<IoApic<'a>>,
    pub acpi: Rc<RefCell<Acpi<'a>>>
}

impl<'a> Apic<'_> {
    pub fn initialize(memory_manager: Rc<RefCell<MemoryManager<'a>>>, acpi: Rc<RefCell<Acpi<'a>>>) -> Apic<'a> {
        // Check if CPU supports APIC
        let cpuid = CpuId::new();
        assert!(
            !cpuid.get_feature_info().unwrap().has_acpi(),
            "CPU does not support APIC"
        );

        // @TODO: Refactor
        let io_apic_address = {
            let binding = acpi.borrow();

            let io_apic_entries: Vec<MadtIOAPIC> = binding.madt.entries.iter().filter_map(|entry| {
                if let MADTEntryInner::IOAPIC(io_apic) = entry.clone().inner { Some(io_apic) } else { None }
            }).collect();
            // There can be multiple I/O APIC chips in the system, but now we'll only use one.
            let io_apic_entry = io_apic_entries.first().unwrap();

            io_apic_entry.io_apic_address
        };

        let mut apic = Apic {
            lapic_timer_ticks_per_second: 0,
            io_apic: Box::new(unsafe { IoApic::with_address(io_apic_address as u64) }),
            acpi,
        };

        apic
        // It's initialized in BSP before PIT is disabled, so we need to count ticks to properly
        // setup timer
    }

    pub fn setup_other_application_processors(&self, kernel: Rc<RefCell<Kernel>>, lapic: &LocalApic) {
        // @FIXME
        let mut stack = vec![0u8; 1 << 12].as_ptr().addr();

        let args = unsafe {
            // Map 0x8000 into memory. This shouldn't be mapped currently.
            kernel.borrow().memory_manager.borrow_mut().map(
                &Page::new(VirtualAddress::new(0x8000)),
                &Frame::new(PhysicalAddress::new(0x8000)),
                PageFlags::WRITABLE | PageFlags::EXECUTABLE
            ).unwrap();

            // Copy AP-startup routine to 0x8000
            ptr::copy_nonoverlapping(
                TRAMPOLINE_CODE.as_ptr(),
            0x8000 as *mut u8,
                TRAMPOLINE_CODE.len()
            );

            let args = (0x8000 as *mut u64).offset(1);
            // PML4 pointer (we'll reuse current processor's pointer)
            args.write(x86_64::registers::control::Cr3::read().0.start_address().as_u64());
            // Address of kernel's AP initialization routine
            args.offset(1).write(ap_start as u64);

            args
        };

        let bsp_id = CpuId::new().get_feature_info().unwrap().initial_local_apic_id() as u16;

        self.acpi.borrow().madt.entries.iter().filter_map(|entry| {
            if let MADTEntryInner::ProcessorLocalAPIC(local_apic) = entry.clone().inner { Some(local_apic)} else { None }
        }).filter(|entry| entry.apic_id != bsp_id as u8).for_each(|entry| {
            if entry.flags & (1 << 0) == 0 {
                // Processor is not online-capable, so ignore this entry
                debug!("Processor {} is not online-capable, skipping...", entry.apic_id);
                return;
            }

            unsafe {
                // Stack
                // FIXME
                args.offset(2).write((stack as u64) + 0x50);
                // APIC ID
                args.offset(3).write(entry.apic_id as u64);

                *AP_STARTUP_SPINLOCK.write() = 0;
            }

            self.boot_processor(&lapic, entry.apic_id);

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
            (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER) & 0x00FFFFFF) | ((destination_processor_apic_id as u32) << 24)
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
            bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER & 0xFFF00000) | 0x00C500
        );

        // Wait for interrupt delivery
        while bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER) & (1 << 12) != 0 { unsafe { asm!("pause") } }

        // Set the target processor for INIT IPI
        bsp_local_apic.write_register(
            LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER,
            (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER) & 0x00FFFFFF) | ((destination_processor_apic_id as u32) << 24)
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
            bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER & 0xFFF00000) | 0x008500
        );

        // Wait for interrupt delivery
        while bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER) & (1 << 12) != 0 { unsafe { asm!("pause") } }

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
                (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_TARGET_PROCESSOR_REGISTER) & 0x00FFFFFF) | ((destination_processor_apic_id as u32) << 24)
            );

            // Trigger startup IPI with memory address 0x8000:0000 (we're in 16-bit mode!)
            bsp_local_apic.write_register(
                LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER,
                (bsp_local_apic.read_register(LOCAL_APIC_INTERRUPT_OPTIONS_REGISTER) & 0xFFF0F800) | 0x608
            );
            unsafe { PIT.wait_sixteen_millis() }
        }
    }
}

#[derive(Debug)]
pub struct IoApic<'a> {
    io_apic_address_register: VolatilePtr<'a, u32>,
    io_apic_data_register: VolatilePtr<'a, u32>,
}

impl IoApic<'_> {
    pub unsafe fn with_address(io_apic_address: u64) -> Self {
        Self {
            io_apic_address_register: VolatilePtr::new(
                NonNull::new(io_apic_address as *mut u32).unwrap(),
            ),
            io_apic_data_register: VolatilePtr::new(
                NonNull::new((io_apic_address + 4) as *mut u32).unwrap(),
            )
        }
    }

    fn read_register(&self, register: u32) -> u32 {
        self.io_apic_address_register.write(register & 0xFF);

        self.io_apic_data_register.read()
    }

    fn write_register(&self, register: u32, value: u32) {
        self.io_apic_address_register.write(register & 0xFF);
        self.io_apic_data_register.write(value);
    }
}

pub struct LocalApic<'a> {
    local_apic_base: u64,
    kernel: Rc<RefCell<Kernel<'a>>>
}

impl<'a> LocalApic<'_> {
    pub fn initialize_for_current_processor(kernel: Rc<RefCell<Kernel>>) -> LocalApic {
        let apic_base =
            unsafe { x86_64::registers::model_specific::Msr::new(IA32_APIC_BASE_MSR).read() };
        let local_apic_base = apic_base & APIC_BASE_MSR_APIC_BASE_FIELD_MASK;

        // Make sure local apic base is mapped into memory
        // It is always on 4KiB boundary
        unsafe {
            match kernel.borrow().memory_manager.borrow_mut().map(
                &Page::new(VirtualAddress::new(local_apic_base)),
                &Frame::new(PhysicalAddress::new(local_apic_base)),
                PageFlags::WRITABLE | PageFlags::WRITE_THROUGH | PageFlags::DISABLE_CACHING,
            ) {
                Ok(()) => {}
                Err(MemoryError::AlreadyMapped) => {}
                Err(err) => {
                    panic!("{}", err);
                }
            }
        };

        let mut apic = LocalApic { local_apic_base, kernel };

        // Enable Local APIC
        //
        // Local APIC can be enabled by setting 8th bit of spurious interrupt vector register
        apic.write_register(
            LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER,
            apic.read_register(LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER) | (1 << 8),
        );

        if apic_base & APIC_BASE_MSR_BSP_FLAG != 0 {
            // We're running first LocalAPIC initialization on the bootstrap processor and need to
            // check the speed of APIC timer.
            apic.check_timer_speed()
        }

        apic
    }

    pub fn reset_error_register(&self) {
        self.write_register(LOCAL_APIC_ERROR_STATUS_REGISTER, 0);
    }

    fn check_timer_speed(&self) {
        // This function is run only once during BSP's Local APIC initialization

        // APIC timer tick speed is not standardized, and every platform can have custom speed, so
        // we need to somehow measure it.
        //
        // It can be done by running APIC timer, sleeping for measurable amount of time (with use of
        // PIT) and checking how many times APIC "ticked".

        // Tell APIC timer to use divider 16
        self.write_register(LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER, 0x3);

        // Set APIC timer init counter to -1
        //
        // After every write to this register, current countdown is discarded and new initial count
        // is copied to current count register and countdown starts.
        self.write_register(LOCAL_APIC_INITIAL_COUNT_REGISTER, 0xFFFFFFFF);

        // Perform PIT-assisted sleep for 1 second
        unsafe { PIT.wait_seconds(1) };

        let ticks_per_second = 0xFFFFFFFF - self.read_register(LOCAL_APIC_CURRENT_COUNT_REGISTER);

        info!(
            "APIC Base: {:#01x}, ticks per second: {:#01x}",
            self.local_apic_base, ticks_per_second
        );

        self.kernel.borrow_mut().apic.borrow_mut().lapic_timer_ticks_per_second = ticks_per_second as u64;
    }

    fn read_register(&self, register: u32) -> u32 {
        let ptr = unsafe {
            VolatilePtr::new(
                NonNull::new((self.local_apic_base + register as u64) as *mut u32).unwrap(),
            )
        };
        ptr.read()
    }

    fn write_register(&self, register: u32, value: u32) {
        let ptr = unsafe {
            VolatilePtr::new(
                NonNull::new((self.local_apic_base + register as u64) as *mut u32).unwrap(),
            )
        };
        ptr.write(value)
    }
}

use crate::arch::x86::idt::IDT;
use crate::cpu::ProcessorControlBlock;
use crate::driver::acpi::{Acpi, MADTEntryInner};
use crate::driver::pit::PIT;
use crate::kernel::Kernel;
use crate::memory::{
    Frame, MemoryError, Page, PageFlags, PhysicalAddress, VirtualAddress, PAGE_SIZE,
};
use alloc::alloc::alloc_zeroed;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::alloc::Layout;
use core::arch::asm;
use core::cell::RefCell;
use core::ptr;
use log::{debug, info};
use raw_cpuid::CpuId;
use spin::RwLock;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::structures::idt::InterruptStackFrame;

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
const LOCAL_APIC_LVT_TIMER_REGISTER: u32 = 0x320;
const LOCAL_APIC_LVT_ERROR_REGISTER: u32 = 0x370;
const LOCAL_APIC_INITIAL_COUNT_REGISTER: u32 = 0x380;
const LOCAL_APIC_CURRENT_COUNT_REGISTER: u32 = 0x390;
const LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER: u32 = 0x3E0;
const IA32_APIC_BASE_MSR: u32 = 0x1B;
const APIC_BASE_MSR_BSP_FLAG: u64 = 1 << 8;
const APIC_BASE_MSR_APIC_GLOBAL_ENABLE_FLAG: u64 = 1 << 11;
const APIC_BASE_MSR_APIC_BASE_FIELD_MASK: u64 = 0xFFFFFF000;

const STACK_SIZE: usize = 4 * 1024 * 1024;
const TIMER_IRQ: u32 = to_irq_number(IrqLevel::Clock, IrqId(0)) as u32;
const LOCAL_APIC_TIMER_PERIODIC: u32 = 1 << 17;

static TRAMPOLINE_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/trampoline"));
static mut AP_STARTUP_SPINLOCK: RwLock<u8> = RwLock::new(0);

pub unsafe extern "C" fn ap_start(apic_processor_id: u64, kernel_ptr: *const RefCell<Kernel>) -> ! {
    // @TODO: Move to perform_arch_initialization()
    let kernel = Arc::from_raw(kernel_ptr);

    IDT.load();
    Cr4::write(Cr4::read() | Cr4Flags::FSGSBASE);

    ProcessorControlBlock::create_pcb_for_current_processor(apic_processor_id as u16);
    let pcb = ProcessorControlBlock::get_pcb_for_current_processor();
    let lapic = LocalApic::initialize_for_current_processor(Arc::clone(&kernel));
    lapic.enable_timer();

    _ = (*pcb).local_apic.set(lapic);

    *AP_STARTUP_SPINLOCK.write() = 1;
    info!("Processor {:p} has started", pcb);

    loop {
        asm!("hlt");
    }
}

pub struct Apic {
    pub lapic_timer_ticks_per_second: u64,
    pub io_apic: Box<IoApic>,
    pub acpi: Arc<RefCell<Acpi>>,
}

impl Apic {
    pub fn initialize(acpi: Arc<RefCell<Acpi>>) -> Apic {
        // Check if CPU supports APIC
        let cpuid = CpuId::new();
        assert!(
            !cpuid.get_feature_info().unwrap().has_acpi(),
            "CPU does not support APIC"
        );

        let io_apic_address = {
            let binding = acpi.borrow();
            // There can be multiple I/O APIC chips in the system, but now we'll only use one.
            let io_apic_entry = binding
                .madt
                .entries
                .iter()
                .filter_map(|entry| {
                    if let MADTEntryInner::IOAPIC(io_apic) = &entry.inner {
                        Some(io_apic)
                    } else {
                        None
                    }
                })
                .next()
                .unwrap();

            io_apic_entry.io_apic_address
        };

        unsafe { IDT[TIMER_IRQ as u8].set_handler_fn(timer_interrupt_handler) };

        let apic = Apic {
            lapic_timer_ticks_per_second: 0,
            io_apic: Box::new(unsafe { IoApic::with_address(io_apic_address as u64) }),
            acpi,
        };

        apic
    }

    pub fn setup_other_application_processors(
        &self,
        kernel: Arc<RefCell<Kernel>>,
        lapic: &LocalApic,
    ) {
        let args = unsafe {
            // Map 0x8000 into memory. This shouldn't be mapped currently.
            kernel
                .borrow()
                .memory_manager
                .borrow_mut()
                .map(
                    &Page::new(VirtualAddress::new(0x8000)),
                    &Frame::new(PhysicalAddress::new(0x8000)),
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
            args.offset(1).write(ap_start as u64);
            // Address of Kernel instance
            args.offset(2).write(Arc::into_raw(kernel.clone()) as u64);

            args
        };

        let bsp_id = CpuId::new()
            .get_feature_info()
            .unwrap()
            .initial_local_apic_id() as u16;
        self.acpi
            .borrow()
            .madt
            .entries
            .iter()
            .filter_map(|entry| {
                if let MADTEntryInner::ProcessorLocalAPIC(local_apic) = &entry.inner {
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

                self.boot_processor(lapic, entry.apic_id);

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

#[derive(Debug)]
pub struct IoApic {
    io_apic_address_register: *mut u32,
    io_apic_data_register: *mut u32,
}

impl IoApic {
    pub unsafe fn with_address(io_apic_address: u64) -> Self {
        Self {
            io_apic_address_register: io_apic_address as *mut u32,
            io_apic_data_register: (io_apic_address + 4) as *mut u32,
        }
    }

    fn read_register(&self, register: u32) -> u32 {
        unsafe {
            ptr::write_volatile(self.io_apic_address_register, register & 0xFF);
            ptr::read_volatile(self.io_apic_data_register)
        }
    }

    fn write_register(&self, register: u32, value: u32) {
        unsafe {
            ptr::write_volatile(self.io_apic_address_register, register & 0xFF);
            ptr::write_volatile(self.io_apic_data_register, value);
        }
    }
}

pub struct LocalApic {
    local_apic_base: u64,
    kernel: Arc<RefCell<Kernel>>,
}

impl LocalApic {
    pub fn initialize_for_current_processor(kernel: Arc<RefCell<Kernel>>) -> LocalApic {
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

        let apic = LocalApic {
            local_apic_base,
            kernel,
        };

        // Enable Local APIC
        //
        // Local APIC can be enabled by setting 8th bit of spurious interrupt vector register
        apic.write_register(
            LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER,
            apic.read_register(LOCAL_APIC_SPURIOUS_INTERRUPT_VECTOR_REGISTER) | (1 << 8),
        );

        // Remap spurious interrupt vector register
        apic.write_register(LOCAL_APIC_LVT_ERROR_REGISTER, 0x1F);

        if apic_base & APIC_BASE_MSR_BSP_FLAG != 0 {
            // We're running first LocalAPIC initialization on the bootstrap processor and need to
            // check the speed of APIC timer.
            apic.check_timer_speed()
        }

        apic
    }

    pub fn enable_timer(&self) {
        // Fire timer every 10ms
        let ticks_per_10ms = self
            .kernel
            .borrow()
            .apic
            .borrow()
            .lapic_timer_ticks_per_second
            / 100;

        // Enable interrupts
        self.write_register(LOCAL_APIC_TASK_PRIORITY_REGISTER, 0);

        // Set divider 16
        self.write_register(LOCAL_APIC_DIVIDE_CONFIGURATION_REGISTER, 0x3);

        self.write_register(
            LOCAL_APIC_LVT_TIMER_REGISTER,
            TIMER_IRQ | LOCAL_APIC_TIMER_PERIODIC,
        );

        // Start the timer
        self.write_register(LOCAL_APIC_INITIAL_COUNT_REGISTER, ticks_per_10ms as u32);
    }

    pub fn signal_end_of_interrupt(&self) {
        self.write_register(LOCAL_APIC_END_OF_INTERRUPT_REGISTER, 0);
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

        self.kernel
            .borrow()
            .apic
            .borrow_mut()
            .lapic_timer_ticks_per_second = ticks_per_second as u64;
    }

    fn read_register(&self, register: u32) -> u32 {
        let ptr = (self.local_apic_base + register as u64) as *mut u32;
        unsafe { ptr::read_volatile(ptr) }
    }

    fn write_register(&self, register: u32, value: u32) {
        let ptr = (self.local_apic_base + register as u64) as *mut u32;

        unsafe { ptr::write_volatile(ptr, value) }
    }
}

extern "x86-interrupt" fn timer_interrupt_handler(_interrupt_stack_frame: InterruptStackFrame) {
    unsafe {
        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
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

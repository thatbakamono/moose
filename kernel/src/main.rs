#![allow(dead_code)]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(strict_provenance)]
#![no_std]
#![no_main]

extern crate alloc;

mod allocator;
mod arch;
mod cpu;
mod driver;
mod font;
mod kernel;
mod logger;
mod memory;
mod serial;
mod terminal;
mod vga;

use crate::allocator::initialize_heap;
use crate::driver::{pic::PIC, pit::PIT};
use crate::memory::initialize_memory_manager;
use crate::terminal::Terminal;
use alloc::sync::Arc;
use core::arch::asm;
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest, RsdpRequest,
    StackSizeRequest,
};
use limine::BaseRevision;
use log::{error, info};
use raw_cpuid::CpuId;
use spin::{Mutex, RwLock};
use x86_64::registers::control::{Cr4, Cr4Flags, Efer, EferFlags};

use crate::arch::irq::{IrqAllocator, IrqLevel};
use crate::driver::acpi::{Acpi, Rsdp};
use crate::driver::apic::{Apic, LocalApic};
use crate::driver::pci::Pci;
use crate::kernel::Kernel;
use crate::{
    logger::{init_logger, switch_to_post_boot_logger},
    memory::FrameAllocator,
    serial::SerialPort,
    vga::Vga,
};

/// Sets the base revision to the latest revision supported by the crate.
/// See specification for further info.
#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[used]
static PAGING_MODE_REQUEST: PagingModeRequest =
    PagingModeRequest::new().with_mode(Mode::FOUR_LEVEL);

#[used]
static MEMORY_MAP_REQUEST: MemoryMapRequest = MemoryMapRequest::new();

#[used]
static HIGHER_HALF_DIRECT_MAPPING_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
static STACK_SIZE_REQUEST: StackSizeRequest = StackSizeRequest::new().with_size(4 * 1024 * 1024); // 4 MiB

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    assert!(BASE_REVISION.is_supported());
    assert!(STACK_SIZE_REQUEST.get_response().is_some());

    Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);
    Cr4::write(Cr4::read() | Cr4Flags::PAGE_GLOBAL | Cr4Flags::FSGSBASE);

    arch::x86::perform_arch_initialization();

    let memory_map_response = MEMORY_MAP_REQUEST.get_response().unwrap();

    let physical_memory_offset = {
        let higher_half_direct_mapping_response =
            HIGHER_HALF_DIRECT_MAPPING_REQUEST.get_response().unwrap();

        higher_half_direct_mapping_response.offset()
    };

    let frame_allocator = FrameAllocator::new(memory_map_response);

    initialize_memory_manager(frame_allocator, physical_memory_offset);

    initialize_heap().expect("Failed to initialize heap");

    let serial = Arc::new(Mutex::new(SerialPort::COM1.open().unwrap()));

    let terminal = Arc::new(Mutex::new({
        let vga = {
            let framebuffer_response = FRAMEBUFFER_REQUEST.get_response().unwrap();
            let framebuffer = framebuffer_response.framebuffers().next().unwrap();

            Vga::new(framebuffer)
        };

        Terminal::new(vga)
    }));

    init_logger(serial.clone(), terminal.clone()).unwrap();

    info!("Hello, moose!");

    PIC.initialize();
    PIT.initialize();

    info!("Waiting started");
    PIT.wait_seconds(1);
    info!("Waiting has ended");

    cpu::ProcessorControlBlock::create_pcb_for_current_processor(
        CpuId::new()
            .get_feature_info()
            .unwrap()
            .initial_local_apic_id() as u16,
    );

    let rsdp_response = RSDP_REQUEST.get_response().unwrap();

    let mut irq_allocator = IrqAllocator::new();
    let timer_irq = irq_allocator.allocate_irq(IrqLevel::Clock);

    let acpi = Arc::new(Acpi::from_rsdp(rsdp_response.address() as *const Rsdp));
    let apic = Arc::new(RwLock::new(Apic::initialize(Arc::clone(&acpi), timer_irq)));

    let kernel = Arc::new(RwLock::new(Kernel {
        acpi,
        apic,
        gdt: x86_64::instructions::tables::sgdt(),
        timer_irq,
        irq_allocator: Arc::new(Mutex::new(irq_allocator)),
    }));

    let _pci_devices = Pci::build_device_tree();

    let bsp_lapic = LocalApic::initialize_for_current_processor(Arc::clone(&kernel));
    let pcb = cpu::ProcessorControlBlock::get_pcb_for_current_processor();

    _ = (*pcb).local_apic.set(bsp_lapic);

    kernel
        .read()
        .apic
        .read()
        .setup_other_application_processors(Arc::clone(&kernel), (*pcb).local_apic.get().unwrap());

    switch_to_post_boot_logger(serial, terminal);

    (*pcb).local_apic.get().unwrap().enable_timer();

    loop {
        asm!("hlt");
    }
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}

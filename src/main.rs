#![feature(abi_x86_interrupt)]
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
mod vga;

use crate::allocator::init_heap;
use crate::driver::{pic::PIC, pit::PIT};
use alloc::rc::Rc;
use core::arch::asm;
use core::cell::RefCell;
use limine::paging::Mode;
use limine::request::{FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest};
use limine::BaseRevision;
use log::{error, info};
use raw_cpuid::CpuId;
use x86_64::registers::control::{Cr4, Cr4Flags, Efer, EferFlags};

use crate::driver::acpi::Acpi;
use crate::driver::apic::{Apic, LocalApic};
use crate::kernel::Kernel;
use crate::logger::LOGGER;
use crate::{
    logger::init_serial_logger,
    memory::{FrameAllocator, MemoryManager},
    serial::{Port, Serial},
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

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    assert!(BASE_REVISION.is_supported());

    Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);
    Cr4::write(Cr4::read() | Cr4Flags::PAGE_GLOBAL | Cr4Flags::FSGSBASE);

    Serial::init(Port::COM1).unwrap();

    init_serial_logger().unwrap();

    info!("Hello, moose!");

    Serial::writeln(Port::COM1, "Hello, moose!");

    arch::x86::perform_arch_initialization();

    PIC.initialize();
    PIT.initialize();

    info!("Waiting started");
    PIT.wait_seconds(1);
    info!("Waiting has ended");

    let memory_map_response = MEMORY_MAP_REQUEST.get_response().unwrap();
    let physical_memory_offset = {
        let higher_half_direct_mapping_response =
            HIGHER_HALF_DIRECT_MAPPING_REQUEST.get_response().unwrap();

        higher_half_direct_mapping_response.offset()
    };

    let frame_allocator = FrameAllocator::new(memory_map_response);
    let mut memory_manager = MemoryManager::new(frame_allocator, physical_memory_offset);
    init_heap(&mut memory_manager).expect("Failed to initialize heap");
    let memory_manager_ref = Rc::new(RefCell::new(memory_manager));

    cpu::ProcessorControlBlock::create_pcb_for_current_processor(
        CpuId::new()
            .get_feature_info()
            .unwrap()
            .initial_local_apic_id() as u16,
    );
    LOGGER.pcb_initialized = true;

    let acpi = Rc::new(RefCell::new(Acpi::with_memory_manager(Rc::clone(
        &memory_manager_ref,
    ))));
    let apic = Rc::new(RefCell::new(Apic::initialize(Rc::clone(&acpi))));

    let kernel = Rc::new(RefCell::new(Kernel {
        acpi,
        apic,
        memory_manager: memory_manager_ref,
    }));

    let bsp_lapic = LocalApic::initialize_for_current_processor(Rc::clone(&kernel));

    kernel
        .borrow()
        .apic
        .borrow()
        .setup_other_application_processors(Rc::clone(&kernel), &bsp_lapic);
    info!(
        "LAPIC TIMER SPEED: {}",
        kernel.borrow().apic.borrow().lapic_timer_ticks_per_second
    );

    let vga = {
        let framebuffer_response = FRAMEBUFFER_REQUEST.get_response().unwrap();
        let framebuffer = framebuffer_response.framebuffers().next().unwrap();

        Vga::new(framebuffer)
    };

    loop {
        asm!("hlt");
    }
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}

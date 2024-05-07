#![feature(abi_x86_interrupt)]
#![feature(strict_provenance)]
#![no_std]
#![no_main]

extern crate alloc;

pub mod allocator;
pub mod arch;
pub mod cpu;
pub mod driver;
pub mod font;
pub mod kernel;
pub mod logger;
pub mod memory;
pub mod serial;
pub mod terminal;
pub mod vga;

use crate::allocator::init_heap;
use crate::driver::{pic::PIC, pit::PIT};
use crate::terminal::Terminal;
use alloc::sync::Arc;
use core::arch::asm;
use limine::paging::Mode;
use limine::request::{FramebufferRequest, HhdmRequest, MemoryMapRequest, PagingModeRequest};
use limine::BaseRevision;
use log::{debug, error, info};
use pretty_hex::pretty_hex;
use raw_cpuid::CpuId;
use spin::{Mutex, RwLock};
use x86_64::registers::control::{Cr4, Cr4Flags, Efer, EferFlags};

use crate::driver::acpi::Acpi;
use crate::driver::apic::{Apic, LocalApic};
use crate::driver::ata::Ata;
use crate::driver::pci::PciDeviceClassMassStorageControllerSubclass::IdeController;
use crate::driver::pci::{Pci, PciDeviceClass};
use crate::kernel::Kernel;
use crate::{
    logger::{init_logger, switch_to_post_boot_logger},
    memory::{FrameAllocator, MemoryManager},
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

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    assert!(BASE_REVISION.is_supported());

    Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);
    Cr4::write(Cr4::read() | Cr4Flags::PAGE_GLOBAL | Cr4Flags::FSGSBASE);

    arch::x86::perform_arch_initialization();

    let mut memory_manager = {
        let memory_map_response = MEMORY_MAP_REQUEST.get_response().unwrap();

        let physical_memory_offset = {
            let higher_half_direct_mapping_response =
                HIGHER_HALF_DIRECT_MAPPING_REQUEST.get_response().unwrap();

            higher_half_direct_mapping_response.offset()
        };

        let frame_allocator = FrameAllocator::new(memory_map_response);

        MemoryManager::new(frame_allocator, physical_memory_offset)
    };

    init_heap(&mut memory_manager).expect("Failed to initialize heap");

    let memory_manager = Arc::new(RwLock::new(memory_manager));

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

    // Comment this out because ACPI will be refactored in next PR anyway
    /*
    let acpi = Arc::new(Acpi::with_memory_manager(Arc::clone(&memory_manager)));
    let apic = Arc::new(RwLock::new(Apic::initialize(Arc::clone(&acpi))));

    let kernel = Arc::new(RwLock::new(Kernel {
        acpi,
        apic,
        memory_manager: memory_manager.clone(),
        gdt: x86_64::instructions::tables::sgdt(),
    }));
    */

    let pci_devices = Pci::build_device_tree();
    let _ata = pci_devices
        .into_iter()
        .filter(|dev| dev.class == PciDeviceClass::MassStorageController(IdeController))
        .for_each(|device| {
            let ata = Ata::new(Arc::new(Mutex::new(device)), memory_manager.clone());

            let sector = ata[1].read_sectors(0, 4);

            for i in 0..sector.len() {
                debug!("{}:\n{}", i, pretty_hex(&sector[i].as_slice()));
            }
        });

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

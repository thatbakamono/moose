#![allow(dead_code)]
#![feature(abi_x86_interrupt)]
#![feature(allocator_api)]
#![feature(strict_provenance)]
#![feature(const_size_of_val)]
#![feature(naked_functions)]
#![feature(asm_const)]
#![no_std]
#![no_main]

extern crate alloc;

mod allocator;
mod arch;
mod cpu;
mod driver;
mod font;
mod kernel;
mod linker;
mod logger;
mod memory;
mod process;
mod scheduler;
mod serial;
mod terminal;
mod vga;

use crate::allocator::initialize_heap;
use crate::driver::{pic::PIC, pit::PIT};
use crate::memory::initialize_memory_manager;
use crate::terminal::Terminal;
use alloc::sync::Arc;
use bitfield_struct::bitfield;
use bitflags::bitflags;
use core::alloc::Layout;
use core::arch::asm;
use core::cmp::min;
use core::ptr::addr_of;
use core::{mem, ptr};
use limine::paging::Mode;
use limine::request::{
    FramebufferRequest, HhdmRequest, KernelAddressRequest, MemoryMapRequest, PagingModeRequest,
    RsdpRequest, StackSizeRequest,
};
use limine::BaseRevision;
use log::{error, info};
use process::Process;
use raw_cpuid::CpuId;
use scheduler::Scheduler;
use spin::{Mutex, RwLock};
use x86_64::registers::control::{Cr3, Cr4, Cr4Flags, Efer, EferFlags};

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

#[used]
static KERNEL_ADDRESS_REQUEST: KernelAddressRequest = KernelAddressRequest::new();

static mut KERNEL_PAGE_TABLE: *const () = ptr::null();

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    assert!(BASE_REVISION.is_supported());
    assert!(STACK_SIZE_REQUEST.get_response().is_some());

    Efer::write(Efer::read() | EferFlags::NO_EXECUTE_ENABLE);
    Cr4::write(Cr4::read() | Cr4Flags::PAGE_GLOBAL | Cr4Flags::PCID | Cr4Flags::FSGSBASE);

    KERNEL_PAGE_TABLE = Cr3::read().0.start_address().as_u64() as *const ();

    asm!("cli", options(nostack, nomem));

    {
        GDT.tss_segment = SystemSegmentDescriptor::new(
            addr_of!(TSS) as u64,
            mem::size_of::<TaskStateSegment>() as u32,
            SystemSegmentDescriptorAttributes::new()
                .with_present(true)
                .with_segment_type(SystemSegmentType::SixtyFourBitAvailableTaskStateSegment),
            Flags::empty(),
        );

        GDT_DESCRIPTOR = GlobalDescriptorTableDescriptor::new(
            mem::size_of_val(&GDT) as u16 - 1,
            addr_of!(GDT) as u64,
        );

        asm!(
            "lgdt [{gdt}]",
            gdt = in(reg) addr_of!(GDT_DESCRIPTOR) as u64,
        );
    }

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

    let interrupt_stack = alloc::alloc::alloc_zeroed(Layout::new::<Stack>()) as *mut Stack;

    TSS.rsp0 = interrupt_stack as u64 + mem::size_of::<Stack>() as u64 - 16;
    TSS.rsp1 = interrupt_stack as u64 + mem::size_of::<Stack>() as u64 - 16;
    TSS.rsp2 = interrupt_stack as u64 + mem::size_of::<Stack>() as u64 - 16;

    {
        asm!(
            "
                push rax
                mov ax, (9 << 3) | 3
                ltr ax
                pop rax
            "
        );

        asm!("sti", options(nomem));
    }

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

    info!("Entering user mode!");

    static PROGRAM_1: &[u8] = include_bytes!("../../program1/target/x86_64-moose/release/program1");
    static PROGRAM_2: &[u8] = include_bytes!("../../program2/target/x86_64-moose/release/program2");

    Process::new(PROGRAM_1, physical_memory_offset, interrupt_stack).start();
    Process::new(PROGRAM_2, physical_memory_offset, interrupt_stack).start();

    (*pcb).local_apic.get().unwrap().enable_timer();

    Scheduler::run();
}

pub trait Read {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()>;
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ()>;
}

pub struct Cursor<T> {
    inner: T,
    position: u64,
}

impl<T> Cursor<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, position: 0 }
    }

    pub fn seek(&mut self, position: u64) {
        self.position = position;
    }
}

impl Read for Cursor<&[u8]> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()> {
        let size = min(self.inner.len() - self.position as usize, buffer.len());

        for i in 0..size {
            buffer[i] = self.inner[self.position as usize + i];
        }

        Ok(size)
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ()> {
        if (self.inner.len() as u64 - self.position) < buffer.len() as u64 {
            return Err(());
        }

        for i in self.position as usize..self.position as usize + buffer.len() {
            buffer[self.position as usize - i] = self.inner[i];
        }

        self.position += buffer.len() as u64;

        Ok(())
    }
}

#[repr(C)]
#[repr(align(4096))]
struct Stack([u8; 16 * 1024]);

impl Stack {
    fn new() -> Self {
        Self([0; 16 * 1024])
    }
}

static mut GDT_DESCRIPTOR: GlobalDescriptorTableDescriptor =
    GlobalDescriptorTableDescriptor::new(0, 0); // We can't obtain the address of GDT at compile-time, so we have to initialize this in _start
static mut GDT: GlobalDescriptorTable = GlobalDescriptorTable::new(); // We can't obtain the address of TSS at compile-time, so we have to initialize it in _start
static mut TSS: TaskStateSegment = TaskStateSegment::new(
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    mem::size_of::<TaskStateSegment>() as u16,
); // We have to allocate stacks first, thus we need to initialize rsps in _start

#[repr(C, packed)]
pub(crate) struct GlobalDescriptorTableDescriptor {
    size: u16,
    offset: u64,
}

impl GlobalDescriptorTableDescriptor {
    pub(crate) const fn new(size: u16, offset: u64) -> Self {
        Self { size, offset }
    }
}

#[repr(C, packed)]
pub(crate) struct GlobalDescriptorTable {
    null_entry: SegmentDescriptor,
    kernel_mode_sixteen_bit_code_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    kernel_mode_sixteen_bit_data_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    kernel_mode_thirty_two_bit_code_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    kernel_mode_thirty_two_bit_data_segment: SegmentDescriptor, // TODO: Unused, present for compatibility with Limine, see whether this can be removed
    kernel_mode_sixty_four_code_segment: SegmentDescriptor,
    kernel_mode_sixty_four_data_segment: SegmentDescriptor,
    user_mode_sixty_four_code_segment: SegmentDescriptor,
    user_mode_sixty_four_data_segment: SegmentDescriptor,
    tss_segment: SystemSegmentDescriptor,
    padding: SegmentDescriptor,
}

impl GlobalDescriptorTable {
    pub(crate) const fn new() -> Self {
        Self {
            null_entry: SegmentDescriptor::zero(),
            kernel_mode_sixteen_bit_code_segment: SegmentDescriptor::zero(),
            kernel_mode_sixteen_bit_data_segment: SegmentDescriptor::zero(),
            kernel_mode_thirty_two_bit_code_segment: SegmentDescriptor::zero(),
            kernel_mode_thirty_two_bit_data_segment: SegmentDescriptor::zero(),
            kernel_mode_sixty_four_code_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_descriptor_type(true)
                    .with_executable(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                Flags::SixtyFourBitCodeSegment,
            ),
            kernel_mode_sixty_four_data_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_descriptor_type(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                Flags::empty(),
            ),
            user_mode_sixty_four_code_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_privilege_level(3)
                    .with_descriptor_type(true)
                    .with_executable(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                Flags::SixtyFourBitCodeSegment,
            ),
            user_mode_sixty_four_data_segment: SegmentDescriptor::new(
                0,
                0,
                SegmentDescriptorAttributes::new()
                    .with_present(true)
                    .with_privilege_level(3)
                    .with_descriptor_type(true)
                    .with_readable_or_writable(true)
                    .with_accessed(true),
                Flags::empty(),
            ),
            tss_segment: SystemSegmentDescriptor::zero(),
            padding: SegmentDescriptor::zero(),
        }
    }
}

#[derive(Clone, Copy, Default)]
#[repr(C, packed)]
pub(crate) struct SegmentDescriptor {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    attributes: u8,
    flags_and_limit_high: u8,
    base_high: u8,
}

impl SegmentDescriptor {
    pub(crate) const fn zero() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            attributes: 0,
            flags_and_limit_high: 0,
            base_high: 0,
        }
    }

    pub(crate) const fn new(
        base: u32,
        limit: u32,
        attributes: SegmentDescriptorAttributes,
        flags: Flags,
    ) -> Self {
        assert!(limit <= 0b1111_1111_1111_1111_1111);

        if flags.contains(Flags::SixtyFourBitCodeSegment) {
            assert!(base == 0);
            assert!(limit == 0);
        }

        let base_high = ((base >> 24) & 0xFF) as u8;
        let base_mid = ((base >> 16) & 0xFF) as u8;
        let base_low = (base & 0xFFFF) as u16;

        let limit_low = limit as u16;

        let attributes = attributes.into_bits();

        let flags_and_limit_high = (((limit >> 16) & 0xF) as u8) | ((flags.bits() & 0xF) << 4);

        Self {
            limit_low,
            base_low,
            base_mid,
            attributes,
            flags_and_limit_high,
            base_high,
        }
    }
}

#[bitfield(u8)]
struct SegmentDescriptorAttributes {
    accessed: bool,
    readable_or_writable: bool,
    direction_or_conforming: bool,
    executable: bool,
    descriptor_type: bool,
    #[bits(2)]
    privilege_level: u8,
    present: bool,
}

#[repr(C, packed)]
pub(crate) struct SystemSegmentDescriptor {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    attributes: u8,
    flags_and_limit_high: u8,
    base_high: u8,
    base_higher: u32,
    reserved: u32,
}

impl SystemSegmentDescriptor {
    pub(crate) const fn zero() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            attributes: 0,
            flags_and_limit_high: 0,
            base_high: 0,
            base_higher: 0,
            reserved: 0,
        }
    }

    pub(crate) const fn new(
        base: u64,
        limit: u32,
        attributes: SystemSegmentDescriptorAttributes,
        flags: Flags,
    ) -> Self {
        assert!(limit <= 0b1111_1111_1111_1111_1111);

        let limit_low = (limit & 0xFFFF) as u16;
        let base_low = (base & 0xFFFF) as u16;
        let base_mid = ((base >> 16) & 0xFF) as u8;
        let attributes = attributes.into_bits();
        let flags_and_limit_high = ((flags.bits() & 0xF) << 4) | (((limit >> 16) & 0xF) as u8);
        let base_high = ((base >> 24) & 0xFF) as u8;
        let base_higher = ((base >> 32) & 0xFFFF_FFFF) as u32;

        Self {
            limit_low,
            base_low,
            base_mid,
            attributes,
            flags_and_limit_high,
            base_high,
            base_higher,
            reserved: 0,
        }
    }

    fn base(&self) -> u64 {
        ((self.base_higher as u64) << 32)
            | ((self.base_high as u64) << 24)
            | ((self.base_mid as u64) << 16)
            | (self.base_low as u64)
    }
}

#[bitfield(u8)]
struct SystemSegmentDescriptorAttributes {
    #[bits(4, default =  SystemSegmentType::LocalDescriptorTable)]
    segment_type: SystemSegmentType,
    _unused: bool,
    #[bits(2)]
    privilege_level: u8,
    present: bool,
}

#[derive(Debug)]
enum SystemSegmentType {
    LocalDescriptorTable,
    SixtyFourBitAvailableTaskStateSegment,
    SixtyFourBitBusyTaskStateSegment,
}

impl SystemSegmentType {
    const fn from_bits(bits: u8) -> Self {
        match bits {
            0x2 => Self::LocalDescriptorTable,
            0x9 => Self::SixtyFourBitAvailableTaskStateSegment,
            0xB => Self::SixtyFourBitBusyTaskStateSegment,
            _ => panic!(),
        }
    }

    const fn into_bits(self) -> u8 {
        match self {
            SystemSegmentType::LocalDescriptorTable => 0x2,
            SystemSegmentType::SixtyFourBitAvailableTaskStateSegment => 0x9,
            SystemSegmentType::SixtyFourBitBusyTaskStateSegment => 0xB,
        }
    }
}

bitflags! {
    pub(crate) struct Flags: u8 {
        const SixtyFourBitCodeSegment = 0b00000010;
        const ThirtyTwoBitProtectedModeSegment = 0b0000100;
        const IsLimitScaledBy4KiB = 0b00001000;

        const _ = !0;
    }
}

#[repr(C, packed)]
pub(crate) struct TaskStateSegment {
    reserved1: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved2: u32,
    reserved3: u32,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved4: u32,
    reserved5: u32,
    reserved6: u16,
    iopb: u16,
}

impl TaskStateSegment {
    pub(crate) const fn new(
        rsp0: u64,
        rsp1: u64,
        rsp2: u64,
        ist1: u64,
        ist2: u64,
        ist3: u64,
        ist4: u64,
        ist5: u64,
        ist6: u64,
        ist7: u64,
        iopb: u16,
    ) -> Self {
        Self {
            reserved1: 0,
            rsp0,
            rsp1,
            rsp2,
            reserved2: 0,
            reserved3: 0,
            ist1,
            ist2,
            ist3,
            ist4,
            ist5,
            ist6,
            ist7,
            reserved4: 0,
            reserved5: 0,
            reserved6: 0,
            iopb,
        }
    }
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}

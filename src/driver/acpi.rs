use crate::memory::{
    Frame, MemoryError, MemoryManager, Page, PageFlags, PhysicalAddress, VirtualAddress, PAGE_SIZE,
};
use alloc::sync::Arc;
use alloc::{format, vec, vec::Vec};
use core::cell::RefCell;
use core::{mem, slice};
use deku::bitvec::{BitSlice, Msb0};
use deku::{DekuEnumExt, DekuError, DekuRead};
use log::info;

/// Root System Description Pointer Signature
const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
///  Multiple APIC Description Table (MADT)
const MADT_SIGNATURE: [u8; 4] = *b"APIC";
/// Boot Error Record Table (BERT)
const BERT_SIGNATURE: [u8; 4] = *b"BERT";
/// Corrected Platform Error Polling Table (CPEP)
const CPEP_SIGNATURE: [u8; 4] = *b"CPEP";
/// Differentiated System Description Table (DSDT)
const DSDT_SIGNATURE: [u8; 4] = *b"DSDT";
/// Embedded Controller Boot Resources Table (ECDT)
const ECDT_SIGNATURE: [u8; 4] = *b"ECDT";
/// Error Injection Table (EINJ)
const EINJ_SIGNATURE: [u8; 4] = *b"EINJ";
/// Error Record Serialization Table (ERST)
const ERST_SIGNATURE: [u8; 4] = *b"ERST";
/// Fixed ACPI Description Table (FADT)
const FADT_SIGNATURE: [u8; 4] = *b"FACP";
/// Firmware ACPI Control Structure (FACS)
const FACS_SIGNATURE: [u8; 4] = *b"FACS";
/// Hardware Error Source Table (HEST)
const HEST_SIGNATURE: [u8; 4] = *b"HEST";
/// Maximum System Characteristics Table (MSCT)
const MSCT_SIGNATURE: [u8; 4] = *b"MSCT";
/// Memory Power State Table (MPST)
const MPST_SIGNATURE: [u8; 4] = *b"MPST";
/// Platform Memory Topology Table (PMTT)
const PMTT_SIGNATURE: [u8; 4] = *b"PMTT";
/// Persistent System Description Table (PSDT)
const PSDT_SIGNATURE: [u8; 4] = *b"PSDT";
/// ACPI RAS Feature Table (RASF)
const RASF_SIGNATURE: [u8; 4] = *b"RASF";
/// Root System Description Table
const RSDT_SIGNATURE: [u8; 4] = *b"RSDT";
/// Smart Battery Specification Table (SBST)
const SBST_SIGNATURE: [u8; 4] = *b"SBST";
/// System Locality System Information Table (SLIT)
const SLIT_SIGNATURE: [u8; 4] = *b"SLIT";
/// System Resource Affinity Table (SRAT)
const SRAT_SIGNATURE: [u8; 4] = *b"SRAT";
/// Secondary System Description Table (SSDT)
const SSDT_SIGNATURE: [u8; 4] = *b"SSDT";
/// Extended System Description Table (XSDT; 64-bit version of the RSDT)
const XSDT_SIGNATURE: [u8; 4] = *b"XSDT";

const BIOS_EXTENDED_AREA_MEMORY_START: u64 = 0x000E0000;
const BIOS_EXTENDED_AREA_MEMORY_END: u64 = 0x000FFFFF;
const PAGE_NUMBER_MASK: u64 = 0xFFFF_FFFF_F000;

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    ext_checksum: u8,
    reserved: [u8; 3],
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
pub struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

#[derive(Debug, Default)]
#[repr(C, packed)]
pub struct Madt {
    header: SdtHeader,
    lapic_address: u32,
}

pub struct Acpi {
    pub rsdp: Rsdp,
    pub madt: Arc<MADT>,
    memory_manager: Arc<RefCell<MemoryManager>>,
}

impl Acpi {
    pub fn with_memory_manager(memory_manager: Arc<RefCell<MemoryManager>>) -> Acpi {
        // Map BIOS extended area memory
        for page in
            (BIOS_EXTENDED_AREA_MEMORY_START..BIOS_EXTENDED_AREA_MEMORY_END).step_by(PAGE_SIZE)
        {
            unsafe {
                memory_manager
                    .borrow_mut()
                    .map(
                        &Page::new(VirtualAddress::new(page)),
                        &Frame::new(PhysicalAddress::new(page)),
                        PageFlags::empty(),
                    )
                    .unwrap()
            }
        }

        let extended_area = unsafe {
            slice::from_raw_parts(
                BIOS_EXTENDED_AREA_MEMORY_START as *mut u8,
                (BIOS_EXTENDED_AREA_MEMORY_END - BIOS_EXTENDED_AREA_MEMORY_START) as usize,
            )
        };
        let rsdp = extended_area
            .windows(mem::size_of::<Rsdp>())
            .step_by(16)
            .find_map(|possible_rsdp_slice| {
                let rsdp_pointer = possible_rsdp_slice.as_ptr().cast::<Rsdp>();
                let rsdp = unsafe { &*rsdp_pointer };

                if rsdp.signature == RSDP_SIGNATURE {
                    return Some(rsdp);
                }

                None
            })
            .expect("RSDP table not found");

        let rsdt_address = rsdp.rsdt_address as u64;

        unsafe {
            memory_manager.borrow_mut().map(
                &Page::new(VirtualAddress::new(rsdt_address & 0xFFFF_FFFF_F000)),
                &Frame::new(PhysicalAddress::new(rsdt_address & 0xFFFF_FFFF_F000)),
                PageFlags::empty(),
            )
        }
        .expect("Cannot map RSDT");

        let mut acpi = Self {
            memory_manager,
            rsdp: rsdp.clone(),
            madt: Arc::new(MADT::default()),
        };

        acpi.parse_rsdt();

        acpi
    }

    fn parse_rsdt(&mut self) {
        let rsdt_header_slice = unsafe {
            slice::from_raw_parts(
                self.rsdp.rsdt_address as *const u8,
                mem::size_of::<SdtHeader>(),
            )
        };
        let rsdt_header = unsafe { &*rsdt_header_slice.as_ptr().cast::<SdtHeader>() };

        // Iterate over pointers to another tables
        for entry in 0..((rsdt_header.length - (mem::size_of::<SdtHeader>() as u32)) / 4) {
            // Get address to the pointer to another table
            let address_to_pointer_to_another_table = (self.rsdp.rsdt_address
                + (mem::size_of::<SdtHeader>() as u32)
                + (entry * 4)) as *const u32;
            let pointer_to_entry_header = unsafe { &*address_to_pointer_to_another_table }.clone();

            // Map table into memory
            unsafe {
                let page_number = pointer_to_entry_header as u64 & PAGE_NUMBER_MASK;
                match self.memory_manager.borrow_mut().map(
                    &Page::new(VirtualAddress::new(page_number)),
                    &Frame::new(PhysicalAddress::new(page_number)),
                    PageFlags::empty(),
                ) {
                    // If page was unmapped, and we've just mapped it, it's ok
                    Ok(()) => {}
                    // If page was already mapped, it means that we have mapped it in previous loop
                    // iteration, and it's ok
                    Err(MemoryError::AlreadyMapped) => {}
                    // In case of any other error bail out
                    Err(err) => {
                        panic!("Memory error: {}", err);
                    }
                }
            };

            // We need to first parse every entry header, create slice and then parse it, because
            // we need to create safe slice around this table and the only way we can get the slice
            // length is by reading the entry header.
            let entry_header = unsafe { &*(pointer_to_entry_header as *const SdtHeader) };
            let slice = unsafe {
                slice::from_raw_parts(
                    pointer_to_entry_header as *const u8,
                    entry_header.length as usize,
                )
            };

            match entry_header.signature {
                MADT_SIGNATURE => {
                    let madt = MADT::try_from(slice).unwrap();
                    info!("MADT: {:#?}", madt);
                    self.madt = Arc::new(madt);
                }
                _ => {}
            }
        }
    }

    fn validate_checksum(_header: &SdtHeader) -> bool {
        todo!()
    }
}

#[derive(DekuRead, Debug, Default)]
#[deku(magic = b"APIC")]
#[repr(C)]
pub struct MADT {
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    #[deku(bytes = "6")]
    pub oem_id: u64,
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    pub local_apic_address: u32,
    pub flags: u32,
    #[deku(reader = "madt_reader((*length as usize), deku::rest)")]
    pub entries: Vec<MADTEntry>,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MADTEntry {
    pub entry_type: u8,
    pub record_length: u8,
    #[deku(ctx = "*entry_type")]
    pub inner: MADTEntryInner,
}

#[derive(DekuRead, Debug, Clone)]
#[deku(ctx = "entry_type: u8", id = "entry_type")]
#[repr(C)]
pub enum MADTEntryInner {
    #[deku(id = "0")]
    ProcessorLocalAPIC(MadtProcessorLocalAPIC),
    #[deku(id = "1")]
    IOAPIC(MadtIOAPIC),
    #[deku(id = "2")]
    IOAPICInterruptSourceOverride(MadtIOAPICInterruptSourceOverride),
    #[deku(id = "3")]
    IOAPICNonMaskableInterruptSource(MadtIOAPICNonMaskableInterruptSource),
    #[deku(id = "4")]
    LocalAPICNonMaskableInterrupts(MadtLocalAPICNonMaskableInterrupts),
    #[deku(id = "5")]
    LocalAPICAddressOverride(MadtLocalAPICAddressOverride),
    // 6 - I/O SAPIC
    // 7 - Local SAPIC
    // 8 - Platofrm Interrupt Sources
    #[deku(id = "9")]
    ProcessorLocalx2APIC(MadtProcessorLocalx2APIC),
    // 10 - Local x2APIC NMI
    #[deku(id = "10")]
    Localx2APICNonMaskableInterrupts(MadtLocalx2APICNonMaskableInterrupts),
    // 11 - GIC CPU Interface
    // 12 - GIC Distributor
    // 13 - GIC MSI Frame
    // 14 - GIC Reditributor
    // 15 - GIC Interrupt Translation Sergice
    // 16 - Multiprocessor Wakeup
    // 17 - Core Programmable Interrupt Controller
    // 18 - Legacy I/O Programmable Interrupt Controller
    // 19 - HyperTransport Programmable Interrupt Controller
    // 20 - Extend I/O Programmable Interrupt Controller (EIO PIC)
    // 21 MSI Programmable Interrupt Controller (MSI PIC)
    // 22 Bridge I/O Programmable Interrupt Controller (BIO PIC)
    // 23 Low Pin Count Programmable Interrupt Controller (LPC PIC)
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtProcessorLocalAPIC {
    pub acpi_processor_id: u8,
    pub apic_id: u8,
    pub flags: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtIOAPIC {
    pub io_apic_id: u8,
    pub _reserved: u8,
    pub io_apic_address: u32,
    pub global_system_interrupt_base: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtIOAPICInterruptSourceOverride {
    pub nmi_source: u8,
    pub _reserved: u8,
    pub global_system_interrupt: u32,
    pub flags: u16,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtIOAPICNonMaskableInterruptSource {
    pub flags: u16,
    pub global_system_interrupt: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtLocalAPICNonMaskableInterrupts {
    pub acpi_processor_id: u8,
    pub flags: u16,
    pub lint: u8,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtLocalAPICAddressOverride {
    pub _reserved: u16,
    pub address: u64,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtProcessorLocalx2APIC {
    pub _reserved: u16,
    pub processors_local_x2apic_id: u32,
    pub flags: u32,
    pub acpi_id: u32,
}

#[derive(DekuRead, Debug, Clone)]
#[repr(C)]
pub struct MadtLocalx2APICNonMaskableInterrupts {
    pub flags: u16,
    pub acpi_processor_uid: u32,
    pub local_x2apic_lint: u8,
    #[deku(bytes = "3")]
    pub reserved: u32,
}

fn madt_reader(
    length: usize,
    rest: &BitSlice<u8, Msb0>,
) -> Result<(&BitSlice<u8, Msb0>, Vec<MADTEntry>), DekuError> {
    let mut remaining_bytes = length - 0x2C;

    let mut entries = vec![];

    let mut rest = rest;

    while remaining_bytes > 0 {
        let (remaining_slice, entry) = MADTEntry::read(rest, ())?;

        rest = remaining_slice;
        remaining_bytes -= entry.record_length as usize;

        entries.push(entry);
    }

    Ok((rest, entries))
}

use alloc::format;
use deku::DekuRead;

#[derive(DekuRead, Debug, Default)]
#[deku(magic = b"FACP")]
pub struct Fadt {
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    #[deku(bytes = "6")]
    pub oem_id: u64,
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    pub firmware_control: u32,
    pub dsdt: u32,
    pub int_model: u8,
    pub _reserved: u8,
    pub sci_interrupt: u16,
    pub smi_command_port: u32,
    pub acpi_enable: u8,
    pub acpi_disable: u8,
    pub s4bios_req: u8,
    pub _reserved2: u8,
    pub pm1a_event_block: u32,
    pub pm1b_event_block: u32,
    pub pm1a_control_block: u32,
    pub pm1b_control_block: u32,
    pub pm2_control_block: u32,
    pub pm_timer_block: u32,
    pub gpe0_block: u32,
    pub gpe1_block: u32,
    pub pm1_event_length: u8,
    pub pm1_control_length: u8,
    pub pm2_control_length: u8,
    pub pm_timer_length: u8,
    pub gpe0_length: u8,
    pub gpe1_length: u8,
    pub gpe1_base: u8,
    pub _reserved3: u8,
    pub worst_c2_latency: u16,
    pub worst_c3_latency: u16,
    pub flush_size: u16,
    pub flush_stride: u16,
    pub duty_offset: u8,
    pub duty_width: u8,
    pub day_alarm: u8,
    pub month_alarm: u8,
    pub century: u8,
    pub _reserved4: [u8; 3],
    pub flags: u32,
}

#[derive(DekuRead, Debug, Default)]
pub struct GenericAddressStructure {
    #[deku(
        assert = "(0..=9).contains(address_space) || *address_space == 0x0A || (0x0B..=0x7F).contains(address_space) || (0x80..=0xFF).contains(address_space)"
    )]
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    #[deku(assert = "*access_size <= 4")]
    pub access_size: u8,
    pub address: u64,
}

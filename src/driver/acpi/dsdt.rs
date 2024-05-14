use alloc::{format, vec, vec::Vec};
use deku::{
    bitvec::{BitSlice, Msb0},
    DekuError, DekuRead,
};

#[derive(DekuRead, Debug, Default)]
#[deku(magic = b"DSDT")]
pub struct Dsdt {
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    #[deku(bytes = "6")]
    pub oem_id: u64,
    pub oem_table_id: u64,
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
    #[deku(reader = "aml_reader((*length as usize), deku::rest)")]
    pub aml: Vec<u8>,
}

fn aml_reader(
    length: usize,
    rest: &BitSlice<u8, Msb0>,
) -> Result<(&BitSlice<u8, Msb0>, Vec<u8>), DekuError> {
    let mut remaining_bytes = length - 36;

    let mut entries = Vec::with_capacity(remaining_bytes);

    let mut rest = rest;

    while remaining_bytes > 0 {
        let (remaining_slice, entry) = u8::read(rest, ())?;

        rest = remaining_slice;
        remaining_bytes -= 1;

        entries.push(entry);
    }

    Ok((rest, entries))
}

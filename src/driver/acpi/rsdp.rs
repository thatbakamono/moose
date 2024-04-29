use core::{mem, ptr};

#[derive(Clone, Copy, Debug, Default)]
#[repr(C, packed)]
pub struct Rsdp {
    pub signature: [u8; 8],
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_address: u32,
}

impl Rsdp {
    pub fn verify_checksum(&self) -> bool {
        self.calculate_checksum() & 0xFF == 0
    }

    fn calculate_checksum(&self) -> u64 {
        let size = mem::size_of::<Self>();

        let mut checksum = 0;

        let pointer = (self) as *const _ as *const u8;

        for i in 0..size {
            checksum += unsafe { ptr::read_volatile(pointer.add(i)) } as u64;
        }

        checksum
    }
}

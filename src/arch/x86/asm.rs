use core::arch::asm;

#[inline]
pub fn outb(port: u16, byte: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") port,
            in("al") byte,
        );
    }
}

pub fn inb(port: u16) -> u8 {
    let mut value;

    unsafe {
        asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
        );
    }

    value
}

#[inline]
pub fn outl(port: u16, byte: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") byte,
        );
    }
}

pub fn inl(port: u16) -> u32 {
    let mut value;

    unsafe {
        asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
        );
    }

    value
}

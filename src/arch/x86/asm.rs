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

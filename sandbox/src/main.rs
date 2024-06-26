#![no_std]
#![no_main]

use core::arch::asm;

#[used]
static MESSAGE: &str = "Hello, world!";

#[no_mangle]
extern "C" fn _start() {
    unsafe {
        asm!(
            "
                mov rsi, {message}
                mov rdx, {length}
                mov rax, 1
                mov rdi, 1
                int 80h
            ",
            message = in(reg) MESSAGE as *const _ as *const u8 as u64,
            length = in(reg) MESSAGE.len(),
        );
    }

    loop {}
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    loop {}
}

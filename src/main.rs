#![feature(abi_x86_interrupt)]
#![no_std]
#![no_main]

mod arch;
mod logger;
mod driver;
mod serial;

use crate::driver::pic::PIC;
use crate::driver::pit::PIT;
use limine::BaseRevision;
use log::{error, info};

use crate::{
    logger::init_serial_logger,
    serial::{Port, Serial},
};

/// Sets the base revision to the latest revision supported by the crate.
/// See specification for further info.
#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    assert!(BASE_REVISION.is_supported());

    Serial::init(Port::COM1).unwrap();

    init_serial_logger().unwrap();

    info!("Hello, moose!");

    Serial::writeln(Port::COM1, "Hello, moose!");

    arch::x86::perform_arch_initialization();

    PIC.initialize();
    PIT.initialize();

    Serial::writeln(Port::COM1, "Waiting started");
    PIT.wait(10);
    Serial::writeln(Port::COM1, "Waiting has ended");

    Serial::writeln(Port::COM1, "no crash");

    loop {}
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}

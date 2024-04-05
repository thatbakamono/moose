#![no_std]
#![no_main]

mod arch;
mod logger;
mod serial;

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

    loop {}
}

#[panic_handler]
fn rust_panic(info: &core::panic::PanicInfo) -> ! {
    error!("{info}");

    loop {}
}

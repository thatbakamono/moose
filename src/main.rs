#![no_std]
#![no_main]

mod arch;
mod serial;

use limine::BaseRevision;

use crate::serial::{Port, Serial};

/// Sets the base revision to the latest revision supported by the crate.
/// See specification for further info.
#[used]
static BASE_REVISION: BaseRevision = BaseRevision::new();

#[no_mangle]
unsafe extern "C" fn _start() -> ! {
    assert!(BASE_REVISION.is_supported());

    Serial::init(Port::COM1).unwrap();

    Serial::writeln(Port::COM1, "Hello, moose!");

    loop {}
}

#[panic_handler]
fn rust_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

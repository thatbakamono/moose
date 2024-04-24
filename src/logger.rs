use crate::cpu;
use log::{LevelFilter, SetLoggerError};

use crate::serial::{Port, SerialWriter};

pub static mut LOGGER: SerialLogger = SerialLogger {
    pcb_initialized: false,
};

pub struct SerialLogger {
    pub pcb_initialized: bool,
}

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        use core::fmt::Write;

        if self.enabled(record.metadata()) {
            let mut writer = SerialWriter::new(Port::COM1);
            let cpu_id = if self.pcb_initialized {
                unsafe {
                    (*cpu::ProcessorControlBlock::get_pcb_for_current_processor()).apic_processor_id
                }
            } else {
                0
            };

            _ = writeln!(
                writer,
                "[CPU{}] -> [{}] {}",
                cpu_id,
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

pub fn init_serial_logger() -> Result<(), SetLoggerError> {
    unsafe { log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace)) }
}

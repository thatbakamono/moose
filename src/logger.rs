use log::{LevelFilter, SetLoggerError};

use crate::serial::{Port, SerialWriter};

static LOGGER: SerialLogger = SerialLogger;

struct SerialLogger;

impl log::Log for SerialLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        use core::fmt::Write;

        if self.enabled(record.metadata()) {
            let mut writer = SerialWriter::new(Port::COM1);

            _ = writeln!(writer, "[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_serial_logger() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))
}

use crate::cpu;
use core::fmt::Write;
use log::{LevelFilter, Log, SetLoggerError};
use spin::RwLock;
use x86_64::instructions::interrupts;

use crate::serial::{Port, SerialWriter};

static BOOT_LOGGER: BootLogger = BootLogger::new();
static POST_BOOT_LOGGER: PostBootLogger = PostBootLogger::new();

static LOGGER: SwitchableLogger = SwitchableLogger::new(&BOOT_LOGGER);

struct SwitchableLogger {
    inner: RwLock<&'static dyn Log>,
}

impl SwitchableLogger {
    const fn new(logger: &'static dyn Log) -> Self {
        Self {
            inner: RwLock::new(logger),
        }
    }

    fn set_logger(&self, logger: &'static dyn Log) {
        interrupts::without_interrupts(|| {
            *self.inner.write() = logger;
        });
    }
}

impl Log for SwitchableLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        let logger = self.inner.read();

        logger.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        let logger = self.inner.read();

        logger.log(record);
    }

    fn flush(&self) {
        let logger = self.inner.read();

        logger.flush();
    }
}

struct BootLogger;

impl BootLogger {
    const fn new() -> Self {
        Self
    }
}

impl Log for BootLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let mut writer = SerialWriter::new(Port::COM1);

            _ = writeln!(writer, "[{}] {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

struct PostBootLogger;

impl PostBootLogger {
    const fn new() -> Self {
        Self
    }
}

impl Log for PostBootLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let mut writer = SerialWriter::new(Port::COM1);

            let cpu_id = unsafe { &*cpu::ProcessorControlBlock::get_pcb_for_current_processor() }
                .apic_processor_id;

            _ = writeln!(
                writer,
                "[CPU{}] [{}] {}",
                cpu_id,
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

pub fn init_logger() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))
}

pub fn switch_to_post_boot_logger() {
    LOGGER.set_logger(&POST_BOOT_LOGGER);
}

use crate::arch::x86::{inb, outb};

const COM1: u16 = 0x3f8;

#[derive(Clone, Copy)]
pub enum Port {
    COM1,
}

pub struct Serial;

impl Serial {
    pub fn init(port: Port) -> Result<(), ()> {
        let port = match port {
            Port::COM1 => COM1,
        };

        // Source: https://wiki.osdev.org/Serial_Ports

        outb(port + 1, 0x00); // Disable all interrupts

        outb(port + 3, 0x80); // Enable DLAB (set baud rate divisor)
        outb(port + 0, 0x03); // Set divisor to 3 (lo byte) 38400 baud
        outb(port + 1, 0x00); //                  (hi byte)
        outb(port + 3, 0x03); // 8 bits, no parity, one stop bit

        outb(port + 2, 0xC7); // Enable FIFO, clear them, with 14-byte threshold

        outb(port + 4, 0x0B); // IRQs enabled, RTS/DSR set

        outb(port + 4, 0x1E); // Set in loopback mode, test the serial chip

        // Test serial chip (send byte 0xAE and check if serial returns same byte)
        outb(port + 0, 0xAE);

        if inb(port + 0) != 0xAE {
            return Err(());
        }

        // If serial is not faulty set it in normal operation mode
        // (not-loopback with IRQs enabled and OUT#1 and OUT#2 bits enabled)
        outb(port + 4, 0x0F);

        Ok(())
    }

    pub fn write(port: Port, text: &str) {
        let port = match port {
            Port::COM1 => COM1,
        };

        for byte in text.bytes() {
            outb(port, byte);
        }
    }

    pub fn writeln(port: Port, text: &str) {
        let port = match port {
            Port::COM1 => COM1,
        };

        for byte in text.bytes() {
            outb(port, byte);
        }

        outb(port, '\n' as u8);
    }
}

pub struct SerialWriter {
    port: Port,
}

impl SerialWriter {
    pub fn new(port: Port) -> Self {
        Self { port }
    }
}

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        Serial::write(self.port, s);

        Ok(())
    }
}

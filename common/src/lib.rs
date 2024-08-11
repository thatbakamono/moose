#![no_std]

use core::cmp::min;

pub trait Read {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()>;
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ()>;
}

pub struct Cursor<T> {
    inner: T,
    position: u64,
}

impl<T> Cursor<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, position: 0 }
    }

    pub fn seek(&mut self, position: u64) {
        self.position = position;
    }
}

impl Read for Cursor<&[u8]> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()> {
        let size = min(self.inner.len() - self.position as usize, buffer.len());

        for i in 0..size {
            buffer[i] = self.inner[self.position as usize + i];
        }

        self.position += size as u64;

        Ok(size)
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ()> {
        if (self.inner.len() as u64 - self.position) < buffer.len() as u64 {
            return Err(());
        }

        for i in self.position as usize..self.position as usize + buffer.len() {
            buffer[self.position as usize - i] = self.inner[i];
        }

        self.position += buffer.len() as u64;

        Ok(())
    }
}

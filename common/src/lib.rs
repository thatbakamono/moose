#![no_std]

use core::cmp::min;

pub trait Read {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()>;
    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ()>;
}

pub trait Seek {
    fn position(&self) -> u64;
    fn seek(&mut self, position: u64) -> Result<(), ()>;
}

pub struct Cursor<T> {
    inner: T,
    position: u64,
}

impl<T> Cursor<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, position: 0 }
    }
}

impl Read for Cursor<&[u8]> {
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, ()> {
        let size = min(self.inner.len() - self.position as usize, buffer.len());

        buffer[..size]
            .copy_from_slice(&self.inner[self.position as usize..self.position as usize + size]);

        self.position += size as u64;

        Ok(size)
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), ()> {
        if (self.inner.len() as u64 - self.position) < buffer.len() as u64 {
            return Err(());
        }

        buffer.copy_from_slice(
            &self.inner[self.position as usize..self.position as usize + buffer.len()],
        );

        self.position += buffer.len() as u64;

        Ok(())
    }
}

impl Seek for Cursor<&[u8]> {
    fn position(&self) -> u64 {
        self.position
    }

    fn seek(&mut self, position: u64) -> Result<(), ()> {
        if position >= self.inner.len() as u64 {
            return Err(());
        }

        self.position = position;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_with_buffer_smaller_than_input() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        let mut buffer = [0u8; 4];

        assert_eq!(cursor.read(&mut buffer), Ok(4));
        assert_eq!(buffer, [0, 1, 2, 3]);
    }

    #[test]
    fn read_with_buffer_bigger_than_input() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        let mut buffer = [0u8; 16];

        assert_eq!(cursor.read(&mut buffer), Ok(8));
        assert_eq!(buffer, [0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn read_exact_with_buffer_smaller_than_input() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        let mut buffer = [0u8; 4];

        assert!(cursor.read_exact(&mut buffer).is_ok());
        assert_eq!(buffer, [0, 1, 2, 3]);
    }

    #[test]
    fn read_exact_with_buffer_equal_in_size_to_input() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        let mut buffer = [0u8; 8];

        assert!(cursor.read_exact(&mut buffer).is_ok());
        assert_eq!(buffer, [0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn read_exact_with_buffer_bigger_than_input() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        let mut buffer = [0u8; 16];

        assert!(cursor.read_exact(&mut buffer).is_err());
    }

    #[test]
    fn position_after_read() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        let mut buffer = [0u8; 4];

        assert!(cursor.read(&mut buffer).is_ok());
        assert_eq!(cursor.position(), 4);
    }

    #[test]
    fn position_after_seek() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        assert!(cursor.seek(3).is_ok());
        assert_eq!(cursor.position(), 3);
    }

    #[test]
    fn read_after_seek() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        assert!(cursor.seek(4).is_ok());

        let mut buffer = [0u8; 4];

        assert_eq!(cursor.read(&mut buffer), Ok(4));
        assert_eq!(buffer, [4, 5, 6, 7]);
    }

    #[test]
    fn read_exact_after_seek() {
        let input = [0, 1, 2, 3, 4, 5, 6, 7];

        let mut cursor = Cursor::new(&input[..]);

        assert!(cursor.seek(4).is_ok());

        let mut buffer = [0u8; 4];

        assert!(cursor.read_exact(&mut buffer).is_ok());
        assert_eq!(buffer, [4, 5, 6, 7]);
    }
}

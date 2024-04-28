use core::ptr;

use crate::font::DEFAULT_ASCII_FONT;
use limine::framebuffer::Framebuffer;

pub struct Vga {
    framebuffer: Framebuffer<'static>,
}

impl Vga {
    pub fn new(framebuffer: Framebuffer<'static>) -> Self {
        Self { framebuffer }
    }

    pub fn put_pixel(&mut self, x: u64, y: u64, color: Rgb) {
        assert!(x < self.framebuffer.width());
        assert!(y < self.framebuffer.height());

        // TODO: Research whether BPP does in practice have other values than 32 and if so,
        //       lift this restriction
        assert_eq!(self.framebuffer.bpp(), 32);

        let bits_per_pixel = self.framebuffer.bpp() as u64;
        let bytes_per_pixel = bits_per_pixel / 8;

        let pixel_offset = ((y * self.framebuffer.pitch()) + (x * bytes_per_pixel)) as isize;
        let current_pixel = unsafe { self.framebuffer.addr().offset(pixel_offset) } as *mut u32;

        let packed_color = (color.0 as u32) << self.framebuffer.red_mask_shift()
            | ((color.1 as u32) << self.framebuffer.green_mask_shift())
            | (color.2 as u32) << self.framebuffer.blue_mask_shift();

        unsafe { ptr::write_volatile(current_pixel, packed_color) };
    }

    pub fn put_pixels(&mut self, x: u64, y: u64, colors: &[Rgb]) {
        let width = self.framebuffer.width();
        let height = self.framebuffer.height();

        assert!(x < width);
        assert!(y < height);

        // TODO: Research whether BPP does in practice have other values than 32 and if so,
        //       lift this restriction
        assert_eq!(self.framebuffer.bpp(), 32);

        let bits_per_pixel = self.framebuffer.bpp() as u64;
        let bytes_per_pixel = bits_per_pixel / 8;

        let mut i = 0;

        let mut current_x = x;
        let mut current_y = y;

        while i < colors.len() {
            if current_x >= width {
                current_x = 0;
                current_y += 1;

                assert!(current_y < height);
            }

            let pixel_offset = ((y * self.framebuffer.pitch()) + (x * bytes_per_pixel)) as isize;
            let current_pixel = unsafe { self.framebuffer.addr().offset(pixel_offset) } as *mut u32;

            let color = colors[i];
            let packed_color = (color.0 as u32) << self.framebuffer.red_mask_shift()
                | ((color.1 as u32) << self.framebuffer.green_mask_shift())
                | (color.2 as u32) << self.framebuffer.blue_mask_shift();

            unsafe { ptr::write_volatile(current_pixel, packed_color) };

            i += 1;
            current_x += 1;
        }
    }

    pub fn fill_rectangle(&mut self, x: u64, y: u64, width: u64, height: u64, color: Rgb) {
        let framebuffer_width = self.framebuffer.width();
        let framebuffer_height = self.framebuffer.height();

        assert!(x < framebuffer_width);
        assert!(y < framebuffer_height);
        assert!((x + width) <= framebuffer_width);
        assert!((y + height) <= framebuffer_height);

        // TODO: Research whether BPP does in practice have other values than 32 and if so,
        //       lift this restriction
        assert_eq!(self.framebuffer.bpp(), 32);

        let bits_per_pixel = self.framebuffer.bpp() as u64;
        let bytes_per_pixel = bits_per_pixel / 8;

        for current_x in x..x + width {
            for current_y in y..y + height {
                let pixel_offset = ((current_y * self.framebuffer.pitch())
                    + (current_x * bytes_per_pixel)) as isize;
                let current_pixel =
                    unsafe { self.framebuffer.addr().offset(pixel_offset) } as *mut u32;

                let packed_color = (color.0 as u32) << self.framebuffer.red_mask_shift()
                    | ((color.1 as u32) << self.framebuffer.green_mask_shift())
                    | (color.2 as u32) << self.framebuffer.blue_mask_shift();

                unsafe { ptr::write_volatile(current_pixel, packed_color) };
            }
        }
    }

    pub fn fill_row(&mut self, x: u64, y: u64, width: u64, color: Rgb) {
        self.fill_rectangle(x, y, width, 1, color);
    }

    pub fn draw_character(
        &mut self,
        x: u64,
        y: u64,
        scale: u64,
        character: char,
        foreground_color: Rgb,
        background_color: Rgb,
    ) {
        let framebuffer_width = self.framebuffer.width();
        let framebuffer_height = self.framebuffer.height();

        assert!((x + 8 * scale) <= framebuffer_width);
        assert!((y + 16 * scale) <= framebuffer_height);

        assert!(character.is_ascii_graphic());

        self.fill_rectangle(x, y, 8 * scale, 16 * scale, background_color);

        for current_x in 0..8 * scale {
            for current_y in 0..16 * scale {
                let glyph = &DEFAULT_ASCII_FONT[character as usize];

                if (glyph[(current_y / scale) as usize] >> (7 - ((current_x / scale) as usize)) & 1)
                    == 1
                {
                    self.put_pixel(x + current_x, y + current_y, foreground_color);
                }
            }
        }
    }

    pub fn copy(&mut self, from: (u64, u64), to: (u64, u64), width: u64, height: u64) {
        let framebuffer_width = self.framebuffer.width();
        let framebuffer_height = self.framebuffer.height();

        assert!(from.0 < framebuffer_width);
        assert!(from.1 < framebuffer_height);
        assert!(to.0 < framebuffer_width);
        assert!(to.1 < framebuffer_height);

        if width == 0 {
            return;
        }

        assert!(from.0 + width <= framebuffer_width);
        assert!(to.0 + width <= framebuffer_width);

        if height == 0 {
            return;
        }

        assert!(from.1 + height <= framebuffer_height);
        assert!(to.1 + height <= framebuffer_height);

        if from == to {
            return;
        }

        if from.0 > to.0 {
            todo!();
        }

        if from.1 < to.1 {
            todo!();
        }

        // TODO: Research whether BPP does in practice have other values than 32 and if so,
        //       lift this restriction
        assert_eq!(self.framebuffer.bpp(), 32);

        let bits_per_pixel = self.framebuffer.bpp() as u64;
        let bytes_per_pixel = bits_per_pixel / 8;

        for y in 0..height {
            for x in 0..width {
                let source_x = x + from.0;
                let source_y = y + from.1;
                let destination_x = x + to.0;
                let destination_y = y + to.1;

                let source_pixel_offset =
                    ((source_y * self.framebuffer.pitch()) + (source_x * bytes_per_pixel)) as isize;
                let source_pixel =
                    unsafe { self.framebuffer.addr().offset(source_pixel_offset) } as *mut u32;

                let destination_pixel_offset = ((destination_y * self.framebuffer.pitch())
                    + (destination_x * bytes_per_pixel))
                    as isize;
                let destination_pixel =
                    unsafe { self.framebuffer.addr().offset(destination_pixel_offset) } as *mut u32;

                unsafe { ptr::write_volatile(destination_pixel, ptr::read_volatile(source_pixel)) };
            }
        }
    }

    pub fn width(&self) -> u64 {
        self.framebuffer.width()
    }

    pub fn height(&self) -> u64 {
        self.framebuffer.height()
    }
}

// Safety: This is safe only if Vga has exclusive access to the framebuffer.
unsafe impl Send for Vga {}

#[derive(Clone, Copy)]
pub struct Rgb(pub u8, pub u8, pub u8);

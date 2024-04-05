use core::ptr;

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
        assert!(x + width < framebuffer_width);
        assert!(x + height < framebuffer_height);

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
}

#[derive(Clone, Copy)]
pub struct Rgb(pub u8, pub u8, pub u8);

use crate::vga::{Rgb, Vga};

pub struct Terminal {
    vga: Vga,
    x: u64,
    y: u64,
}

impl Terminal {
    pub fn new(vga: Vga) -> Self {
        Self { vga, x: 0, y: 0 }
    }

    pub fn print_str(&mut self, string: &str) {
        const FOREGROUND_COLOR: Rgb = Rgb(190, 190, 190);
        const BACKGROUND_COLOR: Rgb = Rgb(0, 0, 0);

        const WIDTH: u64 = 8;
        const HEIGHT: u64 = 16;

        for character in string.chars() {
            if character.is_ascii_control() && !character.is_whitespace() && character != '\n' {
                continue;
            }

            if character == '\n' {
                self.x = 0;
                self.y += HEIGHT;

                if (self.y + HEIGHT) >= self.vga.height() {
                    self.x = 0;
                    self.y -= HEIGHT;

                    self.vga.copy(
                        (0, HEIGHT),
                        (0, 0),
                        self.vga.width(),
                        self.vga.height() - HEIGHT,
                    );

                    self.vga.fill_rectangle(
                        self.x,
                        self.y,
                        self.vga.width(),
                        HEIGHT,
                        BACKGROUND_COLOR,
                    );
                }

                continue;
            }

            if character.is_ascii_graphic() {
                self.vga.draw_character(
                    self.x,
                    self.y,
                    1,
                    character,
                    FOREGROUND_COLOR,
                    BACKGROUND_COLOR,
                );
            } else if !character.is_whitespace() {
                self.vga
                    .draw_character(self.x, self.y, 1, '.', FOREGROUND_COLOR, BACKGROUND_COLOR);
            }

            self.x += WIDTH;

            if (self.x + WIDTH) > self.vga.width() {
                self.x = 0;
                self.y += HEIGHT;

                if (self.y + HEIGHT) >= self.vga.height() {
                    self.x = 0;
                    self.y -= HEIGHT;

                    self.vga.copy(
                        (0, HEIGHT),
                        (0, 0),
                        self.vga.width(),
                        self.vga.height() - HEIGHT,
                    );

                    self.vga.fill_rectangle(
                        self.x,
                        self.y,
                        self.vga.width(),
                        HEIGHT,
                        BACKGROUND_COLOR,
                    );
                }
            }
        }
    }
}

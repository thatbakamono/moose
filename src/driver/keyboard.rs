use crate::arch::irq::IrqLevel;
use crate::arch::x86::asm::inb;
use crate::arch::x86::idt::IDT;
use crate::cpu::ProcessorControlBlock;
use crate::driver::apic::{
    DeliveryMode, DestinationMode, PinPolarity, RedirectionEntry, TriggerMode,
};
use crate::kernel::Kernel;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use log::{debug, error};
use spin::RwLock;
use x86_64::structures::idt::InterruptStackFrame;

pub struct KeyboardDriver {
    irq: u8,
    kernel: Arc<RwLock<Kernel>>,
}

impl KeyboardDriver {
    pub fn new(kernel: Arc<RwLock<Kernel>>) -> Self {
        let irq = kernel
            .write()
            .irq_allocator
            .get_mut()
            .allocate_irq(IrqLevel::HumanInterfaceDevices);

        Self { irq, kernel }
    }

    pub fn init(&self) {
        unsafe {
            IDT[self.irq].set_handler_fn(ps2_keyboard_interrupt_handler);
        }

        let redirection_entry = RedirectionEntry::new()
            .with_delivery_mode(DeliveryMode::Fixed)
            .with_destination(0) // BSP, @TODO: Maybe interrupts load balancing?
            .with_mask(false)
            .with_destination_mode(DestinationMode::Physical)
            .with_interrupt_vector(self.irq)
            .with_pin_polarity(PinPolarity::ActiveHigh)
            .with_trigger_mode(TriggerMode::Edge);

        // PS/2 keyboard has IRQ#1
        self.kernel
            .read()
            .apic
            .read()
            .redirect_interrupt(redirection_entry, 1);
    }
}

static mut PRESSED_KEYS: BTreeSet<Key> = BTreeSet::new();

extern "x86-interrupt" fn ps2_keyboard_interrupt_handler(
    _interrupt_stack_frame: InterruptStackFrame,
) {
    static mut IS_EXTENDED: bool = false;
    static mut IS_PRINT_SCREEN_PRESSED_SEQUENCE: bool = false;
    static mut IS_PRINT_SCREEN_RELEASED_SEQUENCE: bool = false;
    static mut IS_PAUSE_BREAK_SEQUENCE: bool = false;
    static mut PAUSE_BREAK_SEQUENCE_STEP: u8 = 0;

    let status = inb(0x64);

    let can_read = status & 0x1 == 1;
    let time_out_error = (status >> 6) & 0x1 == 1;
    let parity_error = (status >> 7) & 0x1 == 1;

    if time_out_error {
        error!("[Keyboard] Time-out error");

        unsafe {
            _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                .local_apic
                .get()
                .unwrap()
                .signal_end_of_interrupt();
        }

        return;
    }

    if parity_error {
        error!("[Keyboard] Parity error");

        unsafe {
            _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                .local_apic
                .get()
                .unwrap()
                .signal_end_of_interrupt();
        }

        return;
    }

    if can_read {
        let code = inb(0x60);

        if code == 0xE0 && unsafe { !IS_EXTENDED } {
            unsafe {
                IS_EXTENDED = true;

                _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                    .local_apic
                    .get()
                    .unwrap()
                    .signal_end_of_interrupt();
            }

            return;
        }

        if code == 0xE1 && unsafe { !IS_PAUSE_BREAK_SEQUENCE } {
            unsafe {
                IS_PAUSE_BREAK_SEQUENCE = true;

                _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                    .local_apic
                    .get()
                    .unwrap()
                    .signal_end_of_interrupt();
            }

            return;
        }

        if unsafe { IS_PAUSE_BREAK_SEQUENCE } {
            match unsafe { PAUSE_BREAK_SEQUENCE_STEP } {
                0 => {
                    if code == 0x1D {
                        unsafe {
                            PAUSE_BREAK_SEQUENCE_STEP += 1;
                        }
                    } else {
                        error!(
                            "[Keyboard] Invalid pause break sequence, expected 0x1D, got 0x{code:X}"
                        );

                        unsafe {
                            IS_PAUSE_BREAK_SEQUENCE = false;

                            _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                                .local_apic
                                .get()
                                .unwrap()
                                .signal_end_of_interrupt();
                        }

                        return;
                    }
                }
                1 => {
                    if code == 0x45 {
                        unsafe {
                            PAUSE_BREAK_SEQUENCE_STEP += 1;
                        }
                    } else {
                        error!(
                            "[Keyboard] Invalid pause break sequence, expected 0x45, got 0x{code:X}"
                        );

                        unsafe {
                            IS_PAUSE_BREAK_SEQUENCE = false;
                            PAUSE_BREAK_SEQUENCE_STEP = 0;

                            _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                                .local_apic
                                .get()
                                .unwrap()
                                .signal_end_of_interrupt();
                        }

                        return;
                    }
                }
                2 => {
                    if code == 0xE1 {
                        unsafe {
                            PAUSE_BREAK_SEQUENCE_STEP += 1;
                        }
                    } else {
                        error!(
                            "[Keyboard] Invalid pause break sequence, expected 0xE1, got 0x{code:X}"
                        );

                        unsafe {
                            IS_PAUSE_BREAK_SEQUENCE = false;
                            PAUSE_BREAK_SEQUENCE_STEP = 0;

                            _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                                .local_apic
                                .get()
                                .unwrap()
                                .signal_end_of_interrupt();
                        }

                        return;
                    }
                }
                3 => {
                    if code == 0x9D {
                        unsafe {
                            PAUSE_BREAK_SEQUENCE_STEP += 1;
                        }
                    } else {
                        error!(
                            "[Keyboard] Invalid pause break sequence, expected 0x9D, got 0x{code:X}"
                        );

                        unsafe {
                            IS_PAUSE_BREAK_SEQUENCE = false;
                            PAUSE_BREAK_SEQUENCE_STEP = 0;

                            _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                                .local_apic
                                .get()
                                .unwrap()
                                .signal_end_of_interrupt();
                        }

                        return;
                    }
                }
                4 => {
                    if code == 0xC5 {
                        unsafe {
                            PRESSED_KEYS.insert(Key::PauseBreak);
                        }

                        debug!("[Keyboard] {:?} {:?}", KeyState::Pressed, Key::PauseBreak);
                    } else {
                        error!(
                            "[Keyboard] Invalid pause break sequence, expected 0xC5, got 0x{code:X}"
                        );
                    }

                    unsafe {
                        IS_PAUSE_BREAK_SEQUENCE = false;
                        PAUSE_BREAK_SEQUENCE_STEP = 0;

                        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                            .local_apic
                            .get()
                            .unwrap()
                            .signal_end_of_interrupt();
                    }

                    return;
                }
                _ => unreachable!(),
            }

            unsafe {
                _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                    .local_apic
                    .get()
                    .unwrap()
                    .signal_end_of_interrupt();
            }

            return;
        }

        let key_press;

        if unsafe { IS_EXTENDED } {
            if code == 0x2A {
                unsafe {
                    IS_EXTENDED = false;
                    IS_PRINT_SCREEN_PRESSED_SEQUENCE = true;

                    _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                        .local_apic
                        .get()
                        .unwrap()
                        .signal_end_of_interrupt();
                }

                return;
            }

            if code == 0xB7 {
                unsafe {
                    IS_EXTENDED = false;
                    IS_PRINT_SCREEN_RELEASED_SEQUENCE = true;

                    _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
                        .local_apic
                        .get()
                        .unwrap()
                        .signal_end_of_interrupt();
                }

                return;
            }

            if unsafe { IS_PRINT_SCREEN_PRESSED_SEQUENCE } {
                if code == 0x37 {
                    key_press = Some((KeyState::Pressed, Key::PrintScreen));

                    unsafe {
                        IS_PRINT_SCREEN_PRESSED_SEQUENCE = false;
                    }

                    debug!("[Keyboard] {:?} {:?}", KeyState::Pressed, Key::PrintScreen);
                } else {
                    error!("[Keyboard] Invalid print screen sequence follow up");

                    key_press = None;

                    unsafe {
                        IS_PRINT_SCREEN_PRESSED_SEQUENCE = false;
                    }
                }
            } else if unsafe { IS_PRINT_SCREEN_RELEASED_SEQUENCE } {
                if code == 0xAA {
                    key_press = Some((KeyState::Released, Key::PrintScreen));

                    unsafe {
                        IS_PRINT_SCREEN_RELEASED_SEQUENCE = false;
                    }

                    debug!("[Keyboard] {:?} {:?}", KeyState::Released, Key::PrintScreen);
                } else {
                    error!("[Keyboard] Invalid print screen sequence follow up");

                    key_press = None;

                    unsafe {
                        IS_PRINT_SCREEN_RELEASED_SEQUENCE = false;
                    }
                }
            } else {
                key_press = match code {
                    0x10 => Some((KeyState::Pressed, Key::MultimediaPreviousTrack)),
                    0x19 => Some((KeyState::Pressed, Key::MultimediaNextTrack)),
                    0x1C => Some((KeyState::Pressed, Key::KeypadEnter)),
                    0x1D => Some((KeyState::Pressed, Key::RightControl)),
                    0x20 => Some((KeyState::Pressed, Key::MultimediaMute)),
                    0x21 => Some((KeyState::Pressed, Key::MultimediaCalculator)),
                    0x22 => Some((KeyState::Pressed, Key::MultimediaPlay)),
                    0x24 => Some((KeyState::Pressed, Key::MultimediaStop)),
                    0x2E => Some((KeyState::Pressed, Key::MultimediaVolumeDown)),
                    0x30 => Some((KeyState::Pressed, Key::MultimediaVolumeUp)),
                    0x32 => Some((KeyState::Pressed, Key::MultimediaWwwHome)),
                    0x35 => Some((KeyState::Pressed, Key::KeypadSlash)),
                    0x38 => Some((KeyState::Pressed, Key::RightAlt)),
                    0x47 => Some((KeyState::Pressed, Key::Home)),
                    0x48 => Some((KeyState::Pressed, Key::UpArrow)),
                    0x49 => Some((KeyState::Pressed, Key::PageUp)),
                    0x4B => Some((KeyState::Pressed, Key::LeftArrow)),
                    0x4D => Some((KeyState::Pressed, Key::RightArrow)),
                    0x4F => Some((KeyState::Pressed, Key::End)),
                    0x50 => Some((KeyState::Pressed, Key::DownArrow)),
                    0x51 => Some((KeyState::Pressed, Key::PageDown)),
                    0x52 => Some((KeyState::Pressed, Key::Insert)),
                    0x53 => Some((KeyState::Pressed, Key::Delete)),
                    0x5B => Some((KeyState::Pressed, Key::LeftGui)),
                    0x5C => Some((KeyState::Pressed, Key::RightGui)),
                    0x5D => Some((KeyState::Pressed, Key::Apps)),
                    0x5E | 0x5F | 0x63 => {
                        error!("[Keyboard] Unsupported key");

                        None
                    }
                    0x65 => Some((KeyState::Pressed, Key::MultimediaWwwSearch)),
                    0x66 => Some((KeyState::Pressed, Key::MultimediaWwwFavorites)),
                    0x67 => Some((KeyState::Pressed, Key::MultimediaWwwRefresh)),
                    0x68 => Some((KeyState::Pressed, Key::MultimediaWwwStop)),
                    0x69 => Some((KeyState::Pressed, Key::MultimediaWwwForward)),
                    0x6A => Some((KeyState::Pressed, Key::MultimediaWwwBack)),
                    0x6B => Some((KeyState::Pressed, Key::MultimediaMyComputer)),
                    0x6C => Some((KeyState::Pressed, Key::MultimediaEmail)),
                    0x6D => Some((KeyState::Pressed, Key::MultimediaMediaSelect)),

                    0x90 => Some((KeyState::Released, Key::MultimediaPreviousTrack)),
                    0x99 => Some((KeyState::Released, Key::MultimediaNextTrack)),
                    0x9C => Some((KeyState::Released, Key::KeypadEnter)),
                    0x9D => Some((KeyState::Released, Key::RightControl)),
                    0xA0 => Some((KeyState::Released, Key::MultimediaMute)),
                    0xA1 => Some((KeyState::Released, Key::MultimediaCalculator)),
                    0xA2 => Some((KeyState::Released, Key::MultimediaPlay)),
                    0xA4 => Some((KeyState::Released, Key::MultimediaStop)),
                    0xAE => Some((KeyState::Released, Key::MultimediaVolumeDown)),
                    0xB0 => Some((KeyState::Released, Key::MultimediaVolumeUp)),
                    0xB2 => Some((KeyState::Released, Key::MultimediaWwwHome)),
                    0xB5 => Some((KeyState::Released, Key::KeypadSlash)),
                    0xB8 => Some((KeyState::Released, Key::RightAlt)),
                    0xC7 => Some((KeyState::Released, Key::Home)),
                    0xC8 => Some((KeyState::Released, Key::UpArrow)),
                    0xC9 => Some((KeyState::Released, Key::PageUp)),
                    0xCB => Some((KeyState::Released, Key::LeftArrow)),
                    0xCD => Some((KeyState::Released, Key::RightArrow)),
                    0xCF => Some((KeyState::Released, Key::End)),
                    0xD0 => Some((KeyState::Released, Key::DownArrow)),
                    0xD1 => Some((KeyState::Released, Key::PageDown)),
                    0xD2 => Some((KeyState::Released, Key::Insert)),
                    0xD3 => Some((KeyState::Released, Key::Delete)),
                    0xDB => Some((KeyState::Released, Key::LeftGui)),
                    0xDC => Some((KeyState::Released, Key::RightGui)),
                    0xDD => Some((KeyState::Released, Key::Apps)),
                    0xDE | 0xDF | 0xE3 => {
                        error!("[Keyboard] Unsupported key");

                        None
                    }
                    0xE5 => Some((KeyState::Released, Key::MultimediaWwwSearch)),
                    0xE6 => Some((KeyState::Released, Key::MultimediaWwwFavorites)),
                    0xE7 => Some((KeyState::Released, Key::MultimediaWwwRefresh)),
                    0xE8 => Some((KeyState::Released, Key::MultimediaWwwStop)),
                    0xE9 => Some((KeyState::Released, Key::MultimediaWwwForward)),
                    0xEA => Some((KeyState::Released, Key::MultimediaWwwBack)),
                    0xEB => Some((KeyState::Released, Key::MultimediaMyComputer)),
                    0xEC => Some((KeyState::Released, Key::MultimediaEmail)),
                    0xED => Some((KeyState::Released, Key::MultimediaMediaSelect)),

                    _ => {
                        error!("[Keyboard] Unknown scan code");

                        None
                    }
                };
            }

            unsafe {
                IS_EXTENDED = false;
            }
        } else {
            key_press = match code {
                0x01 => Some((KeyState::Pressed, Key::Escape)),
                0x02 => Some((KeyState::Pressed, Key::Numeric1)),
                0x03 => Some((KeyState::Pressed, Key::Numeric2)),
                0x04 => Some((KeyState::Pressed, Key::Numeric3)),
                0x05 => Some((KeyState::Pressed, Key::Numeric4)),
                0x06 => Some((KeyState::Pressed, Key::Numeric5)),
                0x07 => Some((KeyState::Pressed, Key::Numeric6)),
                0x08 => Some((KeyState::Pressed, Key::Numeric7)),
                0x09 => Some((KeyState::Pressed, Key::Numeric8)),
                0x0A => Some((KeyState::Pressed, Key::Numeric9)),
                0x0B => Some((KeyState::Pressed, Key::Numeric0)),
                0x0C => Some((KeyState::Pressed, Key::Minus)),
                0x0D => Some((KeyState::Pressed, Key::Equals)),
                0x0E => Some((KeyState::Pressed, Key::Backspace)),
                0x0F => Some((KeyState::Pressed, Key::Tab)),
                0x10 => Some((KeyState::Pressed, Key::Q)),
                0x11 => Some((KeyState::Pressed, Key::W)),
                0x12 => Some((KeyState::Pressed, Key::E)),
                0x13 => Some((KeyState::Pressed, Key::R)),
                0x14 => Some((KeyState::Pressed, Key::T)),
                0x15 => Some((KeyState::Pressed, Key::Y)),
                0x16 => Some((KeyState::Pressed, Key::U)),
                0x17 => Some((KeyState::Pressed, Key::I)),
                0x18 => Some((KeyState::Pressed, Key::O)),
                0x19 => Some((KeyState::Pressed, Key::P)),
                0x1A => Some((KeyState::Pressed, Key::LeftSquareBracket)),
                0x1B => Some((KeyState::Pressed, Key::RightSquareBracket)),
                0x1C => Some((KeyState::Pressed, Key::Enter)),
                0x1D => Some((KeyState::Pressed, Key::LeftControl)),
                0x1E => Some((KeyState::Pressed, Key::A)),
                0x1F => Some((KeyState::Pressed, Key::S)),
                0x20 => Some((KeyState::Pressed, Key::D)),
                0x21 => Some((KeyState::Pressed, Key::F)),
                0x22 => Some((KeyState::Pressed, Key::G)),
                0x23 => Some((KeyState::Pressed, Key::H)),
                0x24 => Some((KeyState::Pressed, Key::J)),
                0x25 => Some((KeyState::Pressed, Key::K)),
                0x26 => Some((KeyState::Pressed, Key::L)),
                0x27 => Some((KeyState::Pressed, Key::Semicolon)),
                0x28 => Some((KeyState::Pressed, Key::SingleQuote)),
                0x29 => Some((KeyState::Pressed, Key::BackTick)),
                0x2A => Some((KeyState::Pressed, Key::LeftShift)),
                0x2B => Some((KeyState::Pressed, Key::BackSlash)),
                0x2C => Some((KeyState::Pressed, Key::Z)),
                0x2D => Some((KeyState::Pressed, Key::X)),
                0x2E => Some((KeyState::Pressed, Key::C)),
                0x2F => Some((KeyState::Pressed, Key::V)),
                0x30 => Some((KeyState::Pressed, Key::B)),
                0x31 => Some((KeyState::Pressed, Key::N)),
                0x32 => Some((KeyState::Pressed, Key::M)),
                0x33 => Some((KeyState::Pressed, Key::Comma)),
                0x34 => Some((KeyState::Pressed, Key::Dot)),
                0x35 => Some((KeyState::Pressed, Key::Slash)),
                0x36 => Some((KeyState::Pressed, Key::RightShift)),
                0x37 => Some((KeyState::Pressed, Key::KeypadTimes)),
                0x38 => Some((KeyState::Pressed, Key::LeftAlt)),
                0x39 => Some((KeyState::Pressed, Key::Space)),
                0x3A => Some((KeyState::Pressed, Key::CapsLock)),
                0x3B => Some((KeyState::Pressed, Key::F1)),
                0x3C => Some((KeyState::Pressed, Key::F2)),
                0x3D => Some((KeyState::Pressed, Key::F3)),
                0x3E => Some((KeyState::Pressed, Key::F4)),
                0x3F => Some((KeyState::Pressed, Key::F5)),
                0x40 => Some((KeyState::Pressed, Key::F6)),
                0x41 => Some((KeyState::Pressed, Key::F7)),
                0x42 => Some((KeyState::Pressed, Key::F8)),
                0x43 => Some((KeyState::Pressed, Key::F9)),
                0x44 => Some((KeyState::Pressed, Key::F10)),
                0x45 => Some((KeyState::Pressed, Key::NumberLock)),
                0x46 => Some((KeyState::Pressed, Key::ScrollLock)),
                0x47 => Some((KeyState::Pressed, Key::Keypad7)),
                0x48 => Some((KeyState::Pressed, Key::Keypad8)),
                0x49 => Some((KeyState::Pressed, Key::Keypad9)),
                0x4A => Some((KeyState::Pressed, Key::KeypadMinus)),
                0x4B => Some((KeyState::Pressed, Key::Keypad4)),
                0x4C => Some((KeyState::Pressed, Key::Keypad5)),
                0x4D => Some((KeyState::Pressed, Key::Keypad6)),
                0x4E => Some((KeyState::Pressed, Key::KeypadPlus)),
                0x4F => Some((KeyState::Pressed, Key::Keypad1)),
                0x50 => Some((KeyState::Pressed, Key::Keypad2)),
                0x51 => Some((KeyState::Pressed, Key::Keypad3)),
                0x52 => Some((KeyState::Pressed, Key::Keypad0)),
                0x53 => Some((KeyState::Pressed, Key::KeypadDot)),
                0x57 => Some((KeyState::Pressed, Key::F11)),
                0x58 => Some((KeyState::Pressed, Key::F12)),

                0x81 => Some((KeyState::Released, Key::Escape)),
                0x82 => Some((KeyState::Released, Key::Numeric1)),
                0x83 => Some((KeyState::Released, Key::Numeric2)),
                0x84 => Some((KeyState::Released, Key::Numeric3)),
                0x85 => Some((KeyState::Released, Key::Numeric4)),
                0x86 => Some((KeyState::Released, Key::Numeric5)),
                0x87 => Some((KeyState::Released, Key::Numeric6)),
                0x88 => Some((KeyState::Released, Key::Numeric7)),
                0x89 => Some((KeyState::Released, Key::Numeric8)),
                0x8A => Some((KeyState::Released, Key::Numeric9)),
                0x8B => Some((KeyState::Released, Key::Numeric0)),
                0x8C => Some((KeyState::Released, Key::Minus)),
                0x8D => Some((KeyState::Released, Key::Equals)),
                0x8E => Some((KeyState::Released, Key::Backspace)),
                0x8F => Some((KeyState::Released, Key::Tab)),
                0x90 => Some((KeyState::Released, Key::Q)),
                0x91 => Some((KeyState::Released, Key::W)),
                0x92 => Some((KeyState::Released, Key::E)),
                0x93 => Some((KeyState::Released, Key::R)),
                0x94 => Some((KeyState::Released, Key::T)),
                0x95 => Some((KeyState::Released, Key::Y)),
                0x96 => Some((KeyState::Released, Key::U)),
                0x97 => Some((KeyState::Released, Key::I)),
                0x98 => Some((KeyState::Released, Key::O)),
                0x99 => Some((KeyState::Released, Key::P)),
                0x9A => Some((KeyState::Released, Key::LeftSquareBracket)),
                0x9B => Some((KeyState::Released, Key::RightSquareBracket)),
                0x9C => Some((KeyState::Released, Key::Enter)),
                0x9D => Some((KeyState::Released, Key::LeftControl)),
                0x9E => Some((KeyState::Released, Key::A)),
                0x9F => Some((KeyState::Released, Key::S)),
                0xA0 => Some((KeyState::Released, Key::D)),
                0xA1 => Some((KeyState::Released, Key::F)),
                0xA2 => Some((KeyState::Released, Key::G)),
                0xA3 => Some((KeyState::Released, Key::H)),
                0xA4 => Some((KeyState::Released, Key::J)),
                0xA5 => Some((KeyState::Released, Key::K)),
                0xA6 => Some((KeyState::Released, Key::L)),
                0xA7 => Some((KeyState::Released, Key::Semicolon)),
                0xA8 => Some((KeyState::Released, Key::SingleQuote)),
                0xA9 => Some((KeyState::Released, Key::BackTick)),
                0xAA => Some((KeyState::Released, Key::LeftShift)),
                0xAB => Some((KeyState::Released, Key::BackSlash)),
                0xAC => Some((KeyState::Released, Key::Z)),
                0xAD => Some((KeyState::Released, Key::X)),
                0xAE => Some((KeyState::Released, Key::C)),
                0xAF => Some((KeyState::Released, Key::V)),
                0xB0 => Some((KeyState::Released, Key::B)),
                0xB1 => Some((KeyState::Released, Key::N)),
                0xB2 => Some((KeyState::Released, Key::M)),
                0xB3 => Some((KeyState::Released, Key::Comma)),
                0xB4 => Some((KeyState::Released, Key::Dot)),
                0xB5 => Some((KeyState::Released, Key::Slash)),
                0xB6 => Some((KeyState::Released, Key::RightShift)),
                0xB7 => Some((KeyState::Released, Key::KeypadTimes)),
                0xB8 => Some((KeyState::Released, Key::LeftAlt)),
                0xB9 => Some((KeyState::Released, Key::Space)),
                0xBA => Some((KeyState::Released, Key::CapsLock)),
                0xBB => Some((KeyState::Released, Key::F1)),
                0xBC => Some((KeyState::Released, Key::F2)),
                0xBD => Some((KeyState::Released, Key::F3)),
                0xBE => Some((KeyState::Released, Key::F4)),
                0xBF => Some((KeyState::Released, Key::F5)),
                0xC0 => Some((KeyState::Released, Key::F6)),
                0xC1 => Some((KeyState::Released, Key::F7)),
                0xC2 => Some((KeyState::Released, Key::F8)),
                0xC3 => Some((KeyState::Released, Key::F9)),
                0xC4 => Some((KeyState::Released, Key::F10)),
                0xC5 => Some((KeyState::Released, Key::NumberLock)),
                0xC6 => Some((KeyState::Released, Key::ScrollLock)),
                0xC7 => Some((KeyState::Released, Key::Keypad7)),
                0xC8 => Some((KeyState::Released, Key::Keypad8)),
                0xC9 => Some((KeyState::Released, Key::Keypad9)),
                0xCA => Some((KeyState::Released, Key::KeypadMinus)),
                0xCB => Some((KeyState::Released, Key::Keypad4)),
                0xCC => Some((KeyState::Released, Key::Keypad5)),
                0xCD => Some((KeyState::Released, Key::Keypad6)),
                0xCE => Some((KeyState::Released, Key::KeypadPlus)),
                0xCF => Some((KeyState::Released, Key::Keypad1)),
                0xD0 => Some((KeyState::Released, Key::Keypad2)),
                0xD1 => Some((KeyState::Released, Key::Keypad3)),
                0xD2 => Some((KeyState::Released, Key::Keypad0)),
                0xD3 => Some((KeyState::Released, Key::KeypadDot)),
                0xD7 => Some((KeyState::Released, Key::F11)),
                0xD8 => Some((KeyState::Released, Key::F12)),

                _ => {
                    error!("[Keyboard] Unknown code");

                    None
                }
            };
        }

        if let Some((state, key)) = key_press {
            if state == KeyState::Pressed {
                unsafe {
                    PRESSED_KEYS.insert(key);
                }
            } else if state == KeyState::Released {
                unsafe {
                    PRESSED_KEYS.remove(&key);
                }
            }

            debug!("[Keyboard] {state:?} {key:?}");
        }
    }

    unsafe {
        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum KeyState {
    Pressed,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Key {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,

    Numeric0,
    Numeric1,
    Numeric2,
    Numeric3,
    Numeric4,
    Numeric5,
    Numeric6,
    Numeric7,
    Numeric8,
    Numeric9,

    F0,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,

    Keypad0,
    Keypad1,
    Keypad2,
    Keypad3,
    Keypad4,
    Keypad5,
    Keypad6,
    Keypad7,
    Keypad8,
    Keypad9,
    KeypadMinus,
    KeypadPlus,
    KeypadTimes,
    KeypadDot,
    KeypadEnter,
    KeypadSlash,

    Minus,
    Plus,
    Equals,

    Comma,
    Dot,
    SingleQuote,
    DoubleQuote,
    Semicolon,
    BackTick,
    LeftSquareBracket,
    RightSquareBracket,
    BackSlash,
    Slash,

    Enter,
    Tab,
    Space,
    Backspace,
    Insert,
    Delete,

    LeftAlt,
    RightAlt,
    LeftShift,
    RightShift,
    LeftControl,
    RightControl,

    UpArrow,
    DownArrow,
    LeftArrow,
    RightArrow,

    Home,
    End,

    PageUp,
    PageDown,

    Escape,

    CapsLock,
    NumberLock,
    ScrollLock,

    PrintScreen,
    PauseBreak,

    MultimediaPreviousTrack,
    MultimediaWwwSearch,
    MultimediaWwwFavorites,
    MultimediaWwwRefresh,
    MultimediaWwwStop,
    MultimediaWwwForward,
    MultimediaWwwBack,
    MultimediaVolumeUp,
    MultimediaVolumeDown,
    MultimediaStop,
    MultimediaPlay,
    MultimediaCalculator,
    MultimediaNextTrack,
    MultimediaMute,
    MultimediaWwwHome,
    MultimediaMyComputer,
    MultimediaEmail,
    MultimediaMediaSelect,

    LeftGui,
    RightGui,
    Apps,
}

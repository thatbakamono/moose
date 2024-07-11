use core::cell::OnceCell;

use crate::arch::irq::IrqLevel;
use crate::arch::x86::asm::inb;
use crate::arch::x86::idt::IDT;
use crate::cpu::ProcessorControlBlock;
use crate::driver::apic::{
    DeliveryMode, DestinationMode, PinPolarity, RedirectionEntry, TriggerMode,
};
use crate::kernel::Kernel;
use alloc::collections::BTreeSet;
use log::{debug, error};
use x86_64::structures::idt::InterruptStackFrame;

static mut PRESSED_KEYS: BTreeSet<Key> = BTreeSet::new();

static mut KEYBOARD: OnceCell<KeyboardDriver> = OnceCell::new();

pub struct KeyboardDriver {
    is_extended: bool,
    is_print_screen_press_sequence: bool,
    is_print_screen_release_sequence: bool,
    pause_break_sequence_step: Option<u8>,
}

impl KeyboardDriver {
    pub fn initialize(kernel: &mut Kernel) -> Result<(), ()> {
        if unsafe { KEYBOARD.get().is_some() } {
            return Err(());
        }

        let irq = kernel
            .irq_allocator
            .get_mut()
            .allocate_irq(IrqLevel::HumanInterfaceDevices);

        unsafe {
            IDT[irq].set_handler_fn(ps2_keyboard_interrupt_handler);
        }

        let redirection_entry = RedirectionEntry::new()
            .with_delivery_mode(DeliveryMode::Fixed)
            .with_destination(0) // BSP, @TODO: Maybe interrupts load balancing?
            .with_mask(false)
            .with_destination_mode(DestinationMode::Physical)
            .with_interrupt_vector(irq)
            .with_pin_polarity(PinPolarity::ActiveHigh)
            .with_trigger_mode(TriggerMode::Edge);

        // PS/2 keyboard has IRQ#1
        kernel.apic.read().redirect_interrupt(redirection_entry, 1);

        unsafe {
            _ = KEYBOARD.set(KeyboardDriver {
                is_extended: false,
                is_print_screen_press_sequence: false,
                is_print_screen_release_sequence: false,
                pause_break_sequence_step: None,
            });
        }

        Ok(())
    }

    fn on_receive(&mut self, code: u8) -> Result<Option<(KeyState, Key)>, KeyboardError> {
        // https://wiki.osdev.org/PS/2_Keyboard#Scan_Code_Set_1

        if code == 0xE0 {
            self.is_extended = true;

            return Ok(None);
        }

        if code == 0xE1 && self.pause_break_sequence_step.is_none() {
            self.pause_break_sequence_step = Some(0);

            return Ok(None);
        }

        if self.pause_break_sequence_step.is_some() {
            return self.handle_pause_break(code);
        }

        if self.is_extended {
            self.is_extended = false;

            match code {
                // Print screen press consists of 0xE0, 0x2A, 0xE0, 0x37
                0x2A => {
                    // This shouldn't normally happen, it can only happen with faulty hardware or buggy virtualization.
                    if self.is_print_screen_release_sequence {
                        return Err(KeyboardError::InvalidPrintScreenSequenceFollowUp);
                    }

                    self.is_print_screen_press_sequence = true;

                    Ok(None)
                }
                0x37 if self.is_print_screen_press_sequence => {
                    self.is_print_screen_press_sequence = false;

                    Ok(Some((KeyState::Pressed, Key::PrintScreen)))
                }
                // Print screen release consists of 0xE0, 0xB7, 0xE0, 0xAA
                0xB7 => {
                    // This shouldn't normally happen, it can only happen with faulty hardware or buggy virtualization.
                    if self.is_print_screen_press_sequence {
                        return Err(KeyboardError::InvalidPrintScreenSequenceFollowUp);
                    }

                    self.is_print_screen_release_sequence = true;

                    Ok(None)
                }
                0xAA if self.is_print_screen_release_sequence => {
                    self.is_print_screen_release_sequence = false;

                    Ok(Some((KeyState::Released, Key::PrintScreen)))
                }
                _ if (self.is_print_screen_press_sequence
                    | self.is_print_screen_release_sequence) =>
                {
                    self.is_print_screen_press_sequence = false;
                    self.is_print_screen_release_sequence = false;

                    Err(KeyboardError::InvalidPrintScreenSequenceFollowUp)
                }

                _ => self.handle_extended_key(code).map(Some),
            }
        } else {
            self.handle_non_extended_key(code).map(Some)
        }
    }

    fn handle_non_extended_key(&mut self, code: u8) -> Result<(KeyState, Key), KeyboardError> {
        match code {
            0x01 => Ok((KeyState::Pressed, Key::Escape)),
            0x02 => Ok((KeyState::Pressed, Key::Numeric1)),
            0x03 => Ok((KeyState::Pressed, Key::Numeric2)),
            0x04 => Ok((KeyState::Pressed, Key::Numeric3)),
            0x05 => Ok((KeyState::Pressed, Key::Numeric4)),
            0x06 => Ok((KeyState::Pressed, Key::Numeric5)),
            0x07 => Ok((KeyState::Pressed, Key::Numeric6)),
            0x08 => Ok((KeyState::Pressed, Key::Numeric7)),
            0x09 => Ok((KeyState::Pressed, Key::Numeric8)),
            0x0A => Ok((KeyState::Pressed, Key::Numeric9)),
            0x0B => Ok((KeyState::Pressed, Key::Numeric0)),
            0x0C => Ok((KeyState::Pressed, Key::Minus)),
            0x0D => Ok((KeyState::Pressed, Key::Equals)),
            0x0E => Ok((KeyState::Pressed, Key::Backspace)),
            0x0F => Ok((KeyState::Pressed, Key::Tab)),
            0x10 => Ok((KeyState::Pressed, Key::Q)),
            0x11 => Ok((KeyState::Pressed, Key::W)),
            0x12 => Ok((KeyState::Pressed, Key::E)),
            0x13 => Ok((KeyState::Pressed, Key::R)),
            0x14 => Ok((KeyState::Pressed, Key::T)),
            0x15 => Ok((KeyState::Pressed, Key::Y)),
            0x16 => Ok((KeyState::Pressed, Key::U)),
            0x17 => Ok((KeyState::Pressed, Key::I)),
            0x18 => Ok((KeyState::Pressed, Key::O)),
            0x19 => Ok((KeyState::Pressed, Key::P)),
            0x1A => Ok((KeyState::Pressed, Key::LeftSquareBracket)),
            0x1B => Ok((KeyState::Pressed, Key::RightSquareBracket)),
            0x1C => Ok((KeyState::Pressed, Key::Enter)),
            0x1D => Ok((KeyState::Pressed, Key::LeftControl)),
            0x1E => Ok((KeyState::Pressed, Key::A)),
            0x1F => Ok((KeyState::Pressed, Key::S)),
            0x20 => Ok((KeyState::Pressed, Key::D)),
            0x21 => Ok((KeyState::Pressed, Key::F)),
            0x22 => Ok((KeyState::Pressed, Key::G)),
            0x23 => Ok((KeyState::Pressed, Key::H)),
            0x24 => Ok((KeyState::Pressed, Key::J)),
            0x25 => Ok((KeyState::Pressed, Key::K)),
            0x26 => Ok((KeyState::Pressed, Key::L)),
            0x27 => Ok((KeyState::Pressed, Key::Semicolon)),
            0x28 => Ok((KeyState::Pressed, Key::SingleQuote)),
            0x29 => Ok((KeyState::Pressed, Key::BackTick)),
            0x2A => Ok((KeyState::Pressed, Key::LeftShift)),
            0x2B => Ok((KeyState::Pressed, Key::BackSlash)),
            0x2C => Ok((KeyState::Pressed, Key::Z)),
            0x2D => Ok((KeyState::Pressed, Key::X)),
            0x2E => Ok((KeyState::Pressed, Key::C)),
            0x2F => Ok((KeyState::Pressed, Key::V)),
            0x30 => Ok((KeyState::Pressed, Key::B)),
            0x31 => Ok((KeyState::Pressed, Key::N)),
            0x32 => Ok((KeyState::Pressed, Key::M)),
            0x33 => Ok((KeyState::Pressed, Key::Comma)),
            0x34 => Ok((KeyState::Pressed, Key::Dot)),
            0x35 => Ok((KeyState::Pressed, Key::Slash)),
            0x36 => Ok((KeyState::Pressed, Key::RightShift)),
            0x37 => Ok((KeyState::Pressed, Key::KeypadTimes)),
            0x38 => Ok((KeyState::Pressed, Key::LeftAlt)),
            0x39 => Ok((KeyState::Pressed, Key::Space)),
            0x3A => Ok((KeyState::Pressed, Key::CapsLock)),
            0x3B => Ok((KeyState::Pressed, Key::F1)),
            0x3C => Ok((KeyState::Pressed, Key::F2)),
            0x3D => Ok((KeyState::Pressed, Key::F3)),
            0x3E => Ok((KeyState::Pressed, Key::F4)),
            0x3F => Ok((KeyState::Pressed, Key::F5)),
            0x40 => Ok((KeyState::Pressed, Key::F6)),
            0x41 => Ok((KeyState::Pressed, Key::F7)),
            0x42 => Ok((KeyState::Pressed, Key::F8)),
            0x43 => Ok((KeyState::Pressed, Key::F9)),
            0x44 => Ok((KeyState::Pressed, Key::F10)),
            0x45 => Ok((KeyState::Pressed, Key::NumberLock)),
            0x46 => Ok((KeyState::Pressed, Key::ScrollLock)),
            0x47 => Ok((KeyState::Pressed, Key::Keypad7)),
            0x48 => Ok((KeyState::Pressed, Key::Keypad8)),
            0x49 => Ok((KeyState::Pressed, Key::Keypad9)),
            0x4A => Ok((KeyState::Pressed, Key::KeypadMinus)),
            0x4B => Ok((KeyState::Pressed, Key::Keypad4)),
            0x4C => Ok((KeyState::Pressed, Key::Keypad5)),
            0x4D => Ok((KeyState::Pressed, Key::Keypad6)),
            0x4E => Ok((KeyState::Pressed, Key::KeypadPlus)),
            0x4F => Ok((KeyState::Pressed, Key::Keypad1)),
            0x50 => Ok((KeyState::Pressed, Key::Keypad2)),
            0x51 => Ok((KeyState::Pressed, Key::Keypad3)),
            0x52 => Ok((KeyState::Pressed, Key::Keypad0)),
            0x53 => Ok((KeyState::Pressed, Key::KeypadDot)),
            0x57 => Ok((KeyState::Pressed, Key::F11)),
            0x58 => Ok((KeyState::Pressed, Key::F12)),

            0x81 => Ok((KeyState::Released, Key::Escape)),
            0x82 => Ok((KeyState::Released, Key::Numeric1)),
            0x83 => Ok((KeyState::Released, Key::Numeric2)),
            0x84 => Ok((KeyState::Released, Key::Numeric3)),
            0x85 => Ok((KeyState::Released, Key::Numeric4)),
            0x86 => Ok((KeyState::Released, Key::Numeric5)),
            0x87 => Ok((KeyState::Released, Key::Numeric6)),
            0x88 => Ok((KeyState::Released, Key::Numeric7)),
            0x89 => Ok((KeyState::Released, Key::Numeric8)),
            0x8A => Ok((KeyState::Released, Key::Numeric9)),
            0x8B => Ok((KeyState::Released, Key::Numeric0)),
            0x8C => Ok((KeyState::Released, Key::Minus)),
            0x8D => Ok((KeyState::Released, Key::Equals)),
            0x8E => Ok((KeyState::Released, Key::Backspace)),
            0x8F => Ok((KeyState::Released, Key::Tab)),
            0x90 => Ok((KeyState::Released, Key::Q)),
            0x91 => Ok((KeyState::Released, Key::W)),
            0x92 => Ok((KeyState::Released, Key::E)),
            0x93 => Ok((KeyState::Released, Key::R)),
            0x94 => Ok((KeyState::Released, Key::T)),
            0x95 => Ok((KeyState::Released, Key::Y)),
            0x96 => Ok((KeyState::Released, Key::U)),
            0x97 => Ok((KeyState::Released, Key::I)),
            0x98 => Ok((KeyState::Released, Key::O)),
            0x99 => Ok((KeyState::Released, Key::P)),
            0x9A => Ok((KeyState::Released, Key::LeftSquareBracket)),
            0x9B => Ok((KeyState::Released, Key::RightSquareBracket)),
            0x9C => Ok((KeyState::Released, Key::Enter)),
            0x9D => Ok((KeyState::Released, Key::LeftControl)),
            0x9E => Ok((KeyState::Released, Key::A)),
            0x9F => Ok((KeyState::Released, Key::S)),
            0xA0 => Ok((KeyState::Released, Key::D)),
            0xA1 => Ok((KeyState::Released, Key::F)),
            0xA2 => Ok((KeyState::Released, Key::G)),
            0xA3 => Ok((KeyState::Released, Key::H)),
            0xA4 => Ok((KeyState::Released, Key::J)),
            0xA5 => Ok((KeyState::Released, Key::K)),
            0xA6 => Ok((KeyState::Released, Key::L)),
            0xA7 => Ok((KeyState::Released, Key::Semicolon)),
            0xA8 => Ok((KeyState::Released, Key::SingleQuote)),
            0xA9 => Ok((KeyState::Released, Key::BackTick)),
            0xAA => Ok((KeyState::Released, Key::LeftShift)),
            0xAB => Ok((KeyState::Released, Key::BackSlash)),
            0xAC => Ok((KeyState::Released, Key::Z)),
            0xAD => Ok((KeyState::Released, Key::X)),
            0xAE => Ok((KeyState::Released, Key::C)),
            0xAF => Ok((KeyState::Released, Key::V)),
            0xB0 => Ok((KeyState::Released, Key::B)),
            0xB1 => Ok((KeyState::Released, Key::N)),
            0xB2 => Ok((KeyState::Released, Key::M)),
            0xB3 => Ok((KeyState::Released, Key::Comma)),
            0xB4 => Ok((KeyState::Released, Key::Dot)),
            0xB5 => Ok((KeyState::Released, Key::Slash)),
            0xB6 => Ok((KeyState::Released, Key::RightShift)),
            0xB7 => Ok((KeyState::Released, Key::KeypadTimes)),
            0xB8 => Ok((KeyState::Released, Key::LeftAlt)),
            0xB9 => Ok((KeyState::Released, Key::Space)),
            0xBA => Ok((KeyState::Released, Key::CapsLock)),
            0xBB => Ok((KeyState::Released, Key::F1)),
            0xBC => Ok((KeyState::Released, Key::F2)),
            0xBD => Ok((KeyState::Released, Key::F3)),
            0xBE => Ok((KeyState::Released, Key::F4)),
            0xBF => Ok((KeyState::Released, Key::F5)),
            0xC0 => Ok((KeyState::Released, Key::F6)),
            0xC1 => Ok((KeyState::Released, Key::F7)),
            0xC2 => Ok((KeyState::Released, Key::F8)),
            0xC3 => Ok((KeyState::Released, Key::F9)),
            0xC4 => Ok((KeyState::Released, Key::F10)),
            0xC5 => Ok((KeyState::Released, Key::NumberLock)),
            0xC6 => Ok((KeyState::Released, Key::ScrollLock)),
            0xC7 => Ok((KeyState::Released, Key::Keypad7)),
            0xC8 => Ok((KeyState::Released, Key::Keypad8)),
            0xC9 => Ok((KeyState::Released, Key::Keypad9)),
            0xCA => Ok((KeyState::Released, Key::KeypadMinus)),
            0xCB => Ok((KeyState::Released, Key::Keypad4)),
            0xCC => Ok((KeyState::Released, Key::Keypad5)),
            0xCD => Ok((KeyState::Released, Key::Keypad6)),
            0xCE => Ok((KeyState::Released, Key::KeypadPlus)),
            0xCF => Ok((KeyState::Released, Key::Keypad1)),
            0xD0 => Ok((KeyState::Released, Key::Keypad2)),
            0xD1 => Ok((KeyState::Released, Key::Keypad3)),
            0xD2 => Ok((KeyState::Released, Key::Keypad0)),
            0xD3 => Ok((KeyState::Released, Key::KeypadDot)),
            0xD7 => Ok((KeyState::Released, Key::F11)),
            0xD8 => Ok((KeyState::Released, Key::F12)),

            _ => Err(KeyboardError::UnknownCode),
        }
    }

    fn handle_extended_key(&mut self, code: u8) -> Result<(KeyState, Key), KeyboardError> {
        match code {
            0x10 => Ok((KeyState::Pressed, Key::MultimediaPreviousTrack)),
            0x19 => Ok((KeyState::Pressed, Key::MultimediaNextTrack)),
            0x1C => Ok((KeyState::Pressed, Key::KeypadEnter)),
            0x1D => Ok((KeyState::Pressed, Key::RightControl)),
            0x20 => Ok((KeyState::Pressed, Key::MultimediaMute)),
            0x21 => Ok((KeyState::Pressed, Key::MultimediaCalculator)),
            0x22 => Ok((KeyState::Pressed, Key::MultimediaPlay)),
            0x24 => Ok((KeyState::Pressed, Key::MultimediaStop)),
            0x2E => Ok((KeyState::Pressed, Key::MultimediaVolumeDown)),
            0x30 => Ok((KeyState::Pressed, Key::MultimediaVolumeUp)),
            0x32 => Ok((KeyState::Pressed, Key::MultimediaWwwHome)),
            0x35 => Ok((KeyState::Pressed, Key::KeypadSlash)),
            0x38 => Ok((KeyState::Pressed, Key::RightAlt)),
            0x47 => Ok((KeyState::Pressed, Key::Home)),
            0x48 => Ok((KeyState::Pressed, Key::UpArrow)),
            0x49 => Ok((KeyState::Pressed, Key::PageUp)),
            0x4B => Ok((KeyState::Pressed, Key::LeftArrow)),
            0x4D => Ok((KeyState::Pressed, Key::RightArrow)),
            0x4F => Ok((KeyState::Pressed, Key::End)),
            0x50 => Ok((KeyState::Pressed, Key::DownArrow)),
            0x51 => Ok((KeyState::Pressed, Key::PageDown)),
            0x52 => Ok((KeyState::Pressed, Key::Insert)),
            0x53 => Ok((KeyState::Pressed, Key::Delete)),
            0x5B => Ok((KeyState::Pressed, Key::LeftGui)),
            0x5C => Ok((KeyState::Pressed, Key::RightGui)),
            0x5D => Ok((KeyState::Pressed, Key::Apps)),
            0x5E | 0x5F | 0x63 => Err(KeyboardError::UnsupportedKey),
            0x65 => Ok((KeyState::Pressed, Key::MultimediaWwwSearch)),
            0x66 => Ok((KeyState::Pressed, Key::MultimediaWwwFavorites)),
            0x67 => Ok((KeyState::Pressed, Key::MultimediaWwwRefresh)),
            0x68 => Ok((KeyState::Pressed, Key::MultimediaWwwStop)),
            0x69 => Ok((KeyState::Pressed, Key::MultimediaWwwForward)),
            0x6A => Ok((KeyState::Pressed, Key::MultimediaWwwBack)),
            0x6B => Ok((KeyState::Pressed, Key::MultimediaMyComputer)),
            0x6C => Ok((KeyState::Pressed, Key::MultimediaEmail)),
            0x6D => Ok((KeyState::Pressed, Key::MultimediaMediaSelect)),

            0x90 => Ok((KeyState::Released, Key::MultimediaPreviousTrack)),
            0x99 => Ok((KeyState::Released, Key::MultimediaNextTrack)),
            0x9C => Ok((KeyState::Released, Key::KeypadEnter)),
            0x9D => Ok((KeyState::Released, Key::RightControl)),
            0xA0 => Ok((KeyState::Released, Key::MultimediaMute)),
            0xA1 => Ok((KeyState::Released, Key::MultimediaCalculator)),
            0xA2 => Ok((KeyState::Released, Key::MultimediaPlay)),
            0xA4 => Ok((KeyState::Released, Key::MultimediaStop)),
            0xAE => Ok((KeyState::Released, Key::MultimediaVolumeDown)),
            0xB0 => Ok((KeyState::Released, Key::MultimediaVolumeUp)),
            0xB2 => Ok((KeyState::Released, Key::MultimediaWwwHome)),
            0xB5 => Ok((KeyState::Released, Key::KeypadSlash)),
            0xB8 => Ok((KeyState::Released, Key::RightAlt)),
            0xC7 => Ok((KeyState::Released, Key::Home)),
            0xC8 => Ok((KeyState::Released, Key::UpArrow)),
            0xC9 => Ok((KeyState::Released, Key::PageUp)),
            0xCB => Ok((KeyState::Released, Key::LeftArrow)),
            0xCD => Ok((KeyState::Released, Key::RightArrow)),
            0xCF => Ok((KeyState::Released, Key::End)),
            0xD0 => Ok((KeyState::Released, Key::DownArrow)),
            0xD1 => Ok((KeyState::Released, Key::PageDown)),
            0xD2 => Ok((KeyState::Released, Key::Insert)),
            0xD3 => Ok((KeyState::Released, Key::Delete)),
            0xDB => Ok((KeyState::Released, Key::LeftGui)),
            0xDC => Ok((KeyState::Released, Key::RightGui)),
            0xDD => Ok((KeyState::Released, Key::Apps)),
            0xDE | 0xDF | 0xE3 => Err(KeyboardError::UnsupportedKey),
            0xE5 => Ok((KeyState::Released, Key::MultimediaWwwSearch)),
            0xE6 => Ok((KeyState::Released, Key::MultimediaWwwFavorites)),
            0xE7 => Ok((KeyState::Released, Key::MultimediaWwwRefresh)),
            0xE8 => Ok((KeyState::Released, Key::MultimediaWwwStop)),
            0xE9 => Ok((KeyState::Released, Key::MultimediaWwwForward)),
            0xEA => Ok((KeyState::Released, Key::MultimediaWwwBack)),
            0xEB => Ok((KeyState::Released, Key::MultimediaMyComputer)),
            0xEC => Ok((KeyState::Released, Key::MultimediaEmail)),
            0xED => Ok((KeyState::Released, Key::MultimediaMediaSelect)),

            _ => Err(KeyboardError::UnknownCode),
        }
    }

    fn handle_pause_break(&mut self, code: u8) -> Result<Option<(KeyState, Key)>, KeyboardError> {
        let pause_break_sequence_step = self.pause_break_sequence_step.as_mut().unwrap();

        // Pause break consists of 0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5
        //
        // After we encounter 0xE1, we set self.pause_break_sequence_step to Some(0),
        // each step increases the counter by one, so it's 1 after 0x1D, 2 after 0x45, etc,
        // until we receive the entire sequence. Then we can reset the state to None and return.
        match pause_break_sequence_step {
            0 if code == 0x1D => {
                *pause_break_sequence_step += 1;

                Ok(None)
            }
            1 if code == 0x45 => {
                *pause_break_sequence_step += 1;

                Ok(None)
            }
            2 if code == 0xE1 => {
                *pause_break_sequence_step += 1;

                Ok(None)
            }
            3 if code == 0x9D => {
                *pause_break_sequence_step += 1;

                Ok(None)
            }
            4 if code == 0xC5 => {
                self.pause_break_sequence_step = None;

                Ok(Some((KeyState::Pressed, Key::PauseBreak)))
            }
            _ => {
                self.pause_break_sequence_step = None;

                Err(KeyboardError::InvalidPauseBreakSequenceFollowUp)
            }
        }
    }
}

extern "x86-interrupt" fn ps2_keyboard_interrupt_handler(
    _interrupt_stack_frame: InterruptStackFrame,
) {
    let status = inb(0x64);

    let can_read = status & 0x1 == 1;
    let time_out_error = (status >> 6) & 0x1 == 1;
    let parity_error = (status >> 7) & 0x1 == 1;
    let any_error = time_out_error | parity_error;

    if any_error {
        if time_out_error {
            error!("[Keyboard] Time-out error");
        }

        if parity_error {
            error!("[Keyboard] Parity error");
        }
    } else if can_read {
        let code = inb(0x60);

        let keyboard = unsafe { KEYBOARD.get_mut().unwrap() };

        match keyboard.on_receive(code) {
            Ok(result) => {
                if let Some((state, key)) = result {
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
            Err(error) => match error {
                KeyboardError::UnsupportedKey => error!("[Keyboard] Unsupported key"),
                KeyboardError::UnknownCode => error!("[Keyboard] Unknown code"),
                KeyboardError::InvalidPrintScreenSequenceFollowUp => {
                    error!("[Keyboard] Invalid print screen sequence follow up")
                }
                KeyboardError::InvalidPauseBreakSequenceFollowUp => {
                    error!("[Keyboard] Invalid pause break sequence follow up")
                }
            },
        }
    }

    unsafe {
        (*ProcessorControlBlock::get_pcb_for_current_processor())
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

enum KeyboardError {
    UnsupportedKey,
    UnknownCode,
    InvalidPrintScreenSequenceFollowUp,
    InvalidPauseBreakSequenceFollowUp,
}

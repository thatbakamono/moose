use alloc::{boxed::Box, sync::Arc};
use log::debug;
use raw_cpuid::{CpuId, Hypervisor};
use spin::{Mutex, RwLock};
use x86_64::{instructions::interrupts::without_interrupts, structures::idt::InterruptStackFrame};

use crate::{
    arch::{
        irq::IrqLevel,
        x86::{
            asm::{inb, inw, outb, outl, outw},
            idt::register_interrupt_handler,
        },
    },
    cpu::ProcessorControlBlock,
    driver::{
        apic::{DeliveryMode, DestinationMode, PinPolarity, RedirectionEntry, TriggerMode},
        pci::PciDevice,
    },
    kernel::Kernel,
    memory::{memory_manager, Page, PageFlags, VirtualAddress},
};

const RST_BIT: u8 = 0x10;
const RBSTART_REGISTER: u16 = 0x30;
const COMMAND_REGISTER: u16 = 0x37;
const CAPR: u16 = 0x38;
const INTERRUPT_MASK_REGISTER: u16 = 0x3C;
const INTERRUPT_STATUS_REGISTER: u16 = 0x3E;
const RECEIVE_CONFIGURATION_REGISTER: u16 = 0x44;
const CONFIG_1_REGISTER: u16 = 0x52;
const RX_BUFFER_SIZE: usize = (1 << 13) + 1500 + 4 + 4;

#[repr(C, align(4096))]
struct RxBuffer([u8; RX_BUFFER_SIZE]);

#[repr(C, align(4096))]
struct TxBuffer([u8; 1518]);

pub struct Rtl8139 {
    inner: Arc<Mutex<Rtl8139Inner>>,
}

impl Rtl8139 {
    pub fn new(pci_device: Arc<Mutex<PciDevice>>, kernel: Arc<RwLock<Kernel>>) -> Rtl8139 {
        let mut memory_manager = memory_manager().write();

        // We use 8kb ring buffer for RX buffer, but we're also utilizing WRAP feature of the network card
        // so need to make some space for overlapping data
        //
        // 8kb + 1518 bytes (worst case scenario) occupies 3 physical pages.
        // We allocate them manually as we need to explicilty have 3 **physically contiguous** pages.
        let frame1 = memory_manager.allocate_frame().unwrap();
        let frame2 = memory_manager.allocate_frame().unwrap();
        let frame3 = memory_manager.allocate_frame().unwrap();

        unsafe {
            memory_manager
                .map_identity(
                    &Page::new(VirtualAddress::new(frame1.address().as_u64())),
                    PageFlags::WRITABLE,
                )
                .unwrap();
            memory_manager
                .map_identity(
                    &Page::new(VirtualAddress::new(frame2.address().as_u64())),
                    PageFlags::WRITABLE,
                )
                .unwrap();
            memory_manager
                .map_identity(
                    &Page::new(VirtualAddress::new(frame3.address().as_u64())),
                    PageFlags::WRITABLE,
                )
                .unwrap();
        };

        // Safety check that device reports I/O address in first BAR.
        let bar0 = pci_device.lock().get_bar(0);
        assert_eq!(bar0 & 1, 1);

        Self {
            inner: Arc::new(Mutex::new(Rtl8139Inner {
                pci_device,
                io_base: (bar0 & !0x3) as u16,
                rx_buffer: frame1.address().as_u64() as *mut u8,
                current_rx_offset: 0,
                kernel,
                current_tx_index: 0,
            })),
        }
    }

    pub fn initialize(&mut self) {
        assert_eq!(CpuId::new().get_hypervisor_info().unwrap().identify(), Hypervisor::QEMU, "RTL8139 interrupts are only supported on QEMU currently, due to very unpleasant way of handling interrupts without MSI/MSI-X on PCI devices.");

        without_interrupts(|| {
            let rtl8139 = self.inner.lock();

            {
                let pci_device = rtl8139.pci_device.lock();

                // Enable DMA (Bus Master)
                pci_device.enable_dma();

                // Get interrupt line from the PCI configuration space
                //
                // This is weird actually, because it should be totally random when using APIC + IRQ sharing, but in QEMU
                // for some reason it works.
                let interrupt_line = pci_device.get_interrupt_line();
                let irq = rtl8139
                    .kernel
                    .read()
                    .irq_allocator
                    .lock()
                    .allocate_irq(IrqLevel::NetworkInterfaceCard);

                debug!(
                    "[RTL8139] Using IRQ#{} with interrupt line {}",
                    irq, interrupt_line
                );

                let inner = Arc::clone(&self.inner);

                register_interrupt_handler(
                    irq,
                    Box::new(move |_isf: &InterruptStackFrame| {
                        handle_rtl8139_interrupt(&mut inner.lock());
                    }),
                );

                let redirection_entry = RedirectionEntry::new()
                    .with_delivery_mode(DeliveryMode::Fixed)
                    .with_destination(0)
                    .with_mask(false)
                    .with_destination_mode(DestinationMode::Physical)
                    .with_interrupt_vector(irq)
                    .with_pin_polarity(PinPolarity::ActiveHigh)
                    .with_trigger_mode(TriggerMode::Edge);

                rtl8139
                    .kernel
                    .read()
                    .apic
                    .read()
                    .redirect_interrupt(redirection_entry, interrupt_line);
            }

            // Set the LWAKE and LWPTN to active high. This should power on the device.
            outb(rtl8139.io_base + CONFIG_1_REGISTER, 0x00);

            // Perform software reset to make sure there's no garbage in buffers or registers.
            outb(rtl8139.io_base + COMMAND_REGISTER, RST_BIT);

            // Wait until the device reports success.
            loop {
                if (inb(rtl8139.io_base + COMMAND_REGISTER) & RST_BIT) == 0 {
                    break;
                }
            }

            // Initialize receive buffer (RX)
            let rx_buffer_physical_address = memory_manager()
                .read()
                .translate_virtual_address_to_physical(VirtualAddress::new(
                    rtl8139.rx_buffer as u64,
                ))
                .unwrap()
                .as_u64();

            outl(
                rtl8139.io_base + RBSTART_REGISTER,
                rx_buffer_physical_address as u32,
            );

            // Initialize interrupts
            //
            // We're setting Tx OK Interrupt (bit 2) and Rx OK Interrupt (bit 0)
            // For more settings see Realtek RTL8139 DataSheet table at page 18
            outw(
                rtl8139.io_base + INTERRUPT_MASK_REGISTER,
                (1 << 2) | 1 | (1 << 4),
            );

            // Initialize receiver options
            outl(
                rtl8139.io_base + RECEIVE_CONFIGURATION_REGISTER,
                (1 << 7) | // WRAP bit
                (1 << 3) | // Accept Broadcast Packets
                (1 << 2) | // Accept Multicast Packets
                (1 << 1) | // Accept Physical Match Packets
                1, // Accept All Packets
            );

            // Finally, enable receiver and transmitter
            //                                                RE      |  TE
            outb(rtl8139.io_base + COMMAND_REGISTER, (1 << 3) | (1 << 2));
        });
    }

    pub fn send_packet(&mut self, data: &[u8]) {
        // Safety checks
        assert!(data.len() < 1518);
        assert!(data.len() > 0);

        let (transmit_buffer, transmit_status) = self.get_current_transmit_registers();
        let io_base = self.inner.lock().io_base;

        // Create buffer and copy user delivered data to it.
        //
        // It's needed mostly because we need to be aligned at the page boundary, 
        // the data can't be on two, not physically contiguous, page frames.
        let mut tx_buffer = Box::new(TxBuffer([0u8; 1518]));
        tx_buffer.as_mut().0[0..data.len()].copy_from_slice(data);

        // Get physical address of the buffer
        let tx_buffer_virtual_address = &mut *tx_buffer as *mut TxBuffer;
        let tx_buffer_phys_address = memory_manager()
            .read()
            .translate_virtual_address_to_physical(VirtualAddress::new(
                tx_buffer_virtual_address.addr() as u64,
            ))
            .unwrap()
            .as_u64();

        // Safety check it fits in 32 bits
        assert!(tx_buffer_phys_address < (1 << 32));

        outl(io_base + transmit_buffer, tx_buffer_phys_address as u32);
        outl(io_base + transmit_status, data.len() as u32);

        self.adjust_transmit_registers();
    }

    fn get_current_transmit_registers(&self) -> (u16, u16) {
        match self.inner.lock().current_tx_index {
            0 => (0x20, 0x10),
            1 => (0x24, 0x14),
            2 => (0x28, 0x18),
            3 => (0x2C, 0x1C),
            _ => unreachable!(),
        }
    }

    fn adjust_transmit_registers(&mut self) {
        // RTL8139 has 4 transmit registers for sending data, and they are used with round-robin style.
        let mut inner = self.inner.lock();

        inner.current_tx_index += 1;

        if inner.current_tx_index >= 4 {
            inner.current_tx_index = 0;
        }
    }
}

struct Rtl8139Inner {
    pci_device: Arc<Mutex<PciDevice>>,
    io_base: u16,
    rx_buffer: *mut u8,
    current_rx_offset: usize,
    current_tx_index: usize,
    kernel: Arc<RwLock<Kernel>>,
}

impl Rtl8139Inner {
    fn handle_received_packet(&mut self) {
        // Received data from the wire are preceded by two u16's:
        //   - data status
        //   - data length

        let data_start = unsafe { self.rx_buffer.offset(self.current_rx_offset as isize) };
        let status = unsafe { (data_start.add(0) as *const u16).read_volatile() };
        let length = unsafe { (data_start.add(2) as *const u16).read_volatile() };

        debug!(
            "Received data with length {}, status={}, offset={}",
            length, status, self.current_rx_offset
        );

        // 4 is the data status and data length
        // 1518 is maximum Ethernet frame length
        // 4 is CRC32 checksum appended at the end of the data
        let mut buffer = [0u8; 4 + 1518 + 4 + 1];

        for i in 0..length {
            unsafe {
                buffer[i as usize] = *(data_start.offset(i.try_into().unwrap()) as *const u8)
            };
        }

        // @TODO: Pass buffer to the higher layers

        self.current_rx_offset = (self.current_rx_offset + length as usize + 4 + 3) & !3;

        // It's ring buffer, so if we overflow, just go back to the start.
        if self.current_rx_offset > 8192 {
            self.current_rx_offset -= 8192;
        }

        // Notify network card about new RX buffer reading offset
        outw(
            self.io_base + CAPR,
            (self.current_rx_offset as u16).overflowing_sub(0x10).0,
        );
    }
}

fn handle_rtl8139_interrupt(nic: &mut Rtl8139Inner) {
    let status = inw(nic.io_base + INTERRUPT_STATUS_REGISTER);

    // Can't use smarter way, because flags are not exclusive
    if (status & (1 << 2)) != 0 {
        debug!("Packet sent");
    }

    if (status & (1 << 0)) != 0 {
        // Packet received
        nic.handle_received_packet();
    }

    if (status & (1 << 1)) != 0 {
        panic!("Rcv err!");
    }

    if (status & (1 << 4)) != 0 {
        panic!("RX buffer overflow")
    }

    // Acknowledge interrupt
    // This also allows RTL8139 to overwrite our data, so from this moment we can't rely on rx buffer
    outw(nic.io_base + INTERRUPT_STATUS_REGISTER, status);

    unsafe {
        _ = &(*ProcessorControlBlock::get_pcb_for_current_processor())
            .local_apic
            .get()
            .unwrap()
            .signal_end_of_interrupt();
    }
}

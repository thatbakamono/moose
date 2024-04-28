use crate::arch::x86::asm::{inl, outb, outl};
use alloc::format;
use alloc::string::{String, ToString};
use log::{debug, info};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;

pub struct Pci {}

impl Pci {
    pub fn build_device_tree() {
        Pci::perform_brute_force_scan()
    }

    fn perform_brute_force_scan() {
        for bus in 0..256 {
            for device in 0..32 {
                // @TODO: Make tree-like structure of detected
                // devices in system (not only on PCI bus ofc, maybe use some AML and ACPI tables?)
                Pci::scan_device(bus, device);
            }
        }
    }

    fn scan_device(bus: u32, device: u32) -> Option<PciDevice> {
        let vendor_id = Pci::read(bus, device, 0, 0);
        if vendor_id == 0xFFFF {
            return None;
        }

        let device_id = Pci::read(bus, device, 0, 2);
        let class_code = Pci::read(bus, device, 0, 10) >> 8;
        let subclass_code = Pci::read(bus, device, 0, 10) & 0xF;
        let device = PciDevice {
            bus,
            device,
            // We don't support multi-function devices currently
            function: 0,
            vendor_id,
            device_id,
            class: PciDeviceClass::parse(class_code as u32, subclass_code as u32),
        };

        debug!(
            "[PCI] Found new device: {:#x?}:{:#x?} (class: {:?}, vendor: {}, device: {})",
            vendor_id,
            device_id,
            device.class,
            get_device_manufacturer_string(&device),
            get_device_name(&device)
        );

        Some(device)
    }

    fn read(bus: u32, device: u32, function: u32, offset: u32) -> u16 {
        let address: u32 =
            (bus << 16) | (device << 11) | (function << 8) | (offset & 0xFC) | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        return ((inl(CONFIG_DATA) >> ((offset & 2) * 8)) & 0xFFFF) as u16;
    }
}

pub struct PciDevice {
    bus: u32,
    device: u32,
    function: u32,

    pub vendor_id: u16,
    pub device_id: u16,
    pub class: PciDeviceClass,
}

impl PciDevice {
    pub fn get_bar(&self, bar: u8) -> u32 {
        // Don't need to check if bar is bigger or equal 0 because of used type (unsigned byte)
        assert!(
            bar < 6,
            "There are only 6 BARs on PCI devices numbered from 0 to 5"
        );

        let bar_offset = 0x10 + (bar * 4) as u32;

        let lower_word = self.read(bar_offset) as u32;
        let higher_word = self.read(bar_offset + 2) as u32;

        return (higher_word << 16) | lower_word;
    }

    pub fn get_interrupt_pin(&self) -> u8 {
        (self.read(0x3C) >> 8) as u8
    }

    pub fn get_interrupt_line(&self) -> u8 {
        (self.read(0x3C) & 0xFF) as u8
    }

    fn read(&self, offset: u32) -> u16 {
        let address: u32 = (self.bus << 16)
            | (self.device << 11)
            | (self.function << 8)
            | (offset & 0xFC)
            | 0x80000000;
        outl(CONFIG_ADDRESS, address);

        return ((inl(CONFIG_DATA) >> ((offset & 2) * 8)) & 0xFFFF) as u16;
    }
}

// Feel free to add more manufacturer names
fn get_device_manufacturer_string(device: &PciDevice) -> String {
    match device.vendor_id {
        0x1234 => "QEMU emulated device".to_string(),
        0x8086 => "Intel Corp.".to_string(),
        vendor => format!("Unknown ({:#x?})", vendor),
    }
}

fn get_device_name(device: &PciDevice) -> String {
    match (device.vendor_id, device.device_id) {
        (0x1234, 0x1111) => "VGA compatible graphic card".to_string(),
        (0x8086, 0x100e) => "82540EM Gigabit Ethernet Controller".to_string(),
        (0x8086, 0x1237) => "440FX - 82441FX PMC [Natoma]".to_string(),
        (0x8086, 0x7000) => "82371SB PIIX3 ISA [Natoma/Triton II]".to_string(),
        (vendor, device) => format!("Unknown ({:#x?}:{:#x?})", vendor, device),
    }
}

#[derive(Debug)]
pub enum PciDeviceClass {
    Undefined(PciDeviceClassUndefinedSubclass),
    MassStorageController(PciDeviceClassMassStorageControllerSubclass),
    NetworkController(PciDeviceClassNetworkControllerSubclass),
    DisplayController(PciDeviceClassDisplayControllerSubclass),
    MultimediaDevice(PciDeviceClassMultimediaControllerSubclass),
    MemoryController(PciDeviceClassMemoryControllerSubclass),
    Bridge(PciDeviceClassBridgeSubclass),
    SimpleCommunicationController(PciDeviceClassSimpleCommunicationControllerSubclass),
    BaseSystemPeripheral(PciDeviceClassBaseSystemPeripheralSubclass),
    InputDevice(PciDeviceClassInputDeviceControllerSubclass),
    DockingStation(PciDeviceClassDockingStationSubclass),
    Processor(PciDeviceClassProcessorSubclass),
    SerialBusController(PciDeviceClassSerialBusControllerSubclass),
    WirelessController(PciDeviceClassWirelessControllerSubclass),
    IntelligentIoController(PciDeviceClassIntelligentControllerSubclass),
    SatelliteCommunicationController(PciDeviceClassSatelliteCommunicationControllerSubclass),
    EncryptionOrDecryptionController(PciDeviceClassEncryptionControllerSubclass),
    DataAcquisitionAndSignalProcessingController(PciDeviceClassSignalProcessingControllerSubclass),
    ProcessingAccelerator,
    NonEssentialInstrumentation,
    // Reserved
    Unknown,
}

impl PciDeviceClass {
    pub fn parse(class_id: u32, subclass_id: u32) -> PciDeviceClass {
        match class_id {
            0x0 => PciDeviceClass::Undefined(match subclass_id {
                0x0 => PciDeviceClassUndefinedSubclass::NonVgaCompatibleUnclassifiedDevice,
                0x1 => PciDeviceClassUndefinedSubclass::VgaCompatibleUnclassifiedDevice,
                _ => unreachable!(),
            }),
            0x1 => PciDeviceClass::MassStorageController(match subclass_id {
                0x0 => PciDeviceClassMassStorageControllerSubclass::ScsiBusController,
                0x1 => PciDeviceClassMassStorageControllerSubclass::IdeController,
                0x2 => PciDeviceClassMassStorageControllerSubclass::FloppyDiskController,
                0x3 => PciDeviceClassMassStorageControllerSubclass::IpiBusController,
                0x4 => PciDeviceClassMassStorageControllerSubclass::RaidController,
                0x5 => PciDeviceClassMassStorageControllerSubclass::AtaController,
                0x6 => PciDeviceClassMassStorageControllerSubclass::SataController,
                0x7 => PciDeviceClassMassStorageControllerSubclass::SerialAttachedScsiController,
                0x8 => PciDeviceClassMassStorageControllerSubclass::NonVolatileMemoryController,
                _ => unreachable!(),
            }),
            0x2 => PciDeviceClass::NetworkController(match subclass_id {
                0x0 => PciDeviceClassNetworkControllerSubclass::EthernetController,
                0x1 => PciDeviceClassNetworkControllerSubclass::TokenRingController,
                0x2 => PciDeviceClassNetworkControllerSubclass::FddiController,
                0x3 => PciDeviceClassNetworkControllerSubclass::AtmController,
                0x4 => PciDeviceClassNetworkControllerSubclass::IsdnController,
                0x5 => PciDeviceClassNetworkControllerSubclass::WorldFipController,
                0x6 => PciDeviceClassNetworkControllerSubclass::PicmgMultimComputingController,
                0x7 => PciDeviceClassNetworkControllerSubclass::InfinibandController,
                0x8 => PciDeviceClassNetworkControllerSubclass::FabricController,
                _ => unreachable!(),
            }),
            0x3 => PciDeviceClass::DisplayController(match subclass_id {
                0x0 => PciDeviceClassDisplayControllerSubclass::VgaCompatibleController,
                0x1 => PciDeviceClassDisplayControllerSubclass::XgaController,
                0x2 => PciDeviceClassDisplayControllerSubclass::NotVgaCompatible3dController,
                _ => unreachable!(),
            }),
            0x4 => PciDeviceClass::MultimediaDevice(match subclass_id {
                0x0 => PciDeviceClassMultimediaControllerSubclass::MultimediaVideoController,
                0x1 => PciDeviceClassMultimediaControllerSubclass::MultimediaAudioController,
                0x2 => PciDeviceClassMultimediaControllerSubclass::ComputerTelephonyDevice,
                0x3 => PciDeviceClassMultimediaControllerSubclass::AudioDevice,
                _ => unreachable!(),
            }),
            0x5 => PciDeviceClass::MemoryController(match subclass_id {
                0x0 => PciDeviceClassMemoryControllerSubclass::RamController,
                0x1 => PciDeviceClassMemoryControllerSubclass::FlashController,
                _ => unreachable!(),
            }),
            0x6 => PciDeviceClass::Bridge(match subclass_id {
                0x0 => PciDeviceClassBridgeSubclass::HostBridge,
                0x1 => PciDeviceClassBridgeSubclass::IsaBridge,
                0x2 => PciDeviceClassBridgeSubclass::EisaBridge,
                0x3 => PciDeviceClassBridgeSubclass::McaBridge,
                0x4 => PciDeviceClassBridgeSubclass::PciToPciBridge,
                0x5 => PciDeviceClassBridgeSubclass::PcmciaBridge,
                0x6 => PciDeviceClassBridgeSubclass::NuBusBridge,
                0x7 => PciDeviceClassBridgeSubclass::CardBusBridge,
                0x8 => PciDeviceClassBridgeSubclass::RaceWayBridge,
                0x9 => PciDeviceClassBridgeSubclass::PciToPciBridge2,
                0xA => PciDeviceClassBridgeSubclass::InfiniBandToPciHostBridge,
                _ => unreachable!(),
            }),
            0x7 => PciDeviceClass::SimpleCommunicationController(match subclass_id {
                0x0 => PciDeviceClassSimpleCommunicationControllerSubclass::SerialController,
                0x1 => PciDeviceClassSimpleCommunicationControllerSubclass::ParallelController,
                0x2 => PciDeviceClassSimpleCommunicationControllerSubclass::MultiportSerialController,
                0x3 => PciDeviceClassSimpleCommunicationControllerSubclass::Modem,
                0x4 => PciDeviceClassSimpleCommunicationControllerSubclass::GpibController,
                0x5 => PciDeviceClassSimpleCommunicationControllerSubclass::SmartCardController,
                _ => unreachable!(),
            }),
            0x8 => PciDeviceClass::BaseSystemPeripheral(match subclass_id {
                0x0 => PciDeviceClassBaseSystemPeripheralSubclass::Pic,
                0x1 => PciDeviceClassBaseSystemPeripheralSubclass::DmaController,
                0x2 => PciDeviceClassBaseSystemPeripheralSubclass::Timer,
                0x3 => PciDeviceClassBaseSystemPeripheralSubclass::RtcController,
                0x4 => PciDeviceClassBaseSystemPeripheralSubclass::PciHotPlugController,
                0x5 => PciDeviceClassBaseSystemPeripheralSubclass::SdHostController,
                0x6 => PciDeviceClassBaseSystemPeripheralSubclass::IoMmu,
                _ => unreachable!(),
            }),
            0x9 => PciDeviceClass::InputDevice(match subclass_id {
                0x0 => PciDeviceClassInputDeviceControllerSubclass::KeyboardController,
                0x1 => PciDeviceClassInputDeviceControllerSubclass::DigitizerPen,
                0x2 => PciDeviceClassInputDeviceControllerSubclass::MouseController,
                0x3 => PciDeviceClassInputDeviceControllerSubclass::ScannerController,
                0x4 => PciDeviceClassInputDeviceControllerSubclass::GameportController,
                _ => unreachable!(),
            }),
            0xA => PciDeviceClass::DockingStation(match subclass_id {
                0x0 => PciDeviceClassDockingStationSubclass::Generic,
                _ => unreachable!(),
            }),
            0xB => PciDeviceClass::Processor(match subclass_id {
                0x0 => PciDeviceClassProcessorSubclass::x386,
                0x1 => PciDeviceClassProcessorSubclass::x486,
                0x2 => PciDeviceClassProcessorSubclass::Pentium,
                0x3 => PciDeviceClassProcessorSubclass::PentiumPro,
                0x10 => PciDeviceClassProcessorSubclass::Alpha,
                0x20 => PciDeviceClassProcessorSubclass::PowerPc,
                0x30 => PciDeviceClassProcessorSubclass::Mips,
                0x40 => PciDeviceClassProcessorSubclass::CoProcessor,
                _ => unreachable!(),
            }),
            0xC => PciDeviceClass::SerialBusController(match subclass_id {
                0x0 => PciDeviceClassSerialBusControllerSubclass::FireWireController,
                0x1 => PciDeviceClassSerialBusControllerSubclass::AccessBusController,
                0x2 => PciDeviceClassSerialBusControllerSubclass::Ssa,
                0x3 => PciDeviceClassSerialBusControllerSubclass::UsbController,
                0x4 => PciDeviceClassSerialBusControllerSubclass::FibreChannel,
                0x5 => PciDeviceClassSerialBusControllerSubclass::SmbusController,
                0x6 => PciDeviceClassSerialBusControllerSubclass::InfiniBandController,
                0x7 => PciDeviceClassSerialBusControllerSubclass::IpmiInterface,
                0x8 => PciDeviceClassSerialBusControllerSubclass::SercosInterface,
                0x9 => PciDeviceClassSerialBusControllerSubclass::CanbusController,
                _ => unreachable!(),
            }),
            0xD => PciDeviceClass::WirelessController(match subclass_id {
                0x0 => PciDeviceClassWirelessControllerSubclass::IrdaCompatibleController,
                0x1 => PciDeviceClassWirelessControllerSubclass::ConsumerIrController,
                0x10 => PciDeviceClassWirelessControllerSubclass::RfController,
                0x11 => PciDeviceClassWirelessControllerSubclass::BluetoothController,
                0x12 => PciDeviceClassWirelessControllerSubclass::BroadbandController,
                0x20 => PciDeviceClassWirelessControllerSubclass::EthernetControllerA,
                0x21 => PciDeviceClassWirelessControllerSubclass::EthernetControllerB,
                _ => unreachable!(),
            }),
            0xE => PciDeviceClass::IntelligentIoController(match subclass_id {
                0x0 => PciDeviceClassIntelligentControllerSubclass::I20,
                _ => unreachable!(),
            }),
            0xF => PciDeviceClass::SatelliteCommunicationController(match subclass_id {
                0x1 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteTvController,
                0x2 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteAudioController,
                0x3 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteVoiceController,
                0x4 => PciDeviceClassSatelliteCommunicationControllerSubclass::SatelliteDataController,
                _ => unreachable!(),
            }),
            0x10 => PciDeviceClass::EncryptionOrDecryptionController(match subclass_id {
                0x0 => PciDeviceClassEncryptionControllerSubclass::NetworkAndComputingEncryptionOrDecryption,
                0x10 => PciDeviceClassEncryptionControllerSubclass::EntertainmentEncryptionOrDecryption,
                _ => unreachable!(),
            }),
            0x11 => PciDeviceClass::DataAcquisitionAndSignalProcessingController(match subclass_id {
                0x0 => PciDeviceClassSignalProcessingControllerSubclass::DpioModules,
                0x1 => PciDeviceClassSignalProcessingControllerSubclass::PerformanceCounters,
                0x10 => PciDeviceClassSignalProcessingControllerSubclass::CommunicationSynchronizer,
                0x20 => PciDeviceClassSignalProcessingControllerSubclass::SignalProcessingManagement,
                _ => unreachable!(),
            }),
            0x12 => PciDeviceClass::ProcessingAccelerator,
            0x13 => PciDeviceClass::NonEssentialInstrumentation,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug)]
enum PciDeviceClassUndefinedSubclass {
    NonVgaCompatibleUnclassifiedDevice,
    VgaCompatibleUnclassifiedDevice,
}

#[derive(Debug)]
enum PciDeviceClassMassStorageControllerSubclass {
    ScsiBusController,
    IdeController,
    FloppyDiskController,
    IpiBusController,
    RaidController,
    AtaController,
    SataController,
    SerialAttachedScsiController,
    NonVolatileMemoryController,
}

#[derive(Debug)]
enum PciDeviceClassNetworkControllerSubclass {
    EthernetController,
    TokenRingController,
    FddiController,
    AtmController,
    IsdnController,
    WorldFipController,
    PicmgMultimComputingController,
    InfinibandController,
    FabricController,
}

#[derive(Debug)]
enum PciDeviceClassDisplayControllerSubclass {
    VgaCompatibleController,
    XgaController,
    NotVgaCompatible3dController,
}

#[derive(Debug)]
enum PciDeviceClassMultimediaControllerSubclass {
    MultimediaVideoController,
    MultimediaAudioController,
    ComputerTelephonyDevice,
    AudioDevice,
}

#[derive(Debug)]
enum PciDeviceClassMemoryControllerSubclass {
    RamController,
    FlashController,
}

#[derive(Debug)]
enum PciDeviceClassBridgeSubclass {
    HostBridge,
    IsaBridge,
    EisaBridge,
    McaBridge,
    PciToPciBridge,
    PcmciaBridge,
    NuBusBridge,
    CardBusBridge,
    RaceWayBridge,
    PciToPciBridge2,
    InfiniBandToPciHostBridge,
}

#[derive(Debug)]
enum PciDeviceClassSimpleCommunicationControllerSubclass {
    SerialController,
    ParallelController,
    MultiportSerialController,
    Modem,
    GpibController,
    SmartCardController,
}

#[derive(Debug)]
enum PciDeviceClassBaseSystemPeripheralSubclass {
    Pic,
    DmaController,
    Timer,
    RtcController,
    PciHotPlugController,
    SdHostController,
    IoMmu,
}

#[derive(Debug)]
enum PciDeviceClassInputDeviceControllerSubclass {
    KeyboardController,
    DigitizerPen,
    MouseController,
    ScannerController,
    GameportController,
}

#[derive(Debug)]
enum PciDeviceClassDockingStationSubclass {
    Generic,
}

#[derive(Debug)]
enum PciDeviceClassProcessorSubclass {
    x386,
    x486,
    Pentium,
    PentiumPro,
    Alpha,
    PowerPc,
    Mips,
    CoProcessor,
}

#[derive(Debug)]
enum PciDeviceClassSerialBusControllerSubclass {
    FireWireController,
    AccessBusController,
    Ssa,
    UsbController,
    FibreChannel,
    SmbusController,
    InfiniBandController,
    IpmiInterface,
    SercosInterface,
    CanbusController,
}

#[derive(Debug)]
enum PciDeviceClassWirelessControllerSubclass {
    IrdaCompatibleController,
    ConsumerIrController,
    RfController,
    BluetoothController,
    BroadbandController,
    EthernetControllerA,
    EthernetControllerB,
}

#[derive(Debug)]
enum PciDeviceClassIntelligentControllerSubclass {
    I20,
}

#[derive(Debug)]
enum PciDeviceClassSatelliteCommunicationControllerSubclass {
    SatelliteTvController,
    SatelliteAudioController,
    SatelliteVoiceController,
    SatelliteDataController,
}

#[derive(Debug)]
enum PciDeviceClassEncryptionControllerSubclass {
    NetworkAndComputingEncryptionOrDecryption,
    EntertainmentEncryptionOrDecryption,
}

#[derive(Debug)]
enum PciDeviceClassSignalProcessingControllerSubclass {
    DpioModules,
    PerformanceCounters,
    CommunicationSynchronizer,
    SignalProcessingManagement,
}

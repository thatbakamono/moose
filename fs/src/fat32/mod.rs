mod directory;
pub mod fat;
mod file;
pub mod lfn;

use bitfield_struct::bitfield;
use bitflags::bitflags;
use bitvec::prelude::*;
use chrono::{DateTime, Datelike, NaiveDateTime, Timelike};
use core::ffi::CStr;
use deku::{DekuContainerWrite, DekuError, DekuRead, DekuUpdate, DekuWrite};
use pretty_hex::pretty_hex;

use core::clone::Clone;
use core::cmp::PartialEq;
use core::convert::From;
use core::convert::TryFrom;
use core::default::Default;
use core::iter::IntoIterator;
use core::iter::Iterator;
use core::marker::Sized;
use core::result::Result;
use core::result::Result::Ok;

use bytemuck::{cast, cast_slice, Pod, Zeroable};
use libm::ceil;
#[cfg(feature = "no_std")]
use spin::Mutex;
use std::borrow::Cow;
#[cfg(not(feature = "no_std"))]
use std::{
    rc::Rc,
    sync::{Arc, Mutex},
};

use crate::fat32::file::FatFile;
extern crate alloc;
use crate::fat32::lfn::LongFileName;
use crate::{Attributes, FileSystemError};
#[cfg(feature = "no_std")]
use alloc::{
    rc::Rc,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
    {format, vec},
};
use std::io::Read;

/// Defines FAT sector size in bytes. It's independent of underlying storage medium sector size.
pub const FAT_SECTOR_SIZE: usize = 512;
/// Defines FAT's sector type. It's independent of underlying storage medium sector.
pub type Sector = [u8; FAT_SECTOR_SIZE];

/// The `FatDataSource` trait defines an interface for reading and writing sectors in a FAT filesystem.
/// This trait includes methods for reading sectors into a buffer, reading sectors into a vector, and writing a sector from a buffer.
pub trait FatDataSource {
    /// Reads `n` sectors starting from the specified `starting_sector` and returns them as a `Vec<Sector>`.
    fn read_sectors(
        &mut self,
        starting_sector: u32,
        n: u32,
    ) -> Result<Vec<Sector>, FileSystemError> {
        let mut sectors = vec![[0u8; FAT_SECTOR_SIZE]; n as usize];

        self.read_sectors_to(starting_sector, &mut sectors)?;

        Ok(sectors)
    }

    /// Reads sectors starting from the specified `starting_sector` into the provided `buffer`.
    fn read_sectors_to(
        &mut self,
        starting_sector: u32,
        buffer: &mut [Sector],
    ) -> Result<(), FileSystemError>;

    /// Writes data from the provided `buffer` to the specified `starting_sector`.
    fn write_sector(&mut self, starting_sector: u32, buffer: &[u8]) -> Result<(), FileSystemError>;
}

// BPB definition
#[derive(DekuRead, Debug)]
pub(crate) struct BiosParameterBlock {
    jmp_boot: [u8; 3],
    #[deku(
        map = "|value: [u8; 8]| -> Result<_, DekuError> { Ok(String::from_utf8_lossy(&value[..]).into_owned()) }"
    )]
    oem_name: String,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    number_of_fats: u8,
    #[deku(assert = "*root_entries_count == 0")]
    root_entries_count: u16, // must be set to 0 in fat32
    #[deku(assert = "*total_count_of_sectors == 0")]
    total_count_of_sectors: u16, // must be set to 0 in fat32
    #[deku(assert = "[0xF0, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF].contains(media_type)")]
    media_type: u8,
    #[deku(assert = "*sectors_per_fat == 0")]
    sectors_per_fat: u16, // must be set to 0 in fat32
    sectors_per_track: u16,
    number_of_heads: u16,
    hidden_sectors_count: u32,
    total_count_of_sectors_32: u32,
    sectors_per_fat_32: u32,
    ext_flags: u16,
    filesystem_version: u16,
    root_directory_first_cluster: u32,
    fs_info_sector: u16,
    boot_sector_copy_sector_number: u16,
    #[deku(pad_bytes_before = "12")]
    drive_number: u8,
    #[deku(assert = "*boot_signature == 0x29", pad_bytes_before = "1")]
    boot_signature: u8, // assert 0x29
    volume_id: u32,
    #[deku(
        map = "|value: [u8; 11]| -> Result<_, DekuError> { Ok(String::from_utf8_lossy(&value[..]).into_owned()) }"
    )]
    volume_label: String,
    #[deku(
        map = "|value: [u8; 8]| -> Result<_, DekuError> { Ok(String::from_utf8_lossy(&value[..]).into_owned()) }"
    )]
    filesystem_type: String,
    #[deku(assert = "*signature == [0x55, 0xAA]", pad_bytes_before = "420")]
    signature: [u8; 2], // assert 0x55 0xA
}

#[derive(Debug)]
enum FatEntry {
    FileEntry(RawFatFileEntry),
    LongFileNameEntry(LongFileNameFatEntry),
}

#[derive(DekuRead, Debug)]
pub(crate) struct FileListing {
    #[deku(reader = "FileListing::read_files(deku::rest)")]
    files: Vec<FatEntry>,
}

impl FileListing {
    fn read_files(
        rest: &BitSlice<u8, Msb0>,
    ) -> Result<(&BitSlice<u8, Msb0>, Vec<FatEntry>), DekuError> {
        let mut buffer: Vec<FatEntry> = vec![];
        let mut remaining_slice = rest;

        loop {
            let mut processed_slice = remaining_slice;

            // Read name
            for _ in 0..11 {
                (processed_slice, _) = u8::read(processed_slice, ())?;
            }

            // Read attributes
            let (_, attr) = FatFileAttributes::read(processed_slice, ())?;

            // Decide if we need to parse LFN entry or classical SFN
            if attr.is_long_name_entry() {
                let entry;

                (remaining_slice, entry) = LongFileNameFatEntry::read(remaining_slice, ())?;
                buffer.push(FatEntry::LongFileNameEntry(entry));
            } else {
                let entry;

                (remaining_slice, entry) = RawFatFileEntry::read(remaining_slice, ())?;
                buffer.push(FatEntry::FileEntry(entry));
            }

            if remaining_slice.is_empty() {
                break;
            }
        }

        Ok((remaining_slice, buffer))
    }
}

#[derive(DekuRead, DekuWrite, Debug)]
pub(crate) struct RawFileListing {
    #[deku(
        reader = "RawFileListing::read_files_raw(deku::rest)",
        writer = "RawFileListing::write_files_raw(&self.files, deku::output)"
    )]
    files: Vec<RawFatFileEntry>,
}

impl RawFileListing {
    fn read_files_raw(
        rest: &BitSlice<u8, Msb0>,
    ) -> Result<(&BitSlice<u8, Msb0>, Vec<RawFatFileEntry>), DekuError> {
        let mut buffer: Vec<RawFatFileEntry> = vec![];
        let mut remaining_slice = rest;

        loop {
            let entry: RawFatFileEntry;

            (remaining_slice, entry) = RawFatFileEntry::read(remaining_slice, ())?;
            buffer.push(entry);

            if remaining_slice.is_empty() {
                break;
            }
        }

        Ok((remaining_slice, buffer))
    }

    fn write_files_raw(
        files: &[RawFatFileEntry],
        output: &mut BitVec<u8, Msb0>,
    ) -> Result<(), DekuError> {
        assert!(files.len() <= 16);

        for file in files {
            file.write(output, ())?;
        }

        Ok(())
    }
}

#[derive(Copy, Clone, DekuRead, Debug, Pod, Zeroable)]
#[repr(C, packed)]
// Same role as `RawFatFileEntry` but another format
pub(crate) struct LongFileNameFatEntry {
    sequence_number: u8,
    name1: [u16; 5],
    attr: u8,
    reserved: u8,
    checksum: u8,
    name2: [u16; 6],
    first_cluster_low: u16,
    name3: [u16; 2],
}

#[derive(DekuRead, Debug, Default, Clone, Copy, Zeroable, Pod)]
#[repr(C)]
// On-disk file entry structure
pub(crate) struct RawFatFileEntry {
    name: [u8; 11],
    attr: u8,
    nt_res: u8,
    creation_time_milliseconds: u8,
    creation_time: u16,
    creation_date: u16,
    last_access_date: u16,
    first_cluster_high: u16,
    last_write_time: u16,
    last_write_date: u16,
    first_cluster_low: u16,
    file_size: u32,
}

impl DekuWrite for RawFatFileEntry {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: ()) -> Result<(), DekuError> {
        for byte in self.name {
            byte.write(output, ())?;
        }

        self.attr.write(output, ());
        self.nt_res.write(output, ());
        self.creation_time_milliseconds.write(output, ());
        self.creation_time.write(output, ());
        self.creation_date.write(output, ());
        self.last_access_date.write(output, ());
        self.first_cluster_high.write(output, ());
        self.last_write_time.write(output, ());
        self.last_write_date.write(output, ());
        self.first_cluster_low.write(output, ());
        self.file_size.write(output, ());

        Ok(())
    }
}

// High level representation of FAT file, which consists of multiple raw, on-disk fat file entries
#[derive(Debug, Clone, Default)]
pub struct FatFileEntry {
    name: String,
    attr: FatFileAttributes,
    creation_time: NaiveDateTime,
    last_access_time: NaiveDateTime,
    last_write_time: NaiveDateTime,
    file_size: u32,
    raw: Vec<RawFatFileEntry>,
}

impl FatFileEntry {
    pub fn set_name(&mut self, name: String) {
        self.name = name;

        // Remove all LFN entries
        self.raw.resize(1, RawFatFileEntry::default());

        // If name fits in 11 bytes, we don't need to allocate any LFN entries, so fill SFN data and
        // return
        if self.name.len() <= 11 {
            for i in 0..self.name.len() {
                self.raw[0].name[i] = self.name.as_bytes()[i];
            }

            // Names need to be padded to 11 characters with spaces
            for i in self.name.len()..11 {
                self.raw[0].name[i] = b' ';
            }

            return;
        }

        let binding = LongFileName::padded_sfn(&self.name);
        let bytes = binding.as_bytes();

        self.raw[0].name = bytes[0..11]
            .bytes()
            .try_collect::<Vec<u8>>()
            .unwrap()
            .try_into()
            .unwrap();

        let lfn_name_length = ucs2::str_num_ucs2_chars(self.name.as_str()).unwrap();
        let lfn_name_buffer_length = (lfn_name_length / 13) * 13 + 13;
        let mut lfn_buffer: Vec<u16> = vec![0u16; lfn_name_buffer_length];
        ucs2::encode(self.name.as_str(), lfn_buffer.as_mut_slice()).unwrap();

        lfn_buffer
            .chunks(13)
            .rev()
            .enumerate()
            .for_each(|(index, ucs2_part)| {
                let lfn = LongFileNameFatEntry {
                    sequence_number: (index + 1) as u8,
                    name1: ucs2_part[0..5].try_into().unwrap(),
                    // LFN entry attributes
                    attr: (FatFileAttributes::READ_ONLY
                        | FatFileAttributes::HIDDEN
                        | FatFileAttributes::SYSTEM
                        | FatFileAttributes::VOLUME_ID)
                        .bits(),
                    reserved: 0,
                    checksum: 0, // @TODO: Checksum of SFN entry
                    name2: ucs2_part[5..11].try_into().unwrap(),
                    first_cluster_low: 0,
                    name3: ucs2_part[11..=12].try_into().unwrap(),
                };

                // It's safe cast because SFN has the same layout as LFN
                let lfn_as_sfn: RawFatFileEntry = cast(lfn);

                self.raw.push(lfn_as_sfn);
            });
    }

    pub fn set_attr(&mut self, attr: FatFileAttributes) {
        self.attr = attr;

        self.raw[0].attr = attr.bits();
    }

    pub fn set_creation_time(&mut self, creation_time: NaiveDateTime) {
        self.creation_time = creation_time;

        let (date, time) = Self::create_fields_from_datetime(&self.creation_time);
        self.raw[0].creation_date = date.into_bits();
        self.raw[0].creation_time = time.into_bits();
    }

    pub fn set_last_access_time(&mut self, last_access_time: NaiveDateTime) {
        self.last_access_time = last_access_time;

        let (date, _) = Self::create_fields_from_datetime(&self.last_access_time);
        self.raw[0].last_access_date = date.into_bits();
        // There's no last_access_time sadly
    }

    pub fn set_last_write_time(&mut self, last_write_time: NaiveDateTime) {
        self.last_write_time = last_write_time;

        let (date, time) = Self::create_fields_from_datetime(&self.last_write_time);
        self.raw[0].last_write_date = date.into_bits();
        self.raw[0].last_write_time = time.into_bits();
    }

    pub fn set_file_size(&mut self, file_size: u32) {
        self.file_size = file_size;

        self.raw[0].file_size = file_size;
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn attr(&self) -> FatFileAttributes {
        self.attr
    }

    pub fn creation_time(&self) -> NaiveDateTime {
        self.creation_time
    }

    pub fn last_access_time(&self) -> NaiveDateTime {
        self.last_access_time
    }

    pub fn last_write_time(&self) -> NaiveDateTime {
        self.last_write_time
    }

    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    pub(crate) fn raw(&self) -> &Vec<RawFatFileEntry> {
        &self.raw
    }

    pub(crate) fn sfn(&self) -> &RawFatFileEntry {
        self.raw.first().unwrap()
    }

    fn create_datetime_from_fields(date: FatDateFormat, time: FatTimeFormat) -> NaiveDateTime {
        NaiveDateTime::default()
            .with_year(1980 + date.year() as i32)
            .unwrap()
            .with_month(date.month() as u32)
            .unwrap()
            .with_day(date.day() as u32)
            .unwrap()
            .with_hour(time.hours() as u32)
            .unwrap()
            .with_minute(time.minutes() as u32)
            .unwrap()
            .with_second(time.seconds() as u32)
            .unwrap()
    }

    fn create_fields_from_datetime(date_time: &NaiveDateTime) -> (FatDateFormat, FatTimeFormat) {
        let mut fat_date = FatDateFormat::default()
            .with_day(date_time.day() as u8)
            .with_month(date_time.month() as u8)
            .with_year((date_time.year() - 1980) as u8);

        let mut fat_time = FatTimeFormat::default()
            .with_hours(date_time.hour() as u8)
            .with_minutes(date_time.minute() as u8)
            .with_seconds((date_time.second() / 2) as u8);

        (fat_date, fat_time)
    }
}

impl From<RawFatFileEntry> for FatFileEntry {
    fn from(value: RawFatFileEntry) -> Self {
        let creation_time = {
            let date = FatDateFormat::from_bits(value.creation_date);
            let time = FatTimeFormat::from_bits(value.creation_time);

            Self::create_datetime_from_fields(date, time)
        };

        let last_access_time = {
            let date = FatDateFormat::from_bits(value.last_access_date);
            let time = FatTimeFormat::from_bits(value.last_write_time);

            Self::create_datetime_from_fields(date, time)
        };

        let last_write_time = {
            let date = FatDateFormat::from_bits(value.last_write_date);
            let time = FatTimeFormat::from_bits(value.last_write_time);

            Self::create_datetime_from_fields(date, time)
        };

        FatFileEntry {
            name: String::from_utf8_lossy(&value.name[..])
                .to_string()
                .trim()
                .to_string(),
            attr: FatFileAttributes::from_bits(value.attr).unwrap(),
            creation_time,
            last_access_time,
            last_write_time,
            file_size: value.file_size,
            raw: vec![value],
        }
    }
}

bitflags! {
    #[derive(Copy, Clone, Debug, Default)]
    pub struct FatFileAttributes: u8 {
        const READ_ONLY = 1;
        const HIDDEN = 1 << 1;
        const SYSTEM = 1 << 2;
        const VOLUME_ID = 1 << 3;
        const DIRECTORY = 1 << 4;
        const ARCHIVE = 1 << 5;
    }
}

impl FatFileAttributes {
    pub fn is_long_name_entry(&self) -> bool {
        self.contains(FatFileAttributes::READ_ONLY)
            && self.contains(FatFileAttributes::HIDDEN)
            && self.contains(FatFileAttributes::SYSTEM)
            && self.contains(FatFileAttributes::VOLUME_ID)
    }

    pub fn is_directory(&self) -> bool {
        self.contains(FatFileAttributes::DIRECTORY)
    }
}

impl From<Attributes> for FatFileAttributes {
    fn from(value: Attributes) -> Self {
        let mut fat_attributes = FatFileAttributes::default();

        if value.contains(Attributes::ARCHIVE) {
            fat_attributes |= FatFileAttributes::ARCHIVE;
        }

        if value.contains(Attributes::HIDDEN) {
            fat_attributes |= FatFileAttributes::HIDDEN;
        }

        if value.contains(Attributes::READ_ONLY) {
            fat_attributes |= FatFileAttributes::READ_ONLY;
        }

        if value.contains(Attributes::SYSTEM_FILE) {
            fat_attributes |= FatFileAttributes::SYSTEM;
        }

        if value.contains(Attributes::DIRECTORY) {
            fat_attributes |= FatFileAttributes::DIRECTORY;
        }

        fat_attributes
    }
}

impl From<FatFileAttributes> for Attributes {
    fn from(value: FatFileAttributes) -> Self {
        let mut fat_attributes = Attributes::default();

        if value.contains(FatFileAttributes::ARCHIVE) {
            fat_attributes |= Attributes::ARCHIVE;
        }

        if value.contains(FatFileAttributes::HIDDEN) {
            fat_attributes |= Attributes::HIDDEN;
        }

        if value.contains(FatFileAttributes::READ_ONLY) {
            fat_attributes |= Attributes::READ_ONLY;
        }

        if value.contains(FatFileAttributes::SYSTEM) {
            fat_attributes |= Attributes::SYSTEM_FILE;
        }

        if value.contains(FatFileAttributes::DIRECTORY) {
            fat_attributes |= Attributes::DIRECTORY;
        }

        fat_attributes
    }
}

impl DekuRead<'_> for FatFileAttributes {
    fn read(input: &BitSlice<u8, Msb0>, ctx: ()) -> Result<(&BitSlice<u8, Msb0>, Self), DekuError>
    where
        Self: Sized,
    {
        let (slice, byte) = u8::read(input, ())?;

        Ok((slice, FatFileAttributes::from_bits_retain(byte)))
    }
}

#[bitfield(u16)]
struct FatDateFormat {
    #[bits(5)]
    pub day: u8,
    #[bits(4)]
    pub month: u8,
    #[bits(7)]
    pub year: u8,
}

#[bitfield(u16)]
struct FatTimeFormat {
    #[bits(5)]
    seconds: u8,
    #[bits(6)]
    minutes: u8,
    #[bits(5)]
    hours: u8,
}

static IMAGE1_DATA: &[u8] = include_bytes!("../../assets/test1.img");

#[cfg(test)]
mod tests {
    use bytemuck::cast_slice;
    use chrono::{Datelike, NaiveDateTime, Utc};
    use libm::{ceil, exp, round};
    use log::debug;
    use std::cell::RefCell;
    use std::fmt::format;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    use crate::fat32::fat::Fat;
    use crate::{
        Attributes, Directory, File as FileTrait, FileSystem, FileSystemEntry, FileSystemError,
    };

    use super::{
        FatDataSource, FatDateFormat, FatTimeFormat, Sector, FAT_SECTOR_SIZE, IMAGE1_DATA,
    };

    struct FileFatDataSource {
        file: File,
    }

    impl FatDataSource for FileFatDataSource {
        fn read_sectors_to(
            &mut self,
            starting_sector: u32,
            buffer: &mut [Sector],
        ) -> Result<(), FileSystemError> {
            let starting_offset = starting_sector * FAT_SECTOR_SIZE as u32;
            let n = buffer.len() * FAT_SECTOR_SIZE;

            self.file.seek(SeekFrom::Start(starting_offset as u64));
            let read = self.file.read_exact(buffer.flatten_mut());

            Ok(())
        }

        fn write_sector(
            &mut self,
            starting_sector: u32,
            buffer: &[u8],
        ) -> Result<(), FileSystemError> {
            let starting_offset = starting_sector * FAT_SECTOR_SIZE as u32;
            assert_eq!(buffer.len(), 512);

            self.file.seek(SeekFrom::Start(starting_offset as u64));
            self.file.write(buffer).unwrap();

            Ok(())
        }
    }

    struct InMemoryFatDataSource {
        data: Vec<u8>,
    }

    impl FatDataSource for InMemoryFatDataSource {
        fn read_sectors_to(
            &mut self,
            starting_sector: u32,
            buffer: &mut [Sector],
        ) -> Result<(), FileSystemError> {
            let starting_offset = (starting_sector * FAT_SECTOR_SIZE as u32) as usize;
            let n = buffer.len() * FAT_SECTOR_SIZE;

            let buf = buffer.flatten_mut();
            buf.copy_from_slice(&self.data[starting_offset..(starting_offset + n)]);

            Ok(())
        }

        fn write_sector(
            &mut self,
            starting_sector: u32,
            buffer: &[u8],
        ) -> Result<(), FileSystemError> {
            assert_eq!(buffer.len(), 512);

            let starting_offset = (starting_sector * FAT_SECTOR_SIZE as u32) as usize;

            self.data[starting_offset..(starting_offset + buffer.len())].copy_from_slice(buffer);

            Ok(())
        }
    }

    fn setup_fat() -> Rc<RefCell<Fat>> {
        let mut vec = Vec::with_capacity(IMAGE1_DATA.len());
        vec.extend_from_slice(IMAGE1_DATA);

        let data_source = InMemoryFatDataSource { data: vec };
        Fat::new(
            Arc::new(Mutex::new(data_source)),
            0,
            (IMAGE1_DATA.len() / FAT_SECTOR_SIZE) as u32,
        )
    }

    #[test]
    fn test_file_listing_in_root_directory() {
        let expected_names = vec!["lorem_ipsum.txt", "books", "filesystems", "fruits"];

        let fat = setup_fat();
        let dir = fat.open_directory("").unwrap();
        let names: Vec<String> = dir
            .entries()
            .map(|entry| (*entry.name()).to_string())
            .collect();

        assert_eq!(expected_names, names);
    }

    #[test]
    fn test_read_from_sfn_file_in_root_directory() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("lorem_ipsum.txt")?;

        // Start of the file
        let mut buffer1 = [0u8; 11];
        file.read(0, &mut buffer1)?;

        // Somewhere in the first cluster
        let mut buffer2 = [0u8; 11];
        file.read(250, &mut buffer2)?;

        // End of the first cluster and start of the second
        let mut buffer3 = [0u8; 50];
        file.read(508, &mut buffer3)?;

        // Last cluster
        let mut buffer4 = [0u8; 50];
        file.read(file.file_size as usize - 70, &mut buffer4)?;

        // Last 11 characters
        let mut buffer5 = [0u8; 11];
        file.read(file.file_size as usize - 12, &mut buffer5)?;

        // Last character
        let mut buffer6 = [0u8; 1];
        file.read(file.file_size as usize - 1, &mut buffer6)?;

        // Read outside the boundary
        let mut buffer7 = [0u8; 1];
        let result = file.read(file.file_size as usize, &mut buffer7);

        assert_eq!(String::from_utf8_lossy(&buffer1), "Lorem ipsum");
        assert_eq!(String::from_utf8_lossy(&buffer2), "ricies dict");
        assert_eq!(
            String::from_utf8_lossy(&buffer3),
            " nibh. Sed at porttitor tellus. Proin vulputate se"
        );
        assert_eq!(
            String::from_utf8_lossy(&buffer4),
            "rtis enim. Quisque porta elit tellus, ut ullamcorp"
        );
        assert_eq!(String::from_utf8_lossy(&buffer5), "eleifend ut");
        assert_eq!(String::from_utf8_lossy(&buffer6), ".");
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_file_creation_in_directory() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let expected_names = vec![
            "lorem_ipsum.txt",
            "books",
            "filesystems",
            "fruits",
            "Long directory name",
            "Long filename",
        ];
        let dir_path = "".to_string();
        let mut dir = fat.open_directory(&dir_path).unwrap();

        dir.create_directory("Long directory name".to_string(), Attributes::READ_ONLY)?;
        dir.create_file("Long filename".to_string(), Attributes::READ_ONLY)?;

        let names: Vec<String> = dir
            .entries()
            .map(|entry| (*entry.name()).to_string())
            .collect();

        assert_eq!(names, expected_names);

        Ok(())
    }

    #[test]
    fn test_new_file_attributes() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let dir_path = "".to_string();
        let mut dir = fat.open_directory(&dir_path)?;

        dir.create_file(
            "file1".to_string(),
            Attributes::HIDDEN | Attributes::SYSTEM_FILE,
        )?;
        dir.create_directory("dir1".to_string(), Attributes::DIRECTORY);

        let file = fat.open_file("file1")?;
        let directory = fat.open_directory("dir1")?;

        assert_eq!(
            file.attributes(),
            Attributes::HIDDEN | Attributes::SYSTEM_FILE
        );
        assert_eq!(directory.attributes(), Attributes::DIRECTORY);

        Ok(())
    }

    #[test]
    fn test_date_times() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("books/english/macbeth.txt")?;
        let mut directory = fat.open_directory("books/polish")?;
        let current_time = Utc::now().naive_utc();

        assert_eq!(
            file.creation_date_time(),
            NaiveDateTime::parse_from_str("2024-06-16 15:06:04", "%Y-%m-%d %H:%M:%S").unwrap()
        );
        assert_eq!(
            directory.creation_date_time(),
            NaiveDateTime::parse_from_str("2024-06-16 15:06:04", "%Y-%m-%d %H:%M:%S").unwrap()
        );

        file.set_creation_datetime(current_time);
        file.set_modification_datetime(current_time);

        directory.set_creation_datetime(current_time);
        directory.set_modification_datetime(current_time);

        // re-read file information from the disk
        let file2 = fat.open_file("books/english/macbeth.txt")?;
        let directory2 = fat.open_directory("books/polish")?;

        assert!(
            file2
                .creation_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );
        assert!(
            file2
                .modification_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );

        assert!(
            directory2
                .creation_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );
        assert!(
            directory2
                .modification_date_time()
                .signed_duration_since(current_time)
                .num_seconds()
                <= 3
        );

        Ok(())
    }

    #[test]
    fn test_attributes() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("books/polish/pan-tadeusz.txt")?;
        let mut directory = fat.open_directory("books/english")?;

        file.set_attributes(Attributes::SYSTEM_FILE);
        directory.set_attributes(Attributes::HIDDEN | Attributes::DIRECTORY);

        // Re-read files from the disk
        let file2 = fat.open_file("books/polish/pan-tadeusz.txt")?;
        let directory2 = fat.open_directory("books/english")?;

        assert_eq!(file2.attributes(), Attributes::SYSTEM_FILE);
        assert_eq!(
            directory2.attributes(),
            Attributes::HIDDEN | Attributes::DIRECTORY
        );

        Ok(())
    }

    #[test]
    fn test_rename() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file1 = fat.open_file("fruits/random things/random2/Methamphetamine.txt")?;
        let mut dir1 = fat.open_directory("filesystems/Resilient File System")?;

        file1.rename("meth.txt");
        dir1.rename("ReFS");

        let mut file2 = fat.open_file("fruits/random things/random2/meth.txt")?;
        let mut dir2 = fat.open_directory("filesystems/ReFS")?;

        Ok(())
    }

    #[test]
    fn test_file_move() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file1 = fat.open_file("fruits/random things/random2/File Allocation Table.txt")?;
        let destination_directory = fat.open_directory("filesystems/File Allocation Table")?;

        file1.move_to(&destination_directory);

        let mut file2 =
            fat.open_file("filesystems/File Allocation Table/File Allocation Table.txt")?;
        let mut file3 = fat.open_file("fruits/random things/random2/File Allocation Table.txt");

        let entries: Vec<String> = destination_directory
            .entries()
            .map(|entry| entry.name().to_string())
            .collect();
        let expected_entries = vec![
            ".",
            "..",
            "File Allocation Table 16",
            "File Allocation Table 32",
            "File Allocation Table 12",
            "File Allocation Table.txt",
        ];

        assert_eq!(entries, expected_entries);
        assert!(file3.is_err());

        Ok(())
    }

    #[test]
    fn test_directory_move() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut directory = fat.open_directory("fruits")?;
        let expected_entries: Vec<FileSystemEntry> = directory.entries().collect();

        let destination_directory = fat.open_directory("books")?;

        directory.move_to(&destination_directory);

        let directory2 = fat.open_directory("books/fruits")?;
        let entries: Vec<FileSystemEntry> = directory2.entries().collect();

        assert_eq!(entries, expected_entries);

        Ok(())
    }

    #[test]
    fn test_file_removal() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("lorem_ipsum.txt")?;
        file.delete();

        let directory = fat.open_directory("")?;
        let entries: Vec<String> = directory
            .entries()
            .map(|entry| entry.name().to_string())
            .collect();
        let expected_entries = vec!["books", "filesystems", "fruits"];

        assert_eq!(entries, expected_entries);

        Ok(())
    }

    #[test]
    fn test_directory_removal() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut directory = fat.open_directory("fruits")?;
        directory.delete();

        let directory = fat.open_directory("fruits");

        assert!(directory.is_err());

        Ok(())
    }

    #[test]
    fn test_file_write() -> Result<(), FileSystemError> {
        let fat = setup_fat();

        let mut file = fat.open_file("fruits/STRAWBERRY.TXT")?;
        let buffer = "Test";
        unsafe {
            file.write(3, buffer.as_bytes());
        }

        let mut buffer2 = [0u8; 7];
        file.read(0, &mut buffer2[..]);

        assert_eq!(String::from_utf8_lossy(&buffer2), "STRTest");

        Ok(())
    }
}

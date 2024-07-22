use bitvec::prelude::*;
use bytemuck::{cast, cast_slice, cast_slice_mut};
use chrono::NaiveDateTime;
use deku::DekuWrite;
use std::cell::RefCell;
use std::ffi::CStr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use crate::fat32::{FatFileAttributes, FatFileEntry, RawFileListing, FAT_SECTOR_SIZE};
use crate::{FileSystem, FileSystemError};

use super::directory::FatDirectory;
use super::file::FatFile;
use super::{
    BiosParameterBlock, FatDataSource, FatEntry, FatTimeSource, FileListing, RawFatFileEntry,
    Sector,
};

pub const FAT_FREE_SECTOR: u32 = 0x00;
pub const FAT_END_OF_FILE_MARK: u32 = 0xFFFFFFFF;
const FAT_FREE_ENTRY: u8 = 0xE5;

pub struct Fat {
    data_source: Arc<Mutex<dyn FatDataSource>>,
    time_source: Arc<dyn FatTimeSource>,
    partition_first_sector_lba: u32,
    pub(crate) bpb: BiosParameterBlock,
    pub(crate) file_allocation_table: Vec<u32>,
}

impl Fat {
    pub fn new(
        data_source: Arc<Mutex<dyn FatDataSource>>,
        time_source: Arc<dyn FatTimeSource>,
        partition_first_sector_lba: u32,
    ) -> Rc<RefCell<Self>> {
        let bpb = Self::read_bpb(Arc::clone(&data_source), partition_first_sector_lba)
            .expect("Failed to read Bios Parameter Block");

        let mut fat = Self {
            data_source,
            time_source,
            partition_first_sector_lba,
            bpb,
            file_allocation_table: Vec::new(),
        };

        fat.init().unwrap();

        Rc::new(RefCell::new(fat))
    }

    fn init(&mut self) -> Result<(), FileSystemError> {
        // Safety: We can cast FAT because x86_64 endianness is the same as FAT endianness
        if cfg!(target_endian = "big") {
            unimplemented!();
        }

        let fat_size = self.bpb.sectors_per_fat_32;
        let fat_start = self.bpb.reserved_sector_count as u32;
        let sectors = self.read_sectors(fat_start, fat_size)?;

        let fat = sectors
            .into_iter()
            .flatten()
            .array_chunks()
            .map(u32::from_le_bytes)
            .collect();

        self.file_allocation_table = fat;

        Ok(())
    }

    /// Returns an iterator over the cluster chain for a file starting from the given initial cluster.
    /// This iterator yields cluster numbers in the order they are linked within the File Allocation Table.
    ///
    /// The iterator can be cloned and supports double-ended iteration, allowing traversal from both the beginning and the end.
    ///
    /// # Parameters
    ///
    /// - `cluster`: The initial cluster number from which to start the iteration.
    ///
    /// # Returns
    ///
    /// An iterator that yields `u32` values representing the cluster numbers in the file's cluster chain.
    pub(crate) fn get_clusters_for_file(
        &self,
        mut cluster: u32,
    ) -> impl DoubleEndedIterator<Item = u32> + Clone {
        // @TODO: Do some tests to find optimal value
        let mut clusters = Vec::with_capacity(32);
        clusters.push(cluster);

        loop {
            let next_cluster = self.file_allocation_table[cluster as usize];

            if next_cluster >= 0x0FFFFFF8 {
                // Last entry
                break;
            }

            clusters.push(next_cluster);
            cluster = next_cluster;
        }

        clusters.into_iter()
    }

    /// Retrieves a list of raw file entries from a specified cluster.
    fn get_raw_file_listing_from_cluster(
        &self,
        cluster: u32,
    ) -> Result<Vec<RawFatFileEntry>, FileSystemError> {
        let cluster = self.read_cluster(cluster)?;
        let slice = cluster.as_slice().as_flattened();
        let file_listing = RawFileListing::try_from(slice).unwrap();

        Ok(file_listing.files)
    }

    /// Retrieves a list of parsed file entries from a specified cluster.
    pub(crate) fn get_file_listing_from_cluster(
        &self,
        cluster: u32,
    ) -> Result<Vec<FatFileEntry>, FileSystemError> {
        let cluster = self.read_cluster(cluster)?;
        let slice = cluster.as_slice().as_flattened();
        let file_listing = FileListing::try_from(slice).unwrap();

        let mut fat_entries: Vec<FatFileEntry> = vec![];
        let mut lfn_entries: Vec<RawFatFileEntry> = vec![];
        let mut name = String::new();
        let mut processing_lfn = false;

        for entry in file_listing.files {
            match entry {
                FatEntry::FileEntry(file) => {
                    // Last entry, don't read more
                    if file.name == [0u8; 11] {
                        break;
                    }

                    // Free entry, continue reading
                    if file.name[0] == FAT_FREE_ENTRY {
                        continue;
                    }

                    let mut fat_file_entry = FatFileEntry::from(file);

                    if processing_lfn {
                        fat_file_entry.name = name.clone();
                        processing_lfn = false;
                        fat_file_entry.raw.extend(lfn_entries);

                        lfn_entries = vec![];
                        name = String::new();
                    }

                    fat_entries.push(fat_file_entry);
                }
                FatEntry::LongFileNameEntry(lfn) => {
                    processing_lfn = true;

                    // Every UCS-2 char can occupy 3 bytes and need to add null terminator at the end
                    let mut buffer = [0u8; 26 * 3 + 1];
                    let mut index = 0;

                    let name1 = lfn.name1;
                    let name2 = lfn.name2;
                    let name3 = lfn.name3;

                    index += ucs2::decode(&name1, &mut buffer[index..]).unwrap();
                    index += ucs2::decode(&name2, &mut buffer[index..]).unwrap();
                    ucs2::decode(&name3, &mut buffer[index..]).unwrap();

                    name.insert_str(
                        0,
                        CStr::from_bytes_until_nul(&buffer)
                            .unwrap()
                            .to_str()
                            .unwrap(),
                    );

                    let raw_fat_file_entry: RawFatFileEntry = cast(lfn);
                    lfn_entries.push(raw_fat_file_entry);
                }
            }
        }

        Ok(fat_entries)
    }

    /// Reads a specified number of sectors starting from a given Logical Block Address (LBA) and returns them as a vector of `Sector` structs.
    /// This method interacts with the underlying storage to fetch the data contained in the sectors.
    ///
    /// # Parameters
    ///
    /// - `first_sector_lba`: The Logical Block Address of the first sector to read.
    /// - `n`: The number of sectors to read.
    fn read_sectors(&self, first_sector_lba: u32, n: u32) -> Result<Vec<Sector>, FileSystemError> {
        if n * 512 >= (u16::MAX - 1) as u32 {
            let mut sectors = vec![[0u8; 512]; n as usize];
            let mut data_source = self.data_source.lock().unwrap();

            for i in 0..(n - 2) {
                data_source.read_sectors_to(
                    self.partition_first_sector_lba + first_sector_lba + i,
                    &mut sectors[(i as usize)..((i + 1) as usize)],
                )?;
            }

            return Ok(sectors);
        }

        self.data_source
            .lock()
            .unwrap()
            .read_sectors(self.partition_first_sector_lba + first_sector_lba, n)
    }

    /// Reads all sectors belonging to a specified cluster and returns them as a vector of `Sector` structs.
    pub(crate) fn read_cluster(&self, cluster: u32) -> Result<Vec<Sector>, FileSystemError> {
        self.read_sectors(
            self.convert_cluster_number_to_sector_number(cluster),
            self.bpb.sectors_per_cluster as u32,
        )
    }

    /// Reads all sectors belonging to a specified cluster and writes the data into the provided buffer.
    /// This method calculates the starting sector based on the cluster number and reads the sectors sequentially into the buffer.
    ///
    /// # Parameters
    ///
    /// - `cluster`: The cluster number from which to read the sectors.
    /// - `buffer`: A mutable slice of bytes where the read data will be stored. The size of the buffer should be sufficient to hold all the data from the cluster.
    ///
    pub(crate) fn read_cluster_to(
        &self,
        cluster: u32,
        buffer: &mut [u8],
    ) -> Result<(), FileSystemError> {
        assert_eq!(
            self.bpb.bytes_per_sector * (self.bpb.sectors_per_cluster as u16),
            buffer.len() as u16
        );

        let sector_buffer: &mut [Sector] = cast_slice_mut(buffer);
        let mut data_source = self.data_source.lock().unwrap();

        for i in 0..self.bpb.sectors_per_cluster {
            data_source.read_sectors_to(
                self.partition_first_sector_lba
                    + self.convert_cluster_number_to_sector_number(cluster)
                    + i as u32,
                &mut sector_buffer[(i as usize)..((i + 1) as usize)],
            )?
        }

        Ok(())
    }

    /// Writes data from the provided buffer to all sectors belonging to a specified cluster.
    ///
    /// # Parameters
    ///
    /// - `cluster`: The cluster number where the data will be written.
    /// - `buffer`: A slice of bytes containing the data to be written. The size of the buffer should be sufficient to cover all the sectors in the cluster.
    pub(crate) fn write_cluster(&self, cluster: u32, buffer: &[u8]) -> Result<(), FileSystemError> {
        assert_eq!(
            self.bpb.bytes_per_sector * (self.bpb.sectors_per_cluster as u16),
            buffer.len() as u16
        );

        let mut ds = self.data_source.lock().unwrap();

        for i in 0..self.bpb.sectors_per_cluster as u16 {
            let sector_start = i * self.bpb.bytes_per_sector;
            let sector_end = (i + 1) * self.bpb.bytes_per_sector;

            ds.write_sector(
                self.partition_first_sector_lba
                    + self.convert_cluster_number_to_sector_number(cluster)
                    + i as u32,
                &buffer[(sector_start as usize)..(sector_end as usize)],
            )?
        }

        Ok(())
    }

    /// Allocates and links a specified number of clusters.
    /// This method finds free clusters, allocates them, and links them together, returning an iterator over the allocated clusters.
    ///
    /// # Parameters
    ///
    /// - `count`: The number of clusters to allocate and link.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok(impl Iterator<Item = (usize, u32)>)` if the allocation and linking operation succeeds. The iterator yields tuples where the first element is the number of the cluster, and the second element is the entry value.
    /// - `Err(FileSystemError)` if the allocation and linking operation fails.
    pub(crate) fn allocate_and_link_clusters(
        &mut self,
        count: usize,
    ) -> Result<impl Iterator<Item = (usize, u32)>, FileSystemError> {
        let free_clusters: Vec<(usize, u32)> = self.find_free_clusters(count).collect();

        if free_clusters.len() < count {
            return Err(FileSystemError::NotEnoughSpace);
        }

        let mut free_cluster_iterator = free_clusters.iter().peekable();

        while let Some(free_cluster) = free_cluster_iterator.next() {
            let next_cluster = free_cluster_iterator.peek();

            if let Some((next_index, _)) = next_cluster {
                self.file_allocation_table[free_cluster.0] = *next_index as u32;
            } else {
                // End of file
                self.file_allocation_table[free_cluster.0] = 0xFFFF_FFFF;
            }
        }

        Ok(free_clusters.into_iter())
    }

    /// Marks clusters starting from a specified cluster number as free.
    /// This method updates the FAT entries to indicate that the clusters are available for future allocation.
    /// It frees all clusters in the chain starting from the `starting_cluster`.
    ///
    /// # Parameters
    ///
    /// - `starting_cluster`: The cluster number from which to start marking clusters as free.
    pub(crate) fn mark_clusters_as_free(&mut self, starting_cluster: u32) {
        self.get_clusters_for_file(starting_cluster)
            .for_each(|cluster| {
                self.file_allocation_table[cluster as usize] = 0x00;
            });
    }

    /// Saves modified file allocation table to the underlying storage
    pub fn save_fat(&self) -> Result<(), FileSystemError> {
        let mut data_source = self.data_source.lock().unwrap();

        let fat_size = self.bpb.sectors_per_fat_32 as usize;
        let fat_start = self.bpb.reserved_sector_count as usize;
        let fat = self.file_allocation_table.as_slice();
        let fat_slice: &[u8] = cast_slice(fat);

        assert_eq!(fat_slice.len(), fat_size * FAT_SECTOR_SIZE);

        for i in 0..fat_size {
            let slice = &fat_slice[(i * FAT_SECTOR_SIZE)..((i + 1) * FAT_SECTOR_SIZE)];

            data_source.write_sector((fat_start + i) as u32, slice)?;
        }

        Ok(())
    }

    /// Finds and returns an iterator over free clusters.
    /// This method searches for a specified number of consecutive free clusters and returns an iterator.
    ///
    /// # Parameters
    ///
    /// - `count`: The number of free clusters to find.
    ///
    /// # Returns
    ///
    /// An iterator over free clusters, where each item is a tuple containing the number of the cluster and it's value.
    fn find_free_clusters(&mut self, count: usize) -> impl Iterator<Item = (usize, u32)> + '_ {
        self.file_allocation_table
            .iter()
            .cloned()
            .enumerate()
            .filter(|entry| entry.1 == FAT_FREE_SECTOR)
            .take(count + 1)
    }

    /// Convers cluster number to starting sector number.
    fn convert_cluster_number_to_sector_number(&self, cluster_number: u32) -> u32 {
        // Data starts at second cluster so need to subtract 2 from cluster_number
        ((cluster_number - 2) * self.bpb.sectors_per_cluster as u32) + self.first_data_sector()
    }

    /// Returns first data sector in the partition.
    fn first_data_sector(&self) -> u32 {
        self.bpb.reserved_sector_count as u32
            + (self.bpb.number_of_fats as u32 * self.bpb.sectors_per_fat_32)
            + self.root_dir_sectors()
    }

    /// Returns the length of root directory in sectors
    fn root_dir_sectors(&self) -> u32 {
        (((self.bpb.root_entries_count * 32) + (self.bpb.bytes_per_sector - 1))
            / self.bpb.bytes_per_sector) as u32
    }

    /// Reads Bios Parameter Block from the disk.
    fn read_bpb(
        disk: Arc<Mutex<dyn FatDataSource>>,
        partition_first_sector_lba: u32,
    ) -> Result<BiosParameterBlock, FileSystemError> {
        Ok(BiosParameterBlock::try_from(
            disk.lock()
                .unwrap()
                .read_sectors(partition_first_sector_lba, 1)?[0]
                .as_slice(),
        )
        .map_err(|_| FileSystemError::BadData)?)
    }

    /// Retrieves a file entry and its corresponding cluster number by its path.
    /// This method searches for the file entry specified by the given path and returns it along with its cluster number.
    ///
    /// # Parameters
    ///
    /// - `path`: The path of the file to retrieve, represented as a string.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok((FatFileEntry, u32))` containing the file entry and its cluster number on success.
    /// - `Err(FileSystemError)` if the file entry cannot be found or if there is an error in the filesystem.
    pub(crate) fn get_by_path(&self, path: &str) -> Result<(FatFileEntry, u32), FileSystemError> {
        let mut cluster = self.bpb.root_directory_first_cluster;
        let segments = path.split("/").count();

        if path.is_empty() {
            // Root directory
            let mut file_entry = FatFileEntry::default();
            let raw_file_entry = RawFatFileEntry {
                first_cluster_low: cluster as u16,
                ..Default::default()
            };

            file_entry.raw.push(raw_file_entry);

            file_entry.set_attr(FatFileAttributes::DIRECTORY);

            return Ok((file_entry, cluster));
        }

        // Split by `/` and loop over entries
        for (index, subdirectory) in path.split("/").enumerate() {
            if subdirectory.is_empty() {
                continue;
            }

            for file_cluster in self.get_clusters_for_file(cluster) {
                let listing = self.get_file_listing_from_cluster(file_cluster)?;

                for file in listing.iter() {
                    if file.name.eq(subdirectory) {
                        cluster = ((file.sfn().first_cluster_high as u32) << 16)
                            | file.sfn().first_cluster_low as u32;

                        if index == segments - 1 {
                            // Found
                            return Ok((file.clone(), file_cluster));
                        }

                        break;
                    }
                }
            }
        }

        Err(FileSystemError::NotFound)
    }

    /// Moves a file represented by its file entry to a new directory.
    /// This method moves the file entry to the specified directory and updates its location in the filesystem.
    ///
    /// # Parameters
    ///
    /// - `file_entry`: A reference to the `FatFileEntry` representing the file to move.
    /// - `directory`: A reference to the `FatDirectory` representing the destination directory where the file will be moved.
    /// - `current_entry_cluster`: The current cluster number where the file entry is located.
    pub(crate) fn move_file(
        &mut self,
        file_entry: &FatFileEntry,
        directory: &FatDirectory,
        current_entry_cluster: u32,
    ) -> Result<(), FileSystemError> {
        self.remove_file_entry(file_entry, current_entry_cluster)?;

        self.serialize_file_entry(None, file_entry, directory.content_cluster);

        Ok(())
    }

    /// Serializes a file entry or updates existing.
    /// This method serializes the new file entry into the filesystem, optionally replacing an existing file entry if specified.
    ///
    /// # Parameters
    ///
    /// - `old_file_entry`: An optional reference to the old `FatFileEntry` that will be replaced. If `None`, a new file entry will be created.
    /// - `new_file_entry`: A reference to the new `FatFileEntry` that will be serialized into the filesystem.
    /// - `directory_cluster`: The cluster number of the directory where the file entry will be serialized.
    ///
    /// # Returns
    ///
    /// The cluster number of first allocated file entry
    pub(crate) fn serialize_file_entry(
        &mut self,
        old_file_entry: Option<&FatFileEntry>,
        new_file_entry: &FatFileEntry,
        directory_cluster: u32,
    ) -> u32 {
        if let Some(entry) = old_file_entry {
            self.remove_file_entry(entry, directory_cluster).unwrap();
        }

        // @TODO: Technically we can support 20 LFN entries, but this requires some special handling,
        //        as last LFN entry can have max 13 characters, and if filename still does not fit,
        //        we need to cut it, terminate with null char and fill rest of the name with U+FFFF
        assert!(
            new_file_entry.raw.len() < 20,
            "Filename cannot be longer than 255 characters!"
        );

        let occupied_entries = new_file_entry.raw.len();

        let (cluster, first_entry_index) = self
            .find_contiguous_file_entries_in_directory(directory_cluster, occupied_entries)
            .unwrap_or_else(|| {
                self.allocate_file_entries_in_directory(directory_cluster, occupied_entries)
                    .unwrap()
            });

        self.write_file_entry(new_file_entry, cluster, first_entry_index)
            .unwrap();

        cluster
    }

    /// Writes a file entry.
    /// This method writes the specified file entry to the filesystem starting from the given directory cluster and index.
    ///
    /// # Parameters
    ///
    /// - `file_entry`: A reference to the `FatFileEntry` representing the file entry to write.
    /// - `starting_directory_cluster`: The starting cluster number of the directory where the file entry will be written.
    /// - `starting_index`: The starting index within the cluster where the file entry will be written.
    fn write_file_entry(
        &mut self,
        file_entry: &FatFileEntry,
        starting_directory_cluster: u32,
        starting_index: usize,
    ) -> Result<(), FileSystemError> {
        let mut raw_file_entries_iterator = file_entry.raw.iter().skip(1);
        let mut writing_index = starting_index;

        for cluster in self.get_clusters_for_file(starting_directory_cluster) {
            let mut file_listing = self.get_raw_file_listing_from_cluster(cluster)?;

            for file_listing in file_listing.iter_mut().skip(writing_index) {
                if let Some(raw_file_entry) = raw_file_entries_iterator.next() {
                    *file_listing = *raw_file_entry;
                } else {
                    // If there's no more entries left, write SFN at the end (SFN is always at first index
                    // in the raw array.
                    *file_listing = file_entry.raw[0];

                    writing_index += 1;

                    break;
                }
            }

            self.save_listing_to_the_disk(cluster, file_listing)?;
        }

        // Make sure we've written all entries
        assert_eq!(raw_file_entries_iterator.len(), 0);

        Ok(())
    }

    /// Removes a file entry.
    /// This method removes the specified file entry located in the given directory cluster.
    ///
    /// # Parameters
    ///
    /// - `file_entry`: A reference to the `FatFileEntry` representing the file entry to remove.
    /// - `directory_cluster`: The cluster number of the directory from which the file entry will be removed.
    pub(crate) fn remove_file_entry(
        &mut self,
        file_entry: &FatFileEntry,
        directory_cluster: u32,
    ) -> Result<(), FileSystemError> {
        let mut lfn_handling = false;
        let is_lfn = file_entry.raw.len() > 1;

        for cluster in self.get_clusters_for_file(directory_cluster).rev() {
            let mut file_listing = self.get_raw_file_listing_from_cluster(cluster)?;
            let size = file_listing.len();

            // @TODO: Maybe optimize writes?
            for (index, entry) in file_listing.clone().into_iter().rev().enumerate() {
                if entry.name == file_entry.raw[0].name {
                    // found

                    // Zero and mark current entry as free
                    file_listing[size - index - 1] = RawFatFileEntry::default();

                    file_listing[size - index - 1].name[0] = FAT_FREE_ENTRY;

                    // Save modified listing to the disk
                    self.save_listing_to_the_disk(cluster, file_listing.clone())?;

                    if !is_lfn {
                        // Our job is done here because it's single entry
                        break;
                    } else {
                        lfn_handling = true;

                        continue;
                    }
                }

                if lfn_handling {
                    let attributes = FatFileAttributes::from_bits(entry.attr)
                        .expect("Failed to parse attributes");

                    if attributes.is_long_name_entry() {
                        // Zero and mark current entry as free
                        file_listing[size - index - 1] = RawFatFileEntry::default();
                        file_listing[size - index - 1].name[0] = FAT_FREE_ENTRY;

                        // Save modified listing to the disk
                        self.save_listing_to_the_disk(cluster, file_listing.clone())?;
                    } else {
                        break;
                    }
                }
            }
        }

        Ok(())
    }

    /// Saves a listing of raw file entries to the disk.
    /// This method writes the provided raw file entries to the disk starting from the specified cluster.
    ///
    /// # Parameters
    ///
    /// - `cluster`: The cluster number where the file listing will be saved.
    /// - `file_listing`: A reference to a vector containing the raw file entries to save.
    fn save_listing_to_the_disk(
        &mut self,
        cluster: u32,
        file_listing: Vec<RawFatFileEntry>,
    ) -> Result<(), FileSystemError> {
        let raw_file_listing = RawFileListing {
            files: file_listing,
        };

        let mut buffer = BitVec::with_capacity(
            // `BitVec::with_capacity` takes the amount of bits, not bytes, so we have to multiply by 8
            (self.bpb.bytes_per_sector * self.bpb.sectors_per_cluster as u16 * 8) as usize,
        );

        raw_file_listing
            .write(&mut buffer, ())
            .expect("Failed to write RawFileListing");

        self.write_cluster(cluster, buffer.as_raw_slice())?;

        Ok(())
    }

    /// Finds a contiguous block of free file entries within a directory.
    /// This method searches for a specified number of contiguous, free file entries within the directory starting from the given cluster.
    ///
    /// # Parameters
    ///
    /// - `directory_cluster`: The cluster number of the directory where to search for contiguous file entries.
    /// - `n`: The number of contiguous file entries to find.
    ///
    /// # Returns
    ///
    /// An `Option` which is:
    /// - `Some((directory_cluster, index))` containing the cluster number of the directory and the starting index of the contiguous file entries within the directory on success.
    /// - `None` if no contiguous block of free file entries of size `n` is found within the directory.
    fn find_contiguous_file_entries_in_directory(
        &mut self,
        directory_cluster: u32,
        n: usize,
    ) -> Option<(u32, usize)> {
        assert!(n < 20);

        let mut currently_contiguous_entries_count = 0;
        let mut currently_contiguous_chain_starting_index = None;

        for cluster in self.get_clusters_for_file(directory_cluster) {
            let listing = self
                .get_raw_file_listing_from_cluster(cluster)
                .expect("Failed to get file listing from cluster");

            for (idx, entry) in listing.iter().enumerate() {
                let first_byte = entry.name[0];

                if first_byte == 0x00 {
                    // It's last entry in the directory
                    return None;
                }

                if first_byte == FAT_FREE_ENTRY {
                    if currently_contiguous_chain_starting_index.is_none() {
                        currently_contiguous_chain_starting_index = Some(idx as i32);
                    }

                    currently_contiguous_entries_count += 1;

                    if currently_contiguous_entries_count == n {
                        // Safety: Safe, because starting index is Some() every time entries_count
                        // is bigger than 0
                        return Some((
                            cluster,
                            currently_contiguous_chain_starting_index.unwrap() as usize,
                        ));
                    }
                } else {
                    // It's not 0x00 nor FREE_ENTRY mark, so probably a valid entry
                    currently_contiguous_entries_count = 0;
                    currently_contiguous_chain_starting_index = None;
                }
            }
        }

        None
    }

    /// Allocates a specified number of file entries within a directory in the FAT (File Allocation Table) filesystem.
    /// This method allocates contiguous file entries within the directory starting from the specified cluster.
    ///
    /// # Parameters
    ///
    /// - `directory_cluster`: The cluster number of the directory where to allocate file entries.
    /// - `n`: The number of file entries to allocate contiguously within the directory.
    ///
    /// # Returns
    ///
    /// A `Result` which is:
    /// - `Ok((directory_cluster, index))` containing the cluster number of the directory and the starting index of the allocated file entries within the directory on success.
    /// - `Err(FileSystemError)` if the allocation operation fails.
    fn allocate_file_entries_in_directory(
        &mut self,
        directory_cluster: u32,
        n: usize,
    ) -> Result<(u32, usize), FileSystemError> {
        let mut chain_found = false;
        let mut chain_size = 0;
        let mut starting_cluster = 0;
        let mut starting_index = 0;

        let clusters = self.get_clusters_for_file(directory_cluster);

        for cluster in clusters.clone() {
            for (index, entry) in self
                .get_raw_file_listing_from_cluster(cluster)?
                .iter()
                .enumerate()
            {
                let first_byte = entry.name[0];

                if first_byte == FAT_FREE_SECTOR as u8 || first_byte == FAT_FREE_ENTRY {
                    if !chain_found {
                        chain_found = true;
                        starting_cluster = cluster;
                        starting_index = index;
                    }

                    chain_size += 1;

                    if chain_size == n {
                        return Ok((starting_cluster, starting_index));
                    }

                    continue;
                } else if chain_found {
                    chain_found = false;
                    chain_size = 0;
                    starting_cluster = 0;
                    starting_index = 0;
                }
            }
        }

        if chain_size == n {
            return Ok((starting_cluster, starting_index));
        }

        // There's no sufficient entries in directory so need to allocate some
        let current_last_cluster = clusters.last().unwrap();
        let first_new_cluster = self.allocate_and_link_clusters(1)?.next().unwrap().0;

        self.file_allocation_table[current_last_cluster as usize] = first_new_cluster as u32;

        if chain_found {
            Ok((starting_cluster, starting_index))
        } else {
            Ok((first_new_cluster as u32, 0))
        }
    }

    /// Retrieves the current date and time.
    ///
    /// This method obtains the current date and time from the time source encapsulated
    /// within the struct.
    ///
    /// # Returns
    ///
    /// A `NaiveDateTime` representing the current date and time.
    pub fn current_datetime(&self) -> NaiveDateTime {
        self.time_source.now()
    }
}

impl FileSystem for Rc<RefCell<Fat>> {
    type File = FatFile;
    type Directory = FatDirectory;

    fn open_file(&self, path: &str) -> Result<Self::File, FileSystemError> {
        let fat = RefCell::borrow(self);

        let (entry, entry_cluster) = fat.get_by_path(path)?;

        if entry.attr().is_directory() {
            return Err(FileSystemError::NotAFile);
        }

        Ok(FatFile {
            filesystem: Rc::clone(self),
            starting_cluster: (((entry.sfn().first_cluster_high as u32) << 16)
                | entry.sfn().first_cluster_low as u32),
            file_size: entry.file_size,
            file_entry: entry,
            file_entry_cluster: entry_cluster,
        })
    }

    fn open_directory(&self, path: &str) -> Result<Self::Directory, FileSystemError> {
        let fat = RefCell::borrow(self);

        let (entry, entry_cluster) = fat.get_by_path(path)?;

        if !entry.attr().is_directory() {
            return Err(FileSystemError::NotADirectory);
        }

        Ok(FatDirectory {
            filesystem: Rc::clone(self),
            content_cluster: (((entry.sfn().first_cluster_high as u32) << 16)
                | entry.sfn().first_cluster_low as u32),
            file_entry: entry,
            file_entry_cluster: entry_cluster,
        })
    }
}

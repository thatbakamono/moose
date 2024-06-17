use chrono::NaiveDateTime;
use core::slice::SlicePattern;
use libm::ceil;
use std::cell::RefCell;
use std::cmp::min;
use std::rc::Rc;

use crate::fat32::directory::FatDirectory;
use crate::fat32::{FatFileAttributes, FatFileEntry, RawFatFileEntry};
use crate::{Attributes, File, FileSystemError};

use super::fat::Fat;

pub struct FatFile {
    pub(crate) filesystem: Rc<RefCell<Fat>>,
    pub(crate) starting_cluster: u32,
    pub(crate) file_size: u32,
    pub(crate) file_entry: FatFileEntry,
    pub(crate) file_entry_cluster: u32,
}

impl File for FatFile {
    type Directory = FatDirectory;

    fn read(&mut self, offset: usize, buffer: &mut [u8]) -> Result<(), FileSystemError> {
        assert!(!buffer.is_empty());

        if (offset + buffer.len()) > (self.file_size as usize) {
            return Err(FileSystemError::NotFound);
        }

        let cluster_size = (self.filesystem.borrow().bpb.sectors_per_cluster as u16
            * self.filesystem.borrow().bpb.bytes_per_sector) as usize;
        let clusters_to_skip = libm::floorf((offset / cluster_size) as f32) as usize;
        let mut offset_within_cluster = offset % cluster_size;

        let mut to_read = buffer.len();
        let mut reading_offset = 0;

        for cluster in self
            .filesystem
            .borrow()
            .get_clusters_for_file(self.starting_cluster)
            .skip(clusters_to_skip)
        {
            if to_read == 0 {
                break;
            }

            let copy_size = min(to_read, cluster_size - offset_within_cluster);

            if offset_within_cluster == 0 {
                if copy_size < cluster_size {
                    let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
                    let mut temp_slice = temp_buffer.as_mut_slice();

                    // Copy whole cluster to the temporary buffer
                    self.filesystem
                        .borrow()
                        .read_cluster_to(cluster, temp_slice);

                    // Copy from temporary_buffer[offset:] to the user supplied buffer
                    buffer[reading_offset..(reading_offset + copy_size)]
                        .copy_from_slice(&temp_slice[0..copy_size]);

                    to_read -= copy_size;
                    reading_offset += copy_size;

                    // Start next read from first byte of next cluster
                    offset_within_cluster = 0;
                } else {
                    self.filesystem.borrow().read_cluster_to(
                        cluster,
                        &mut buffer[reading_offset..(reading_offset + cluster_size)],
                    );

                    to_read -= cluster_size;
                    reading_offset += cluster_size;
                }
            } else {
                let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
                let mut temp_slice = temp_buffer.as_mut_slice();

                // Copy whole cluster to the temporary buffer
                self.filesystem
                    .borrow()
                    .read_cluster_to(cluster, temp_slice);

                // Copy from temporary_buffer[offset:] to the user supplied buffer
                buffer[reading_offset..(reading_offset + copy_size)].copy_from_slice(
                    &temp_slice[offset_within_cluster..(offset_within_cluster + copy_size)],
                );

                to_read -= copy_size;
                reading_offset += copy_size;

                // Start next read from first byte of next cluster
                offset_within_cluster = 0;
            }
        }

        assert_eq!(to_read, 0);

        Ok(())
    }

    fn write(&mut self, offset: usize, buffer: &[u8]) -> Result<(), FileSystemError> {
        // Writing n bytes after end of the file is forbidden
        assert!(offset <= self.file_size as usize);

        let cluster_size = (self.filesystem.borrow().bpb.sectors_per_cluster as u16
            * self.filesystem.borrow().bpb.bytes_per_sector) as usize;
        let clusters_to_skip = libm::floorf((offset / cluster_size) as f32) as usize;
        let mut offset_within_cluster = offset % cluster_size;

        let mut to_write = buffer.len();
        let mut writing_offset = 0;
        let clusters = self
            .filesystem
            .borrow()
            .get_clusters_for_file(self.starting_cluster)
            .skip(clusters_to_skip);
        let last_cluster = clusters.clone().last().unwrap();

        for cluster in clusters {
            if to_write == 0 {
                break;
            }

            let copy_size = min(to_write, cluster_size - offset_within_cluster);

            if offset_within_cluster == 0 {
                if copy_size < cluster_size {
                    let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
                    let mut temp_slice = temp_buffer.as_mut_slice();

                    // Copy whole cluster to the temporary buffer
                    self.filesystem
                        .borrow()
                        .read_cluster_to(cluster, temp_slice);

                    // Overwrite read cluster with user supplied data starting at the writing_offset
                    temp_slice[0..copy_size]
                        .copy_from_slice(&buffer[writing_offset..(writing_offset + copy_size)]);

                    // Write cluster to the disk
                    self.filesystem.borrow().write_cluster(cluster, temp_slice);

                    to_write -= copy_size;
                    writing_offset += copy_size;

                    // Start next read from first byte of next cluster
                    offset_within_cluster = 0;
                } else {
                    self.filesystem.borrow().write_cluster(
                        cluster,
                        &buffer[writing_offset..(writing_offset + cluster_size)],
                    );

                    to_write -= cluster_size;
                    writing_offset += cluster_size;
                }
            } else {
                let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
                let mut temp_slice = temp_buffer.as_mut_slice();

                // Copy whole cluster to the temporary buffer
                self.filesystem
                    .borrow()
                    .read_cluster_to(cluster, temp_slice);

                // Overwrite read cluster with user supplied data starting at the writing_offset
                temp_slice[offset_within_cluster..(offset_within_cluster + copy_size)]
                    .copy_from_slice(&buffer[writing_offset..(writing_offset + copy_size)]);

                // Write cluster to the disk
                self.filesystem.borrow().write_cluster(cluster, temp_slice);

                to_write -= copy_size;
                writing_offset += copy_size;

                // Start next read from first byte of next cluster
                offset_within_cluster = 0;
            }
        }

        if self.file_size < (offset + buffer.len()) as u32 {
            // Adjust filesize in file entry
            let difference = (offset + buffer.len()) - self.file_size as usize;

            let old_file_entry = self.file_entry.clone();
            let mut new_file_entry = old_file_entry.clone();
            new_file_entry.file_size += difference as u32;
            self.file_size += difference as u32;

            self.filesystem.borrow_mut().serialize_file_entry(
                Some(&old_file_entry),
                &new_file_entry,
                self.file_entry_cluster,
            );

            self.file_entry = new_file_entry;
        }

        if to_write == 0 {
            return Ok(());
        }

        // Data does not fit into current file, so need to allocate new clusters at the end of the file
        let needed_clusters = ceil((to_write / cluster_size) as f64) as usize;
        let allocated_clusters: Vec<(usize, u32)> = self
            .filesystem
            .borrow_mut()
            .allocate_and_link_clusters(needed_clusters)?
            .collect();

        // Link current last cluster to the newly allocated chain of clusters
        self.filesystem.borrow_mut().file_allocation_table[last_cluster as usize] =
            allocated_clusters.first().unwrap().0 as u32;

        // Perform write
        for new_cluster in allocated_clusters {
            let mut temp_buffer: Vec<u8> = vec![0; cluster_size];
            let mut temp_slice = temp_buffer.as_mut_slice();
            let copy_size = min(to_write, cluster_size) - 1;

            // Overwrite read cluster with user supplied data starting at the writing_offset
            temp_slice[0..copy_size]
                .copy_from_slice(&buffer[writing_offset..(writing_offset + copy_size)]);

            // Write cluster to the disk
            self.filesystem
                .borrow()
                .write_cluster(new_cluster.0 as u32, temp_slice);

            to_write -= copy_size;
            writing_offset += copy_size;
        }

        Ok(())
    }

    fn delete(&mut self) -> Result<(), FileSystemError> {
        let mut fat = self.filesystem.borrow_mut();

        fat.remove_file_entry(&self.file_entry, self.file_entry_cluster);
        fat.mark_clusters_as_free(self.starting_cluster);

        Ok(())
    }

    fn rename(&mut self, name: &str) -> Result<(), FileSystemError> {
        let old = self.file_entry.clone();

        self.file_entry.set_name(name.to_string());

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&old),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn move_to(&mut self, directory: &Self::Directory) -> Result<(), FileSystemError> {
        self.filesystem.borrow_mut().move_file(
            &self.file_entry,
            directory,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn shrink(&mut self, new_size: usize) -> Result<(), FileSystemError> {
        todo!()
    }

    fn set_creation_datetime(
        &mut self,
        creation_datetime: NaiveDateTime,
    ) -> Result<(), FileSystemError> {
        self.file_entry.set_creation_time(creation_datetime);

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&self.file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn set_modification_datetime(
        &mut self,
        modification_datetime: NaiveDateTime,
    ) -> Result<(), FileSystemError> {
        self.file_entry.set_last_write_time(modification_datetime);

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&self.file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn set_attributes(&mut self, attributes: Attributes) -> Result<(), FileSystemError> {
        self.file_entry
            .set_attr(FatFileAttributes::from(attributes));

        self.filesystem.borrow_mut().serialize_file_entry(
            Some(&self.file_entry),
            &self.file_entry,
            self.file_entry_cluster,
        );

        Ok(())
    }

    fn file_size(&self) -> usize {
        self.file_entry.file_size as usize
    }

    fn creation_date_time(&self) -> NaiveDateTime {
        self.file_entry.creation_time
    }

    fn modification_date_time(&self) -> NaiveDateTime {
        self.file_entry.last_write_time
    }

    fn attributes(&self) -> Attributes {
        Attributes::from(self.file_entry.attr)
    }

    fn name(&self) -> &str {
        &self.file_entry.name
    }
}

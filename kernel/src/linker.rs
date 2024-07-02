use goblin::elf::{
    program_header::{self, PF_R, PF_W, PF_X},
    Elf,
};

use crate::{
    memory::{MemoryManager, Page, PageFlags, PageTable, VirtualAddress, PAGE_SIZE},
    Cursor, Read,
};

pub struct Linker;

impl Linker {
    pub fn link(
        binary: &[u8],
        memory_manager: &mut MemoryManager,
        page_table: &mut PageTable,
    ) -> u64 {
        let elf = Elf::parse(binary).unwrap();

        if !elf.is_64 {
            panic!("Unsupported architecture");
        }

        if elf.is_lib {
            panic!();
        }

        if !elf.little_endian {
            panic!("Unsupported endianness");
        }

        if !elf.libraries.is_empty() {
            unimplemented!();
        }

        if !elf.shdr_relocs.is_empty() {
            unimplemented!();
        }

        if !elf.pltrelocs.is_empty() {
            unimplemented!();
        }

        if !elf.dynrels.is_empty() {
            unimplemented!();
        }

        if !elf.dynrelas.is_empty() {
            unimplemented!();
        }

        if !elf.dynsyms.is_empty() {
            unimplemented!();
        }

        let mut reader = Cursor::new(binary);
        let mut buffer = [0u8; PAGE_SIZE];

        for header in elf.program_headers {
            if header.p_type == program_header::PT_LOAD {
                if header.p_flags & PF_R == 0 {
                    unimplemented!();
                }

                if header.p_align != PAGE_SIZE as u64 {
                    unimplemented!();
                }

                let required_frames =
                    (header.p_filesz + (PAGE_SIZE as u64 - 1)) as usize / PAGE_SIZE;

                for _ in 0..required_frames {
                    reader.seek(header.p_offset);

                    let read = reader.read(&mut buffer).unwrap();

                    let page =
                        Page::new(VirtualAddress::new(header.p_vaddr & 0xfff_ffff_ffff_f000));
                    let frame = memory_manager.allocate_frame().unwrap();

                    let offset = header.p_vaddr - (header.p_vaddr & 0xfff_ffff_ffff_f000);

                    unsafe {
                        memory_manager
                            .map_any_temporary_for_current_address_space(
                                &frame,
                                PageFlags::WRITABLE,
                                |page| {
                                    let destination = page.address().as_mut_ptr::<u8>();

                                    for i in 0..read {
                                        *destination.add(offset as usize + i) = buffer[i];
                                    }
                                },
                            )
                            .unwrap();

                        let mut flags = PageFlags::USER_MODE_ACCESSIBLE;

                        if header.p_flags & PF_W != 0 {
                            flags |= PageFlags::WRITABLE;
                        }

                        if header.p_flags & PF_X != 0 {
                            flags |= PageFlags::EXECUTABLE;
                        }

                        memory_manager
                            .map(page_table, &page, &frame, flags)
                            .unwrap();
                    }
                }
            }
        }

        elf.entry
    }
}

use core::{
    alloc::Layout,
    ffi::c_void,
    mem,
    sync::atomic::{AtomicUsize, Ordering},
};

use alloc::{boxed::Box, vec, vec::Vec};
use x86_64::registers::{
    rflags,
    segmentation::{Segment64, GS},
};

use crate::{
    linker::Linker,
    memory::{
        current_page_table, memory_manager, Frame, Page, PageFlags, PageTable, VirtualAddress,
    },
    scheduler::Scheduler,
    Stack, KERNEL_ADDRESS_REQUEST,
};

static CURRENT_USABLE_PROCESS_ID: AtomicUsize = AtomicUsize::new(0);
static CURRENT_USABLE_THREAD_ID: AtomicUsize = AtomicUsize::new(0);

static mut PROCESSES: Vec<Process> = Vec::new();

pub type ProcessId = usize;

pub struct Process {
    id: ProcessId,
    pub(crate) page_table: *mut PageTable,
    pub(crate) page_table_physical_address: u64,
    threads: Vec<Thread>,
}

impl Process {
    pub fn new(program: &[u8], physical_memory_offset: u64, interrupt_stack: *mut Stack) -> &Self {
        let id = CURRENT_USABLE_PROCESS_ID.fetch_add(1, Ordering::SeqCst);

        let program_page_table = Box::leak(Box::new(PageTable::new()));
        let stack =
            unsafe { alloc::alloc::alloc_zeroed(Layout::new::<ThreadStack>()) } as *mut ThreadStack;

        let mut memory_manager = memory_manager().write();

        let program_page_table_physical_address = memory_manager
            .translate_virtual_address_to_physical_for_current_address_space(VirtualAddress::new(
                program_page_table as *const _ as u64,
            ))
            .unwrap()
            .as_u64();

        // map kernel in program's address space
        {
            let kernel_virtual_base_address = KERNEL_ADDRESS_REQUEST
                .get_response()
                .unwrap()
                .virtual_base();

            let kernel_level_4_page_table_entry_index =
                ((kernel_virtual_base_address >> 39) & 0b1_1111_1111) as usize;

            let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

            let level_4_page_table_entry =
                &unsafe { &*kernel_page_table }[kernel_level_4_page_table_entry_index];

            program_page_table[kernel_level_4_page_table_entry_index]
                .set_address(level_4_page_table_entry.address());
            program_page_table[kernel_level_4_page_table_entry_index]
                .set_flags(level_4_page_table_entry.flags());
        }

        // map kernel's stack in program's address space | FIXME (XD!)
        {
            let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

            let level_4_page_table_entry = &unsafe { &*kernel_page_table }[256];

            program_page_table[256].set_address(level_4_page_table_entry.address());
            program_page_table[256].set_flags(level_4_page_table_entry.flags());
        }

        // map kernel's heap in program's address space | FIXME (XD!)
        {
            let kernel_page_table = unsafe { current_page_table(physical_memory_offset) };

            let level_4_page_table_entry = &unsafe { &*kernel_page_table }[136];

            program_page_table[136].set_address(level_4_page_table_entry.address());
            program_page_table[136].set_flags(level_4_page_table_entry.flags());
        }

        // remap interrupt's stack in program's address space
        {
            for page_index in 0..4 {
                let interrupt_stack_virtual_address =
                    VirtualAddress::new(interrupt_stack as u64 + (page_index * 4096));
                let interrupt_stack_physical_address = memory_manager
                    .translate_virtual_address_to_physical_for_current_address_space(
                        interrupt_stack_virtual_address,
                    )
                    .unwrap();

                unsafe {
                    memory_manager
                        .unmap(
                            program_page_table,
                            &Page::new(interrupt_stack_virtual_address),
                        )
                        .unwrap();

                    memory_manager
                        .map(
                            program_page_table,
                            &Page::new(interrupt_stack_virtual_address),
                            &Frame::new(interrupt_stack_physical_address),
                            PageFlags::WRITABLE,
                        )
                        .unwrap();
                }
            }
        }

        let entry_point = Linker::link(program, &mut memory_manager, program_page_table);

        // remap program's stack in program's address space
        {
            for page_index in 0..4 {
                let stack_virtual_address = VirtualAddress::new(stack as u64 + (page_index * 4096));
                let stack_physical_address = memory_manager
                    .translate_virtual_address_to_physical_for_current_address_space(
                        stack_virtual_address,
                    )
                    .unwrap();

                unsafe {
                    memory_manager
                        .unmap(program_page_table, &Page::new(stack_virtual_address))
                        .unwrap();

                    memory_manager
                        .map(
                            program_page_table,
                            &Page::new(stack_virtual_address),
                            &Frame::new(stack_physical_address),
                            PageFlags::USER_MODE_ACCESSIBLE | PageFlags::WRITABLE,
                        )
                        .unwrap();
                }
            }
        }

        let threads = vec![Thread::new(
            id,
            entry_point as *const c_void,
            Registers {
                rip: entry_point,
                rsp: stack as u64 + mem::size_of::<ThreadStack>() as u64 - 16,
                cs: (7 << 3) | 3,
                ss: (8 << 3) | 3,
                gs: GS::read_base().as_u64(),
                rflags: rflags::read_raw(),
                ..Default::default()
            },
            stack,
        )];

        let process = Self {
            id,
            page_table: program_page_table,
            page_table_physical_address: program_page_table_physical_address,
            threads,
        };

        unsafe { PROCESSES.push(process) };

        unsafe { PROCESSES.last().unwrap() }
    }

    pub fn get_by_id<'a>(id: ProcessId) -> &'a Process {
        unsafe { PROCESSES.iter().find(|process| process.id == id).unwrap() }
    }

    pub fn start(&self) {
        Scheduler::schedule(&self.threads[0]);
    }
}

pub type ThreadId = usize;

pub struct Thread {
    process_id: ProcessId,
    id: ThreadId,
    pub(crate) entry: *const c_void,
    pub(crate) registers: Registers,
    pub(crate) stack: *mut ThreadStack,
}

impl Thread {
    fn new(
        process_id: ProcessId,
        entry: *const c_void,
        registers: Registers,
        stack: *mut ThreadStack,
    ) -> Self {
        let id = CURRENT_USABLE_THREAD_ID.fetch_add(1, Ordering::SeqCst);

        Self {
            process_id,
            id,
            entry,
            registers,
            stack,
        }
    }

    pub fn get_by_id<'a>(id: ThreadId) -> &'a Thread {
        unsafe {
            PROCESSES
                .iter()
                .flat_map(|process| &process.threads)
                .find(|thread| thread.id == id)
                .unwrap()
        }
    }

    pub fn get_by_id_mut<'a>(id: ThreadId) -> &'a mut Thread {
        unsafe {
            PROCESSES
                .iter_mut()
                .flat_map(|process| &mut process.threads)
                .find(|thread| thread.id == id)
                .unwrap()
        }
    }

    pub fn id(&self) -> ThreadId {
        self.id
    }

    pub fn process(&self) -> &Process {
        Process::get_by_id(self.process_id)
    }
}

#[repr(C)]
#[repr(align(4096))]
pub(crate) struct ThreadStack([u8; 16 * 1024]);

impl ThreadStack {
    fn new() -> Self {
        Self([0; 16 * 1024])
    }
}

#[derive(Clone, Debug, Default)]
#[repr(C, packed)]
pub struct Registers {
    pub(crate) rax: u64,
    pub(crate) rbx: u64,
    pub(crate) rcx: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rbp: u64,
    pub(crate) rsp: u64,
    pub(crate) r8: u64,
    pub(crate) r9: u64,
    pub(crate) r10: u64,
    pub(crate) r11: u64,
    pub(crate) r12: u64,
    pub(crate) r13: u64,
    pub(crate) r14: u64,
    pub(crate) r15: u64,
    pub(crate) rip: u64,
    pub(crate) rflags: u64,
    pub(crate) cs: u16,
    pub(crate) ss: u16,
    pub(crate) fs: u64,
    pub(crate) gs: u64,
}

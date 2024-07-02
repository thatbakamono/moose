use core::{arch::asm, mem};

use alloc::collections::VecDeque;
use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::{PhysFrame, Size4KiB},
    PhysAddr,
};

use crate::{
    memory::{memory_manager, VirtualAddress},
    process::{Thread, ThreadId, ThreadStack},
};

static mut THREAD_QUEUE: VecDeque<ThreadId> = VecDeque::new();

pub struct Scheduler;

impl Scheduler {
    pub fn run() -> ! {
        let thread_id = *unsafe { THREAD_QUEUE.front() }.unwrap();

        let thread = Thread::get_by_id(thread_id);
        let process = thread.process();

        let memory_manager = memory_manager().read();

        // switch page table
        {
            let program_page_table_physical_address = memory_manager
                .translate_virtual_address_to_physical_for_current_address_space(
                    VirtualAddress::new(process.page_table as *const _ as u64),
                )
                .unwrap()
                .as_u64();

            let program_page_table_frame = PhysFrame::<Size4KiB>::from_start_address(
                PhysAddr::new(program_page_table_physical_address),
            )
            .unwrap();

            unsafe { Cr3::write(program_page_table_frame, Cr3Flags::empty()) };
        }

        enter_user_mode(thread.entry as *const _, unsafe {
            (thread.stack as *const u8)
                .add(mem::size_of::<ThreadStack>())
                .offset(-16)
        });
    }

    pub fn current_thread<'a>() -> &'a Thread {
        Thread::get_by_id(*unsafe { THREAD_QUEUE.front() }.unwrap())
    }

    pub fn current_thread_mut<'a>() -> &'a mut Thread {
        Thread::get_by_id_mut(*unsafe { THREAD_QUEUE.front() }.unwrap())
    }

    pub(crate) fn finish_execution() {
        let thread_id = unsafe { THREAD_QUEUE.pop_front() }.unwrap();

        unsafe { THREAD_QUEUE.push_back(thread_id) };
    }

    pub(crate) fn schedule(thread: &Thread) {
        unsafe {
            THREAD_QUEUE.push_back(thread.id());
        }
    }
}

extern "C" fn enter_user_mode(program: *const u8, stack: *const u8) -> ! {
    unsafe {
        asm!(
            "
                mov ds, {data_segment:r}
                mov es, {data_segment:r}

                push (8 << 3) | 3
                push {stack}
                pushf
                push (7 << 3) | 3
                push {program}

                iretq
            ",
            data_segment = in(reg) (8 << 3) | 3,
            program = in(reg) program,
            stack = in(reg) stack,
            options(noreturn)
        );
    };
}

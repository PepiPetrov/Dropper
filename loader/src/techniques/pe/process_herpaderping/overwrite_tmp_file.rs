use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Storage::FileSystem::{
        FILE_BEGIN, FlushFileBuffers, GetFileSize, ReadFile, SetEndOfFile, SetFilePointer,
        WriteFile,
    },
    System::Memory::{LPTR, LocalAlloc, LocalFree},
};

use crate::log;

pub unsafe fn overwrite_tmp_file(
    h_source_file: Option<isize>,
    p_source_buffer: Option<*const u8>,
    dw_source_buffer_size: Option<u32>,
    h_destination_file: isize,
    b_overwrite_by_handle: bool,
) -> bool {
    unsafe {
        if h_destination_file == 0 || h_destination_file == INVALID_HANDLE_VALUE {
            return false;
        }

        if b_overwrite_by_handle {
            if h_source_file.is_none() || h_source_file.unwrap() == INVALID_HANDLE_VALUE {
                return false;
            }
        } else {
            if p_source_buffer.is_none() || dw_source_buffer_size.is_none() {
                return false;
            }
        }

        let dw_pe_file_size: u32;
        let mut dw_number_of_bytes_read: u32 = 0;
        let mut dw_number_of_bytes_written: u32 = 0;
        let p_pe_file_buffer: *mut u8;

        if b_overwrite_by_handle {
            let h_src = h_source_file.unwrap();

            dw_pe_file_size = GetFileSize(h_src, std::ptr::null_mut());
            if dw_pe_file_size == u32::MAX {
                log!("GetFileSize failed.");
                return false;
            }

            p_pe_file_buffer = LocalAlloc(LPTR, dw_pe_file_size as usize) as *mut u8;
            if p_pe_file_buffer.is_null() {
                log!("LocalAlloc failed.");
                return false;
            }

            if SetFilePointer(h_src, 0, std::ptr::null_mut(), FILE_BEGIN) == u32::MAX {
                log!("SetFilePointer [1] failed.");
                LocalFree(p_pe_file_buffer as _);
                return false;
            }

            if SetFilePointer(h_destination_file, 0, std::ptr::null_mut(), FILE_BEGIN) == u32::MAX {
                log!("SetFilePointer [2] failed.");
                LocalFree(p_pe_file_buffer as _);
                return false;
            }

            let read_result = ReadFile(
                h_src,
                p_pe_file_buffer as _,
                dw_pe_file_size,
                &mut dw_number_of_bytes_read,
                std::ptr::null_mut(),
            );

            if read_result == 0 || dw_pe_file_size != dw_number_of_bytes_read {
                log!("ReadFile failed.");
                LocalFree(p_pe_file_buffer as _);
                return false;
            }
        } else {
            dw_pe_file_size = dw_source_buffer_size.unwrap();
            p_pe_file_buffer = p_source_buffer.unwrap() as *mut u8;

            if SetFilePointer(h_destination_file, 0, std::ptr::null_mut(), FILE_BEGIN) == u32::MAX {
                log!("SetFilePointer failed.");
                return false;
            }
        }

        let write_result = WriteFile(
            h_destination_file,
            p_pe_file_buffer as _,
            dw_pe_file_size,
            &mut dw_number_of_bytes_written,
            std::ptr::null_mut(),
        );

        if write_result == 0 || dw_pe_file_size != dw_number_of_bytes_written {
            log!("WriteFile failed.");
            if b_overwrite_by_handle {
                LocalFree(p_pe_file_buffer as _);
            }
            return false;
        }

        if FlushFileBuffers(h_destination_file) == 0 {
            log!("FlushFileBuffers failed.");
            if b_overwrite_by_handle {
                LocalFree(p_pe_file_buffer as _);
            }
            return false;
        }

        if SetEndOfFile(h_destination_file) == 0 {
            log!("SetEndOfFile failed.");
            if b_overwrite_by_handle {
                LocalFree(p_pe_file_buffer as _);
            }
            return false;
        }

        if b_overwrite_by_handle {
            LocalFree(p_pe_file_buffer as _);
        }

        true
    }
}

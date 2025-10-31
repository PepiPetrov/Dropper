use ntapi::{
    ntmmapi::{MEMORY_RANGE_ENTRY, VmCfgCallTargetInformation},
    ntpsapi::NtCurrentProcess,
};
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::System::{
    Memory::{CFG_CALL_TARGET_INFO, MEM_COMMIT, MEM_IMAGE, MEMORY_BASIC_INFORMATION},
    SystemServices::CFG_CALL_TARGET_VALID,
};

use crate::call_fn;

#[repr(C)]
struct VmInformation {
    dw_number_of_offsets: u32,
    pt_offsets: *const CFG_CALL_TARGET_INFO,
    pl_output: *mut u32,
    p_must_be_zero: *mut core::ffi::c_void,
    p_moar_zero: *mut core::ffi::c_void,
}

pub unsafe fn cfg_address_add(address: usize) -> NTSTATUS {
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
        let mut return_len: usize = 0;

        let status = call_fn!(
            "ntdll",
            "NtQueryVirtualMemory",
            NtCurrentProcess,
            address,
            0, // MemoryBasicInformation
            &mut mbi as *mut _ as *mut u8,
            core::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            &mut return_len
        ) as i32;

        if status < 0 {
            return status;
        }

        if mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE {
            return status;
        }

        // Prepare the structures
        let mut output: u32 = 0;

        let offset_info = CFG_CALL_TARGET_INFO {
            Offset: address.wrapping_sub(mbi.BaseAddress as usize),
            Flags: CFG_CALL_TARGET_VALID as usize,
        };

        let mut virtual_addresses = MEMORY_RANGE_ENTRY {
            VirtualAddress: mbi.BaseAddress as _,
            NumberOfBytes: mbi.RegionSize,
        };

        let vm_info = VmInformation {
            dw_number_of_offsets: 1,
            pt_offsets: &offset_info,
            pl_output: &mut output,
            p_must_be_zero: core::ptr::null_mut(),
            p_moar_zero: core::ptr::null_mut(),
        };

        call_fn!(
            "ntdll",
            "NtSetInformationVirtualMemory",
            NtCurrentProcess,
            VmCfgCallTargetInformation,
            1,
            &mut virtual_addresses,
            &vm_info as *const _ as *const u8,
            core::mem::size_of::<VmInformation>() as u32
        ) as i32
    }
}

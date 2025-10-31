use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64},
    SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
};

pub unsafe fn resolve_function(module: usize, hash: u32) -> Option<usize> {
    unsafe {
        // Step 1: Locate the DOS and NT headers
        let dos_header = module as *const IMAGE_DOS_HEADER;
        let nt_header =
            (module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;

        // Step 2: Locate the export directory
        let export_directory_rva = (*nt_header).OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress;
        if export_directory_rva == 0 {
            return None; // No export table found
        }
        let export_directory =
            (module as usize + export_directory_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

        // Step 3: Access the arrays of function names, ordinals, and addresses
        let names_rva = (*export_directory).AddressOfNames;
        let ordinals_rva = (*export_directory).AddressOfNameOrdinals;
        let functions_rva = (*export_directory).AddressOfFunctions;
        let num_names = (*export_directory).NumberOfNames as usize;

        for i in 0..num_names {
            let name_rva = *((module as usize + names_rva as usize + i * 4) as *const u32) as usize;
            let name_ptr = (module as usize + name_rva) as *const u8;

            // Step 4: Hash the function name and compare
            let name_len = (0..).take_while(|&j| *name_ptr.offset(j) != 0).count();
            let name_slice = core::slice::from_raw_parts(name_ptr, name_len);
            if crate::hash::fnv1a_hash_fn(name_slice) == hash {
                let ordinal =
                    *((module as usize + ordinals_rva as usize + i * 2) as *const u16) as usize;
                let function_rva =
                    *((module as usize + functions_rva as usize + ordinal * 4) as *const u32);
                return Some((module as usize + function_rva as usize) as usize);
            }
        }

        None
    }
}

pub unsafe fn resolve_module(hash: u32) -> Option<usize> {
    unsafe {
        // let peb = get_peb();
        let peb: ntapi::ntpebteb::PPEB;
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, nomem)
        );
        let peb_ldr_data_ptr = (*peb).Ldr as *mut ntapi::ntpsapi::PEB_LDR_DATA;
        let mut module_list = (*peb_ldr_data_ptr).InLoadOrderModuleList.Flink
            as *mut ntapi::ntldr::LDR_DATA_TABLE_ENTRY;

        while !(*module_list).DllBase.is_null() {
            let dll_buffer_ptr = (*module_list).BaseDllName.Buffer;
            let dll_length = (*module_list).BaseDllName.Length as usize / 2;
            let dll_name_slice =
                core::slice::from_raw_parts(dll_buffer_ptr as *const u16, dll_length);

            let mut effective_len = dll_length;

            // lowercase last 4 chars and compare
            if dll_name_slice[effective_len - 4..]
                .iter()
                .copied()
                .map(|ch| ch | 0x20)
                .eq([b'.', b'd', b'l', b'l'].map(|c| c as u16))
            {
                effective_len -= 4;
            }

            if hash == crate::hash::fnv1a_hash_fn_wide(&dll_name_slice[..effective_len]) {
                return Some((*module_list).DllBase as _);
            }

            module_list =
                (*module_list).InLoadOrderLinks.Flink as *mut ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
        }

        return None;
    }
}

#[macro_export]
macro_rules! call_fn {
    ($mod:expr, $func:expr, $($args:expr),*) => {{
        // Retrieve the module using its hash
        // let module = crate::resolve::moonwalk::resolve_module(crate::hash::fnv1a_hash!($mod)).unwrap();
        let module = crate::resolve::function::resolve_module(crate::hash::fnv1a_hash!($mod)).unwrap();

        // Retrieve the function using its hash
        let function_ptr = crate::resolve::function::resolve_function(module, crate::hash::fnv1a_hash!($func)).unwrap();
        // Cast the function pointer to a callable type
        let callable: unsafe extern "C" fn(...) -> usize =
            core::mem::transmute(function_ptr);
        // Call the function with the provided arguments
        callable($($args),*)
    }};
}

pub use call_fn;

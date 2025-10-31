use core::{mem, ptr};

use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_TLS,
        IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    },
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualAlloc,
    },
    SystemServices::{
        IMAGE_BASE_RELOCATION, IMAGE_IMPORT_BY_NAME, IMAGE_IMPORT_DESCRIPTOR, IMAGE_ORDINAL_FLAG64,
        IMAGE_REL_BASED_DIR64, IMAGE_TLS_DIRECTORY64,
    },
    WindowsProgramming::IMAGE_THUNK_DATA64,
};

use super::super::pe_utils::*;

fn get_section_protection(characteristics: u32) -> u32 {
    let executable = characteristics & 0x20000000 != 0;
    let readable = characteristics & 0x40000000 != 0;
    let writable = characteristics & 0x80000000 != 0;

    match (executable, readable, writable) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        (false, false, true) => PAGE_WRITECOPY,
        _ => PAGE_NOACCESS,
    }
}

pub unsafe fn manual_map(buffer: &[u8]) {
    unsafe {
        let (dos_header, nt_headers) = parse_headers(buffer);
        let image_base = VirtualAlloc(
            ptr::null_mut(),
            (*nt_headers).OptionalHeader.SizeOfImage as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if image_base.is_null() {
            return;
        }

        // Copy headers
        ptr::copy_nonoverlapping(
            buffer.as_ptr(),
            image_base as *mut u8,
            nt_headers.OptionalHeader.SizeOfHeaders as usize,
        );

        // Copy sections
        let sections = (buffer
            .as_ptr()
            .add(dos_header.e_lfanew as usize + mem::size_of::<IMAGE_NT_HEADERS64>()))
            as *const IMAGE_SECTION_HEADER;
        for i in 0..nt_headers.FileHeader.NumberOfSections {
            let section = &*sections.add(i as usize);
            let dest = (image_base as usize + section.VirtualAddress as usize) as *mut u8;
            let src = buffer.as_ptr().add(section.PointerToRawData as usize);
            ptr::copy_nonoverlapping(src, dest, section.SizeOfRawData as usize);
        }

        // Relocations
        let delta = image_base as isize - nt_headers.OptionalHeader.ImageBase as isize;
        if delta != 0 {
            let reloc_dir =
                nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];
            if reloc_dir.VirtualAddress != 0 {
                let mut reloc = (image_base as usize + reloc_dir.VirtualAddress as usize)
                    as *mut IMAGE_BASE_RELOCATION;
                while (*reloc).VirtualAddress != 0 {
                    let count = ((*reloc).SizeOfBlock as usize
                        - mem::size_of::<IMAGE_BASE_RELOCATION>())
                        / 2;
                    let reloc_data =
                        (reloc as usize + mem::size_of::<IMAGE_BASE_RELOCATION>()) as *const u16;
                    for i in 0..count {
                        let entry = *reloc_data.add(i);
                        let typ = entry >> 12;
                        let offset = entry & 0x0FFF;
                        if u32::from(typ) == IMAGE_REL_BASED_DIR64 {
                            let patch_addr = (image_base as usize
                                + (*reloc).VirtualAddress as usize
                                + offset as usize)
                                as *mut usize;
                            *patch_addr = (*patch_addr as isize + delta) as usize;
                        }
                    }
                    reloc = (reloc as usize + (*reloc).SizeOfBlock as usize)
                        as *mut IMAGE_BASE_RELOCATION;
                }
                core::ptr::write_bytes(
                    (image_base as usize + reloc_dir.VirtualAddress as usize) as *mut u8,
                    0,
                    reloc_dir.Size as usize,
                );
            }
        }

        // IAT Resolution + Logging
        let import_dir =
            nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize];
        if import_dir.VirtualAddress != 0 {
            let mut import_desc = (image_base as usize + import_dir.VirtualAddress as usize)
                as *mut IMAGE_IMPORT_DESCRIPTOR;
            while (*import_desc).Name != 0 {
                let dll_name_ptr =
                    (image_base as usize + (*import_desc).Name as usize) as *const i8;

                let handle = LoadLibraryA(dll_name_ptr as _);
                if handle == 0 {
                    return;
                }

                let thunk_orig = (image_base as usize
                    + (*import_desc).Anonymous.OriginalFirstThunk as usize)
                    as *const IMAGE_THUNK_DATA64;
                let thunk_iat =
                    (image_base as usize + (*import_desc).FirstThunk as usize) as *mut usize;

                let mut idx = 0;
                loop {
                    let orig = *thunk_orig.add(idx);
                    if orig.u1.AddressOfData == 0 {
                        break;
                    }

                    let resolved_addr = if orig.u1.Ordinal & IMAGE_ORDINAL_FLAG64 != 0 {
                        // Ordinal import
                        let ordinal = (orig.u1.Ordinal & 0xFFFF) as usize;
                        GetProcAddress(handle, ordinal as _).unwrap() as usize
                    } else {
                        // Import by name
                        let import_by_name = (image_base as usize + orig.u1.AddressOfData as usize)
                            as *const IMAGE_IMPORT_BY_NAME;
                        let func_name_ptr = &(*import_by_name).Name as *const u8;
                        GetProcAddress(handle, func_name_ptr).unwrap() as usize
                    };

                    *thunk_iat.add(idx) = resolved_addr;
                    idx += 1;
                }

                import_desc = import_desc.add(1);
            }
        }

        for i in 0..nt_headers.FileHeader.NumberOfSections {
            let section = &*sections.add(i as usize);
            let dest = (image_base as usize + section.VirtualAddress as usize) as *mut u8;

            let size = if section.Misc.VirtualSize != 0 {
                section.Misc.VirtualSize
            } else {
                section.SizeOfRawData
            } as usize;

            let protection = get_section_protection(section.Characteristics);
            let mut old = 0;
            windows_sys::Win32::System::Memory::VirtualProtect(
                dest as _, size, protection, &mut old,
            );
        }

        let tls_dir = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS as usize];
        if tls_dir.VirtualAddress != 0 {
            let tls = (image_base as usize + tls_dir.VirtualAddress as usize)
                as *const IMAGE_TLS_DIRECTORY64;

            let callback_ptr = (*tls).AddressOfCallBacks as *const usize;
            if !callback_ptr.is_null() {
                let mut current = callback_ptr;
                while *current != 0 {
                    let callback: extern "system" fn(usize, u32, usize) =
                        core::mem::transmute(*current);
                    callback(image_base as usize, 1 /* DLL_PROCESS_ATTACH */, 0);
                    current = current.add(1);
                }
            }
        }

        // Return entry point
        let ep = image_base as usize + nt_headers.OptionalHeader.AddressOfEntryPoint as usize;
        mem::transmute::<usize, extern "system" fn()>(ep)();
    }
}

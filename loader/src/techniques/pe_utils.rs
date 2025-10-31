use windows_sys::Win32::System::{
    Diagnostics::Debug::{
        IMAGE_NT_HEADERS64, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
        IMAGE_SECTION_HEADER,
    },
    Memory::{
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY,
    },
    SystemServices::IMAGE_DOS_HEADER,
};

pub fn parse_headers<'a>(buffer: &'a [u8]) -> (&'a IMAGE_DOS_HEADER, &'a IMAGE_NT_HEADERS64) {
    let dos_header = unsafe { &*(buffer.as_ptr() as *const IMAGE_DOS_HEADER) };

    let nt_headers = unsafe {
        let nt_offset = dos_header.e_lfanew as usize;
        &*(buffer.as_ptr().add(nt_offset) as *const IMAGE_NT_HEADERS64)
    };

    (dos_header, nt_headers)
}

pub fn get_section_headers<'a>(nt_headers: &'a IMAGE_NT_HEADERS64) -> &'a [IMAGE_SECTION_HEADER] {
    let nt_headers_ptr = nt_headers as *const IMAGE_NT_HEADERS64 as usize;
    let section_header_ptr = (nt_headers_ptr + core::mem::size_of::<IMAGE_NT_HEADERS64>())
        as *const IMAGE_SECTION_HEADER;

    let section_count = nt_headers.FileHeader.NumberOfSections as usize;

    unsafe { core::slice::from_raw_parts(section_header_ptr, section_count) }
}

pub fn get_section_protection(characteristics: u32) -> u32 {
    let has_read = characteristics & IMAGE_SCN_MEM_READ != 0; // IMAGE_SCN_MEM_READ
    let has_write = characteristics & IMAGE_SCN_MEM_WRITE != 0; // IMAGE_SCN_MEM_WRITE
    let has_exec = characteristics & IMAGE_SCN_MEM_EXECUTE != 0; // IMAGE_SCN_MEM_EXECUTE

    match (has_exec, has_write, has_read) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_WRITECOPY,
        (true, false, true) => PAGE_EXECUTE_READ,
        (true, false, false) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_WRITECOPY,
        (false, false, true) => PAGE_READONLY,
        _ => PAGE_READONLY, // Default fallback
    }
}

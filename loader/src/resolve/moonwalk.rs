use core::{arch::asm, cell::Cell, ptr};

use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

use super::hash::*;

thread_local! {
    static STACK_BASE: Cell<u64> = Cell::new(0);
    static STACK_LIMIT: Cell<u64> = Cell::new(0);
    static TEB_ADDRESS: Cell<u64> = Cell::new(0);
}

const MIN_ADDRESS: u64 = 0x10000; // Skip first 64KB
const MAX_ADDRESS: u64 = 0x7FFFFFFFFFFF; // Max user-mode address on Windows x64

// Memory regions that would never contain a DLL
const SKIP_REGIONS: &[(u64, u64)] = &[
    (0x0000000000000000, 0x000000000000FFFF), // NULL page
    (0x0000000000010000, 0x000000000001FFFF), // First 64KB
    (0x0000000000020000, 0x000000000002FFFF), // Second 64KB
    (0x0000000000030000, 0x000000000003FFFF), // Third 64KB
    (0x0000000000040000, 0x000000000004FFFF), // Fourth 64KB
    (0x0000000000050000, 0x000000000005FFFF), // Fifth 64KB
    (0x0000000000060000, 0x000000000006FFFF), // Sixth 64KB
    (0x0000000000070000, 0x000000000007FFFF), // Seventh 64KB
    (0x0000000000080000, 0x000000000008FFFF), // Eighth 64KB
    (0x0000000000090000, 0x000000000009FFFF), // Ninth 64KB
    (0x00000000000A0000, 0x00000000000AFFFF), // Tenth 64KB
    (0x00000000000B0000, 0x00000000000BFFFF), // Eleventh 64KB
    (0x00000000000C0000, 0x00000000000CFFFF), // Twelfth 64KB
    (0x00000000000D0000, 0x00000000000DFFFF), // Thirteenth 64KB
    (0x00000000000E0000, 0x00000000000EFFFF), // Fourteenth 64KB
    (0x00000000000F0000, 0x00000000000FFFFF), // Fifteenth 64KB
    (0x0000000000100000, 0x000000000010FFFF), // Sixteenth 64KB
];

// Safe wrapper for reading memory that catches access violations
unsafe fn safe_read<T: Copy>(ptr: *const T) -> Option<T> {
    Some(unsafe { ptr::read(ptr) })
}

fn is_target_dll(base_address: usize, target_hash: u32) -> bool {
    // Check if address is in skip regions
    for (start, end) in SKIP_REGIONS {
        if (base_address as u64) >= *start && (base_address as u64) <= *end {
            return false;
        }
    }

    unsafe {
        // First validate we can read the DOS header magic
        let dos_header = base_address as *const IMAGE_DOS_HEADER;
        let magic = match safe_read(dos_header) {
            Some(header) => header.e_magic,
            None => return false,
        };

        if magic != 0x5A4D {
            return false;
        }

        // Validate e_lfanew
        let e_lfanew = match safe_read(dos_header) {
            Some(header) => header.e_lfanew,
            None => return false,
        };

        if e_lfanew < 0x40 || e_lfanew > 0x1000 {
            return false;
        }

        let nt_headers_addr = base_address + e_lfanew as usize;

        // Validate we can read the NT headers
        let nt_headers = nt_headers_addr as *const IMAGE_NT_HEADERS64;
        let pe_sig = match safe_read(nt_headers) {
            Some(header) => header.Signature,
            None => return false,
        };

        if pe_sig != 0x00004550 {
            return false;
        }

        // Validate we can read the file header
        let file_header = match safe_read(nt_headers) {
            Some(header) => header.FileHeader,
            None => return false,
        };

        let characteristics = file_header.Characteristics;

        // Validate it's a DLL and x64
        if characteristics & 0x2000 == 0 {
            return false;
        }

        let machine = file_header.Machine;
        if machine != 0x8664 {
            return false;
        }

        // Validate we can read the optional header
        let opt_header = match safe_read(nt_headers) {
            Some(header) => header.OptionalHeader,
            None => return false,
        };

        let size_of_image = opt_header.SizeOfImage;

        // Validate image size is reasonable
        if size_of_image < 0x1000 || size_of_image > 0x10000000 {
            return false;
        }

        let export_dir_rva = opt_header.DataDirectory[0].VirtualAddress;
        let export_dir_size = opt_header.DataDirectory[0].Size;

        if export_dir_rva == 0 || export_dir_size == 0 {
            return false;
        }

        // Validate export directory RVA is within image bounds
        if export_dir_rva as u64 >= size_of_image as u64 {
            return false;
        }

        let export_dir = base_address + export_dir_rva as usize;

        // Validate we can read the name RVA
        let name_rva = match safe_read((export_dir as *const u32).add(3)) {
            Some(rva) => rva,
            None => return false,
        };

        if name_rva == 0 || name_rva as u64 >= size_of_image as u64 {
            return false;
        }

        let name_ptr = base_address + name_rva as usize;
        let mut name_bytes = [0u8; 256];
        let mut i = 0;

        while i < name_bytes.len() {
            let current_ptr = (name_ptr as *const u8).add(i);
            if name_ptr + i >= base_address + size_of_image as usize {
                break;
            }

            let byte = match safe_read(current_ptr) {
                Some(b) => b,
                None => return false,
            };

            if byte == 0 {
                break;
            }

            name_bytes[i] = byte;
            i += 1;
        }

        let mut effective_len = i;
        if effective_len >= 4 && &name_bytes[effective_len - 4..effective_len] == b".dll" {
            effective_len -= 4;
        }

        let name_hash = hash_fn(&name_bytes[..effective_len]);
        name_hash == target_hash
    }
}

// Validate if an address could be a DLL base by checking its contents
fn validate_potential_base(addr: usize) -> bool {
    unsafe {
        // Must be aligned
        if (addr & 0xFFF) != 0 {
            return false;
        }

        // Basic address range check
        if (addr as u64) < MIN_ADDRESS || (addr as u64) > MAX_ADDRESS {
            return false;
        }

        // Try to read DOS header
        let magic = match safe_read(addr as *const u16) {
            Some(m) => m,
            None => return false,
        };

        if magic != 0x5A4D {
            // MZ signature
            return false;
        }

        // Read e_lfanew
        let e_lfanew_ptr = (addr as *const u8).add(0x3C);
        let e_lfanew = match safe_read(e_lfanew_ptr as *const i32) {
            Some(lfanew) => lfanew,
            None => return false,
        };

        if e_lfanew <= 0 || e_lfanew > 0x1000 {
            return false;
        }

        // Validate PE header
        let pe_addr = addr + e_lfanew as usize;
        let pe_sig = match safe_read(pe_addr as *const u32) {
            Some(sig) => sig,
            None => return false,
        };

        if pe_sig != 0x00004550 {
            // PE signature
            return false;
        }

        // Validate we can read the file header
        let file_header = (pe_addr + 4) as *const IMAGE_FILE_HEADER;
        let header = match safe_read(file_header) {
            Some(h) => h,
            None => return false,
        };

        // Check if it's a DLL
        if header.Characteristics & 0x2000 == 0 {
            return false;
        }

        true
    }
}

pub fn resolve_module(dll_hash: u32) -> Option<usize> {
    let teb: *mut u64;
    unsafe {
        asm!(
            "mov {}, gs:[0x30]",
            out(reg) teb,
            options(nostack, nomem)
        );
    }

    // Store TEB address
    TEB_ADDRESS.with(|addr| addr.set(teb as u64));

    let stack_base: u64;
    unsafe {
        asm!(
            "mov {}, [{} + 0x08]",
            out(reg) stack_base,
            in(reg) teb,
            options(nostack, nomem)
        );
    }

    let stack_limit: u64;
    unsafe {
        asm!(
            "mov {}, [{} + 0x10]",
            out(reg) stack_limit,
            in(reg) teb,
            options(nostack, nomem)
        );
    }

    // Store stack region in thread local storage
    STACK_BASE.with(|base| base.set(stack_base));
    STACK_LIMIT.with(|limit| limit.set(stack_limit));

    let mut rsp: u64;
    unsafe {
        asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nostack, nomem)
        );
    }

    let mut current_stack = stack_base - 8; // Start from top of stack
    let mut found_dlls = Vec::new();

    // Walk down the stack until we hit RSP
    while current_stack > rsp {
        // Read return address safely from stack
        let return_address = match unsafe { safe_read(current_stack as *const u64) } {
            Some(addr) => addr,
            None => {
                current_stack -= 8;
                continue;
            }
        };

        // Get page-aligned address and walk back to 64KB alignment
        let mut potential_base = return_address & !0xFFF;
        while potential_base % 0x10000 != 0 {
            potential_base -= 0x1000;

            // Basic range check
            if potential_base < 0x7FF000000000 || potential_base > 0x7FFFFFFFFFFF {
                break;
            }
        }

        // Skip if we've already checked this address
        if found_dlls.contains(&potential_base) {
            current_stack -= 8;
            continue;
        }

        // Skip addresses that are clearly not DLL bases
        if potential_base < 0x7FF000000000 || potential_base > 0x7FFFFFFFFFFF {
            current_stack -= 8;
            continue;
        }

        // For ntdll, check more thoroughly around the base
        if dll_hash == fnv1a_hash!("ntdll") {
            // Get the high part of the address (should be consistent within the module)
            let addr_high = potential_base & 0xFFFFFFFFF0000000;

            // Check if this could be ntdll (based on typical load ranges)
            if addr_high >= 0x7FF800000000 && addr_high <= 0x7FFFFFFF0000 {
                // Check the 64KB-aligned address and a few before it
                for i in 0..16 {
                    // Try up to 1MB back
                    let try_address = potential_base - (i * 0x10000); // Try each 64KB-aligned address
                    if found_dlls.contains(&try_address) {
                        continue;
                    }

                    if is_target_dll(try_address as usize, dll_hash) {
                        return Some(try_address as usize);
                    } else {
                        continue;
                    }
                }
            }
        }

        // Try to validate this as a DLL base
        match is_target_dll(potential_base as usize, dll_hash) {
            true => return Some(potential_base as usize),
            false => {
                if validate_potential_base(potential_base as usize) {
                    found_dlls.push(potential_base);
                }
            }
        }

        // Always decrement the stack pointer
        current_stack -= 8;
    }

    None
}

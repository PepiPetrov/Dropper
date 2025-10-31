fn main() {
    if cfg!(feature = "resource") {
        embed_resource::compile_for_everything("assets/Resource.rc", embed_resource::NONE)
            .manifest_optional()
            .unwrap();
    }
    // GNU / MinGW-specific linker args
    let mut args: Vec<&str> = [
        "-ffunction-sections",
        "-fdata-sections",
        "-Wl,--gc-sections",
        "-Wl,-s",
        "-Wl,--strip-all",
        "-Wl,--no-seh",
        "-Wl,--enable-stdcall-fixup",
    ]
    .to_vec();

    if std::env::var("CARGO_FEATURE_DLL").is_err() {
        args.push("-Wl,-e"); // Add entry point for no_main
        args.push("mainCRTStartup") // Add entry point for no_main
    }
    for arg in args {
        println!("cargo:rustc-link-arg={arg}");
    }
}

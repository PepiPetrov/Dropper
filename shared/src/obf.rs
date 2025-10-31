use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

#[inline(always)]
fn pad_to_multiple(mut data: Vec<u8>, block_size: usize) -> Vec<u8> {
    while data.len() % block_size != 0 {
        data.push(0);
    }
    data
}

// ------------------- IPv4 -------------------

pub fn obfuscate_ipv4(shellcode: Vec<u8>) -> Vec<String> {
    pad_to_multiple(shellcode, 4)
        .chunks(4)
        .map(|ip| {
            let mut s = String::with_capacity(15);
            write!(s, "{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]).unwrap();
            s
        })
        .collect()
}

pub fn deobfuscate_ipv4(data: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    for line in data.lines() {
        let mut parts = line.as_bytes().split(|&b| b == b'.');
        let mut ip = [0u8; 4];
        for i in 0..4 {
            let part = parts.next().ok_or(())?;
            ip[i] = parse_decimal(part)?;
        }
        out.extend_from_slice(&ip);
    }
    Ok(out)
}

// ------------------- IPv6 -------------------

pub fn obfuscate_ipv6(shellcode: Vec<u8>) -> Vec<String> {
    pad_to_multiple(shellcode, 16)
        .chunks(16)
        .map(|c| {
            let mut s = String::with_capacity(39);
            for i in 0..8 {
                if i > 0 {
                    s.push(':');
                }
                write!(s, "{:02x}{:02x}", c[i * 2], c[i * 2 + 1]).unwrap();
            }
            s
        })
        .collect()
}

pub fn deobfuscate_ipv6(data: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    for line in data.lines() {
        let mut bytes = Vec::with_capacity(16);
        for part in line.as_bytes().split(|&b| b == b':') {
            if part.len() != 4 {
                return Err(());
            }
            let hi = parse_hex(&part[0..2])?;
            let lo = parse_hex(&part[2..4])?;
            bytes.push(hi);
            bytes.push(lo);
        }
        if bytes.len() != 16 {
            return Err(());
        }
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

// ------------------- MAC -------------------

pub fn obfuscate_mac(shellcode: Vec<u8>) -> Vec<String> {
    pad_to_multiple(shellcode, 6)
        .chunks(6)
        .map(|chunk| {
            let mut s = String::with_capacity(17);
            for (i, b) in chunk.iter().enumerate() {
                write!(s, "{:02X}", b).unwrap();
                if i < 5 {
                    s.push(':');
                }
            }
            s
        })
        .collect()
}

pub fn deobfuscate_mac(data: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    for line in data.lines() {
        let mut mac = [0u8; 6];
        let mut parts = line.as_bytes().split(|&b| b == b':');
        for i in 0..6 {
            let part = parts.next().ok_or(())?;
            mac[i] = parse_hex(part)?;
        }
        out.extend_from_slice(&mac);
    }
    Ok(out)
}

// ------------------- UUID -------------------

pub fn obfuscate_uuid(shellcode: Vec<u8>) -> Vec<String> {
    pad_to_multiple(shellcode, 16)
        .chunks(16)
        .map(|c| {
            let mut s = String::with_capacity(36);
            for i in 0..16 {
                write!(s, "{:02x}", c[i]).unwrap();
                if i == 3 || i == 5 || i == 7 || i == 9 {
                    s.push('-');
                }
            }
            s
        })
        .collect()
}

pub fn deobfuscate_uuid(data: &str) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    for line in data.lines() {
        let mut hex = [0u8; 32];
        let mut i = 0;
        for b in line.as_bytes().iter().copied() {
            if b == b'-' {
                continue;
            }
            if i >= 32 {
                return Err(());
            }
            hex[i] = b;
            i += 1;
        }

        if i != 32 {
            return Err(());
        }

        for j in (0..32).step_by(2) {
            out.push(parse_hex(&hex[j..j + 2])?);
        }
    }
    Ok(out)
}

// ------------------- Helpers -------------------

#[inline(always)]
fn parse_decimal(bytes: &[u8]) -> Result<u8, ()> {
    let mut val = 0u16;
    for &b in bytes {
        if !(b as char).is_ascii_digit() {
            return Err(());
        }
        val = val * 10 + (b - b'0') as u16;
        if val > 255 {
            return Err(());
        }
    }
    Ok(val as u8)
}

#[inline(always)]
fn parse_hex(bytes: &[u8]) -> Result<u8, ()> {
    if bytes.len() != 2 {
        return Err(());
    }
    let mut val = 0u8;
    for &b in bytes {
        val = val << 4
            | match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return Err(()),
            };
    }
    Ok(val)
}

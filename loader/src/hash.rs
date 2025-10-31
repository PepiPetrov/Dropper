#[inline(always)]
pub const fn fnv1a_hash_fn(s: &[u8]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C9DC5;
    const FNV_PRIME: u32 = 0x01000193;

    let mut hash = FNV_OFFSET_BASIS;
    let mut i: usize = 0;
    while i < s.len() {
        if let Some(c) = char::from_u32(s[i] as u32) {
            let c = c.to_ascii_lowercase();
            hash ^= c as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        i += 1;
    }
    hash
}

#[inline(always)]
pub const fn fnv1a_hash_fn_wide(s: &[u16]) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C9DC5;
    const FNV_PRIME: u32 = 0x01000193;

    let mut hash = FNV_OFFSET_BASIS;
    let mut i: usize = 0;
    while i < s.len() {
        if let Some(c) = char::from_u32(s[i] as u32) {
            let c = c.to_ascii_lowercase();
            hash ^= c as u32;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        i += 1;
    }
    hash
}

#[macro_export]
macro_rules! fnv1a_hash {
    ($str:expr) => {{
        const HASH: u32 = crate::hash::fnv1a_hash_fn($str.as_bytes());
        HASH
    }};
}

#[macro_export]
macro_rules! fnv1a_hash_wide {
    ($str:expr) => {{
        const HASH: u32 = crate::hash::fnv1a_hash_fn_wide($str.as_bytes());
        HASH
    }};
}
pub use fnv1a_hash;
pub use fnv1a_hash_wide;

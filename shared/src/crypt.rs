use rand::{TryRngCore, rngs::OsRng};
pub struct CryptoUtils;

//TODO: CHECK OUT XCHACHA20 ERRORS
pub trait XChaCha20Cipher {
    fn chacha20_xor(key: &[u8], counter: u32, nonce: &[u8], input: &[u8], output: &mut [u8]);
    fn chacha20_init_state(state: &mut [u32; 16], key: &[u8], counter: u32, nonce: &[u8]);
    fn chacha20_block(state: &mut [u32], output: &mut [u8], rounds: usize);
    fn chacha20_quarterround(state: &mut [u32], a: usize, b: usize, c: usize, d: usize);
    fn rotl32(x: u32, n: u32) -> u32;
    fn hchacha20(key: &[u8], nonce: &[u8]) -> [u8; 32];
    fn xchacha20_encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8], counter: u32) -> Vec<u8>;
    fn xchacha20_decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8], counter: u32) -> Vec<u8>;
    fn u32_to_u8_le(value: u32, output: &mut [u8]);
    fn u8_to_u32_le(input: &[u8]) -> u32;
}

pub trait Rc4Cipher {
    fn rc4_init(context: &mut Rc4Context, key: &[u8]) -> Result<(), &'static str>;
    fn rc4_cipher(context: &mut Rc4Context, input: &[u8], output: &mut [u8]);
    fn rc4_crypt(input: &[u8], key: &[u8]) -> Vec<u8>;
}

pub trait XorCipher {
    fn xor_crypt(input: &[u8], key: &[u8]) -> Vec<u8>;
}

pub struct Rc4Context {
    i: u32,
    j: u32,
    s: [u8; 256],
}

impl CryptoUtils {
    pub fn generate_bytes(len: usize) -> Vec<u8> {
        let mut key = vec![0u8; len];
        let _ = OsRng.try_fill_bytes(&mut key);
        key
    }
}

impl XChaCha20Cipher for CryptoUtils {
    fn u32_to_u8_le(value: u32, output: &mut [u8]) {
        output[0] = (value & 0xFF) as u8;
        output[1] = ((value >> 8) & 0xFF) as u8;
        output[2] = ((value >> 16) & 0xFF) as u8;
        output[3] = ((value >> 24) & 0xFF) as u8;
    }

    fn u8_to_u32_le(input: &[u8]) -> u32 {
        (input[3] as u32) << 24
            | (input[2] as u32) << 16
            | (input[1] as u32) << 8
            | (input[0] as u32)
    }

    fn rotl32(x: u32, n: u32) -> u32 {
        (x << n) | (x >> (32 - n))
    }

    fn chacha20_quarterround(state: &mut [u32], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = Self::rotl32(state[d], 16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = Self::rotl32(state[b], 12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = Self::rotl32(state[d], 8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = Self::rotl32(state[b], 7);
    }

    fn chacha20_block(state: &mut [u32], output: &mut [u8], rounds: usize) {
        // let mut working_state = state.clone();
        let mut working_state = [0u32; 16];
        working_state.copy_from_slice(&state[0..16]); // Copy the contents of the state

        for _ in 0..(rounds / 2) {
            // Odd rounds
            Self::chacha20_quarterround(&mut working_state, 0, 4, 8, 12);
            Self::chacha20_quarterround(&mut working_state, 1, 5, 9, 13);
            Self::chacha20_quarterround(&mut working_state, 2, 6, 10, 14);
            Self::chacha20_quarterround(&mut working_state, 3, 7, 11, 15);

            // Even rounds
            Self::chacha20_quarterround(&mut working_state, 0, 5, 10, 15);
            Self::chacha20_quarterround(&mut working_state, 1, 6, 11, 12);
            Self::chacha20_quarterround(&mut working_state, 2, 7, 8, 13);
            Self::chacha20_quarterround(&mut working_state, 3, 4, 9, 14);
        }

        for i in 0..16 {
            working_state[i] = working_state[i].wrapping_add(state[i]);
            Self::u32_to_u8_le(working_state[i], &mut output[i * 4..(i + 1) * 4]);
        }
    }

    fn chacha20_init_state(state: &mut [u32; 16], key: &[u8], counter: u32, nonce: &[u8]) {
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        for i in 0..8 {
            state[4 + i] = Self::u8_to_u32_le(&key[i * 4..(i + 1) * 4]);
        }

        // Counter
        state[12] = counter;

        // Nonce
        for i in 0..3 {
            state[13 + i] = Self::u8_to_u32_le(&nonce[i * 4..(i + 1) * 4]);
        }
    }

    fn chacha20_xor(key: &[u8], counter: u32, nonce: &[u8], input: &[u8], output: &mut [u8]) {
        let mut state = [0u32; 16];
        let mut block = [0u8; 64];
        let mut current_counter = counter;

        Self::chacha20_init_state(&mut state, key, current_counter, nonce);

        for (i, chunk) in input.chunks(64).enumerate() {
            state[12] = current_counter;
            Self::chacha20_block(&mut state, &mut block, 20);
            current_counter = current_counter.wrapping_add(1);

            for (j, &byte) in chunk.iter().enumerate() {
                output[i * 64 + j] = byte ^ block[j];
            }
        }
    }

    fn hchacha20(key: &[u8], nonce: &[u8]) -> [u8; 32] {
        let mut state = [0u32; 16];
        
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        // Key
        for i in 0..8 {
            state[4 + i] = Self::u8_to_u32_le(&key[i * 4..(i + 1) * 4]);
        }

        // First 16 bytes of nonce
        for i in 0..4 {
            state[12 + i] = Self::u8_to_u32_le(&nonce[i * 4..(i + 1) * 4]);
        }

        // Perform 20 rounds (10 double rounds)
        for _ in 0..10 {
            // Odd rounds
            Self::chacha20_quarterround(&mut state, 0, 4, 8, 12);
            Self::chacha20_quarterround(&mut state, 1, 5, 9, 13);
            Self::chacha20_quarterround(&mut state, 2, 6, 10, 14);
            Self::chacha20_quarterround(&mut state, 3, 7, 11, 15);

            // Even rounds
            Self::chacha20_quarterround(&mut state, 0, 5, 10, 15);
            Self::chacha20_quarterround(&mut state, 1, 6, 11, 12);
            Self::chacha20_quarterround(&mut state, 2, 7, 8, 13);
            Self::chacha20_quarterround(&mut state, 3, 4, 9, 14);
        }

        // Extract the key material from positions 0, 1, 2, 3, 12, 13, 14, 15
        let mut new_key = [0u8; 32];
        for i in 0..4 {
            Self::u32_to_u8_le(state[i], &mut new_key[i * 4..(i + 1) * 4]);
        }
        for i in 0..4 {
            Self::u32_to_u8_le(state[12 + i], &mut new_key[16 + i * 4..20 + i * 4]);
        }

        new_key
    }

    fn xchacha20_encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8], counter: u32) -> Vec<u8> {
        if nonce.len() != 24 {
            panic!("XChaCha20 requires a 24-byte nonce");
        }
        
        // Derive new key using HChaCha20
        let new_key = Self::hchacha20(key, &nonce[0..16]);
        
        // Use the last 8 bytes of the nonce for ChaCha20
        let chacha20_nonce = &nonce[16..24];
        
        // Pad the nonce to 12 bytes for ChaCha20 (8 bytes from nonce + 4 bytes of zeros)
        let mut padded_nonce = [0u8; 12];
        padded_nonce[4..12].copy_from_slice(chacha20_nonce);
        
        let mut output = vec![0u8; plaintext.len()];
        Self::chacha20_xor(&new_key, counter, &padded_nonce, plaintext, &mut output);
        output
    }

    fn xchacha20_decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8], counter: u32) -> Vec<u8> {
        if nonce.len() != 24 {
            panic!("XChaCha20 requires a 24-byte nonce");
        }
        
        // Derive new key using HChaCha20
        let new_key = Self::hchacha20(key, &nonce[0..16]);
        
        // Use the last 8 bytes of the nonce for ChaCha20
        let chacha20_nonce = &nonce[16..24];
        
        // Pad the nonce to 12 bytes for ChaCha20 (8 bytes from nonce + 4 bytes of zeros)
        let mut padded_nonce = [0u8; 12];
        padded_nonce[4..12].copy_from_slice(chacha20_nonce);
        
        let mut output = vec![0u8; ciphertext.len()];
        Self::chacha20_xor(&new_key, counter, &padded_nonce, ciphertext, &mut output);
        output
    }
}

impl Rc4Cipher for CryptoUtils {
    fn rc4_init(context: &mut Rc4Context, key: &[u8]) -> Result<(), &'static str> {
        if key.is_empty() {
            return Err("Key cannot be empty");
        }

        // Initialize context
        context.i = 0;
        context.j = 0;

        // Initialize the S array with identity permutation
        for i in 0..256 {
            context.s[i] = i as u8;
        }

        // S is then processed for 256 iterations
        let mut j = 0;
        for i in 0..256 {
            // Randomize the permutations using the supplied key
            j = (j + context.s[i] as usize + key[i % key.len()] as usize) % 256;

            // Swap the values of S[i] and S[j]
            context.s.swap(i, j);
        }

        Ok(())
    }

    fn rc4_cipher(context: &mut Rc4Context, input: &[u8], output: &mut [u8]) {
        let mut i = context.i as usize;
        let mut j = context.j as usize;
        let s = &mut context.s;

        for (in_byte, out_byte) in input.iter().zip(output.iter_mut()) {
            // Adjust indices
            i = (i + 1) % 256;
            j = (j + s[i] as usize) % 256;

            // Swap the values of S[i] and S[j]
            s.swap(i, j);

            // XOR the input data with the RC4 stream
            let k = s[(s[i] as usize + s[j] as usize) % 256];
            *out_byte = *in_byte ^ k;
        }

        // Save context
        context.i = i as u32;
        context.j = j as u32;
    }

    fn rc4_crypt(input: &[u8], key: &[u8]) -> Vec<u8> {
        let mut ciphertext = vec![0u8; input.len()];
        let mut context: Rc4Context = Rc4Context {
            i: 0,
            j: 0,
            s: [0; 256],
        };

        Self::rc4_init(&mut context, key).unwrap();
        Self::rc4_cipher(&mut context, input, &mut ciphertext);

        ciphertext
    }
}

impl XorCipher for CryptoUtils {
    fn xor_crypt(input: &[u8], key: &[u8]) -> Vec<u8> {
        input.iter()
            .enumerate()
            .map(|(i, byte)| byte ^ key[i % key.len()])
            .collect()
    }
}

// ============================================================================
// ChaCha20-Poly1305 — COMPLETE FROM-SCRATCH IMPLEMENTATION
// RFC 7539 / RFC 8439
//
// ChaCha20: a stream cipher based on the Salsa20 family by D.J. Bernstein
// Poly1305: a one-time MAC by D.J. Bernstein, operating in GF(2^130 - 5)
//
// This file implements:
//   - ChaCha20 quarter-round (the atomic operation)
//   - ChaCha20 full block function (20 rounds)
//   - ChaCha20 stream cipher with seeking
//   - Poly1305 MAC (arithmetic in the prime field 2^130 - 5)
//   - ChaCha20-Poly1305 AEAD construction
//   - HChaCha20 (for XChaCha20 extended-nonce construction)
//   - XChaCha20-Poly1305 (192-bit nonce — safer for random nonce generation)
// ============================================================================

use core::hint::black_box;
use crate::aes_gcm::secure_zero;

// ---------------------------------------------------------------------------
// ChaCha20 Quarter Round
// The fundamental operation of ChaCha20: 4 add-rotate-XOR operations.
// Bernstein designed this to be fast on modern CPUs and provably secure.
// ---------------------------------------------------------------------------

/// ChaCha20 quarter round: modifies 4 words of the state.
/// Each step: a += b; d ^= a; d <<<= rotation_amount
/// The rotations (16, 12, 8, 7) were chosen to maximize diffusion.
#[inline(always)]
pub fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]); state[d] ^= state[a]; state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]); state[b] ^= state[c]; state[b] = state[b].rotate_left(7);
}

// ---------------------------------------------------------------------------
// ChaCha20 Block Function
// Takes a 512-bit (64-byte) state and produces a 512-bit keystream block.
//
// Initial state layout (RFC 7539 §2.3):
//   cccccccc cccccccc cccccccc cccccccc   (4 constant words: "expand 32-byte k")
//   kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk   (8 key words)
//   kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk
//   bbbbbbbb nnnnnnnn nnnnnnnn nnnnnnnn   (1 counter + 3 nonce words)
//
// where c=constant, k=key, b=block counter, n=nonce
// ---------------------------------------------------------------------------

/// The 4 ChaCha20 setup constants — ASCII for "expand 32-byte k"
const CHACHA_CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// ChaCha20 block function: runs 20 rounds (10 double-rounds) on the state.
/// Returns the keystream block as 64 bytes.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initialize state
    let mut state = [0u32; 16];
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    // Key words (little-endian)
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
    }
    // Counter
    state[12] = counter;
    // Nonce (little-endian)
    state[13] = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
    state[14] = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
    state[15] = u32::from_le_bytes(nonce[8..12].try_into().unwrap());

    let initial = state; // Save for final addition

    // 20 rounds = 10 double-rounds
    // Each double-round: 4 column rounds + 4 diagonal rounds
    for _ in 0..10 {
        // Column rounds
        quarter_round(&mut state, 0, 4,  8, 12);
        quarter_round(&mut state, 1, 5,  9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7,  8, 13);
        quarter_round(&mut state, 3, 4,  9, 14);
    }

    // Final addition: add initial state to prevent invertibility
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialize to bytes (little-endian)
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[4*i..4*i+4].copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// ChaCha20 Stream Cipher
// Generates an infinite keystream by incrementing the counter for each block.
// Counter starts at 1 for ChaCha20-Poly1305 (0 is reserved for key generation).
// ---------------------------------------------------------------------------

pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    block: [u8; 64],
    block_pos: usize,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], initial_counter: u32) -> Self {
        let block = chacha20_block(key, initial_counter, nonce);
        ChaCha20 {
            key: *key,
            nonce: *nonce,
            counter: initial_counter,
            block,
            block_pos: 0,
        }
    }

    fn advance_block(&mut self) {
        self.counter = self.counter.wrapping_add(1);
        self.block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.block_pos = 0;
    }

    /// Seek to a specific byte position in the keystream.
    /// ChaCha20's counter-based design makes this O(1) — no need to regenerate
    /// all preceding blocks.
    pub fn seek(&mut self, byte_pos: u64) {
        let block_idx = (byte_pos / 64) as u32;
        let byte_idx  = (byte_pos % 64) as usize;
        self.counter = block_idx; // counter is the initial counter + block offset
        self.block = chacha20_block(&self.key, self.counter, &self.nonce);
        self.block_pos = byte_idx;
    }

    /// Apply ChaCha20 keystream to data (encrypt or decrypt — symmetric).
    pub fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.block_pos == 64 {
                self.advance_block();
            }
            *byte ^= self.block[self.block_pos];
            self.block_pos += 1;
        }
    }

    /// Fill buffer with raw keystream bytes (for analysis/testing).
    pub fn fill_keystream(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.block_pos == 64 {
                self.advance_block();
            }
            *byte = self.block[self.block_pos];
            self.block_pos += 1;
        }
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
        secure_zero(&mut self.block);
    }
}

// ---------------------------------------------------------------------------
// HChaCha20 — extended key/nonce derivation for XChaCha20
// Takes a 32-byte key and 16-byte input, returns a 32-byte subkey.
// This allows XChaCha20 to use 192-bit (24-byte) nonces safely.
// 192-bit nonces are large enough to generate randomly without collision risk.
// ---------------------------------------------------------------------------

pub fn hchacha20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[0] = CHACHA_CONSTANTS[0];
    state[1] = CHACHA_CONSTANTS[1];
    state[2] = CHACHA_CONSTANTS[2];
    state[3] = CHACHA_CONSTANTS[3];
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes(input[4*i..4*i+4].try_into().unwrap());
    }

    // 20 rounds (same as ChaCha20, but NO final addition)
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4,  8, 12);
        quarter_round(&mut state, 1, 5,  9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7,  8, 13);
        quarter_round(&mut state, 3, 4,  9, 14);
    }

    // Output: first and last 4 words (128 bits total = 32 bytes)
    // This is HChaCha20's special output selection
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[4*i..4*i+4].copy_from_slice(&state[i].to_le_bytes());
    }
    for i in 0..4 {
        out[16 + 4*i..16 + 4*i+4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Poly1305 MAC
//
// Poly1305 is a MAC based on polynomial evaluation over GF(2^130 - 5).
// The key is a pair (r, s) where:
//   - r is a 128-bit "clamp"ed value (certain bits forced to 0 for security)
//   - s is a 128-bit one-time pad added to the output
//
// The MAC is computed as:
//   tag = ((m[0]*r^q + m[1]*r^(q-1) + ... + m[q]*r^1) + s) mod 2^128
// where m[i] are 17-byte blocks of the message (with a '1' bit appended),
// and q is the number of blocks.
//
// Arithmetic here is in the field F_p where p = 2^130 - 5.
// We represent 130-bit integers as 5 × 26-bit limbs to avoid overflow.
// ---------------------------------------------------------------------------

/// Poly1305 state — uses 5 limbs of 26 bits each for 130-bit arithmetic
pub struct Poly1305 {
    // Accumulator: h[0..4] are 26-bit limbs, h[4] may be slightly larger
    h: [u32; 5],
    // r: the clamped key part (limbs)
    r: [u32; 5],
    // s: the one-time pad part
    s: [u32; 4],
    // Precomputed: 5*r for the reduction step
    // (Since p = 2^130 - 5, reducing mod p involves multiplying high bits by 5)
    r5: [u32; 5], // = 5 * r[i] for i in 0..5
    // Buffered partial block
    buf: [u8; 16],
    buf_len: usize,
    // Total message length for padding the final block
    finished: bool,
}

impl Poly1305 {
    /// Create a new Poly1305 instance with a 32-byte one-time key.
    /// The key is split: first 16 bytes are r (clamped), last 16 bytes are s.
    pub fn new(key: &[u8; 32]) -> Self {
        // Parse r from first 16 bytes with clamping
        // RFC 8439 §2.5.1: clamp bits to prevent attacks
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[..16]);
        // Clamping: clear specific bits
        r_bytes[3]  &= 0x0F;
        r_bytes[7]  &= 0x0F;
        r_bytes[11] &= 0x0F;
        r_bytes[15] &= 0x0F;
        r_bytes[4]  &= 0xFC;
        r_bytes[8]  &= 0xFC;
        r_bytes[12] &= 0xFC;

        // Parse into 5 × 26-bit limbs (little-endian)
        let r0 = u32::from_le_bytes(r_bytes[0..4].try_into().unwrap()) & 0x3FFFFFF;
        let r1 = (u32::from_le_bytes(r_bytes[3..7].try_into().unwrap()) >> 2) & 0x3FFFF03;
        // Actually use the standard radix-2^26 decomposition:
        let raw_r = u128::from_le_bytes(r_bytes);
        let r = [
            ((raw_r)       & 0x3FFFFFF) as u32,
            ((raw_r >> 26) & 0x3FFFFFF) as u32,
            ((raw_r >> 52) & 0x3FFFFFF) as u32,
            ((raw_r >> 78) & 0x3FFFFFF) as u32,
            ((raw_r >> 104) & 0x3FFFFFF) as u32,
        ];

        // Precompute 5*r for modular reduction
        let r5 = [r[0] * 5, r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];

        // Parse s from last 16 bytes as 4 × u32
        let s = [
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
        ];

        let _ = r0; let _ = r1; // suppress unused warnings

        Poly1305 {
            h: [0u32; 5],
            r,
            s,
            r5,
            buf: [0u8; 16],
            buf_len: 0,
            finished: false,
        }
    }

    /// Process a 16-byte block (with the "hibit" indicating if it's a full block).
    /// Full blocks append a '1' bit at position 128 (making them 17-byte values mod p).
    /// The final block may be shorter and gets a '1' bit at its true length.
    fn process_block(&mut self, block: &[u8], hibit: u32) {
        debug_assert!(block.len() <= 16);

        // Parse block as a 128-bit integer + optional high bit
        let mut raw = [0u8; 17];
        raw[..block.len()].copy_from_slice(block);
        raw[block.len()] = 1; // the high bit (for full blocks: hibit=2^128; here we set byte)

        let n = u128::from_le_bytes(raw[..16].try_into().unwrap());
        // For full blocks: n_128 = n | (1 << 128) represented in limbs
        let hi = if block.len() == 16 { hibit } else { 0 };

        // Parse n into 5 × 26-bit limbs, with h added
        let h0 = self.h[0] + ((n         & 0x3FFFFFF) as u32);
        let h1 = self.h[1] + (((n >> 26) & 0x3FFFFFF) as u32);
        let h2 = self.h[2] + (((n >> 52) & 0x3FFFFFF) as u32);
        let h3 = self.h[3] + (((n >> 78) & 0x3FFFFFF) as u32);
        let h4 = self.h[4] + (((n >> 104) & 0x3FFFFFF) as u32) + hi;

        // Multiply h by r using 130-bit arithmetic
        // h * r = (h0 + h1*2^26 + h2*2^52 + h3*2^78 + h4*2^104) *
        //         (r0 + r1*2^26 + r2*2^52 + r3*2^78 + r4*2^104)
        // mod 2^130 - 5
        //
        // The key insight: 2^130 ≡ 5 (mod p), so any term with 2^130k
        // can be reduced by multiplying its coefficient by 5.
        //
        // Use u64 intermediate values to prevent overflow during accumulation.
        let h0 = h0 as u64;
        let h1 = h1 as u64;
        let h2 = h2 as u64;
        let h3 = h3 as u64;
        let h4 = h4 as u64;
        let r0 = self.r[0] as u64;
        let r1 = self.r[1] as u64;
        let r2 = self.r[2] as u64;
        let r3 = self.r[3] as u64;
        let r4 = self.r[4] as u64;
        let r5_0 = self.r5[0] as u64;
        let r5_1 = self.r5[1] as u64;
        let r5_2 = self.r5[2] as u64;
        let r5_3 = self.r5[3] as u64;
        let r5_4 = self.r5[4] as u64;

        // Accumulate products for each output limb
        // d[i] = sum of h[j] * r[k] where j+k = i (or i+5 with factor 5)
        let d0: u64 = h0*r0 + h1*r5_4 + h2*r5_3 + h3*r5_2 + h4*r5_1;
        let d1: u64 = h0*r1 + h1*r0   + h2*r5_4 + h3*r5_3 + h4*r5_2;
        let d2: u64 = h0*r2 + h1*r1   + h2*r0   + h3*r5_4 + h4*r5_3;
        let d3: u64 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*r5_4;
        let d4: u64 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0;

        // Carry propagation to normalize back to 26-bit limbs
        let mut c: u64;
        let mut h: [u64; 5] = [d0, d1, d2, d3, d4];

        c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;
        c = h[1] >> 26; h[1] &= 0x3FFFFFF; h[2] += c;
        c = h[2] >> 26; h[2] &= 0x3FFFFFF; h[3] += c;
        c = h[3] >> 26; h[3] &= 0x3FFFFFF; h[4] += c;
        // h[4] may overflow 26 bits; reduce mod p (2^130 - 5)
        c = h[4] >> 26; h[4] &= 0x3FFFFFF; h[0] += c * 5;
        c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] += c;

        self.h = [h[0] as u32, h[1] as u32, h[2] as u32, h[3] as u32, h[4] as u32];
    }

    /// Feed data into the Poly1305 authenticator.
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;

        // Fill buffer first
        if self.buf_len > 0 {
            let need = 16 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..].copy_from_slice(&data[..need]);
            data = &data[need..];
            let block = self.buf;
            self.process_block(&block, 1);
            self.buf_len = 0;
        }

        // Process full blocks
        while data.len() >= 16 {
            self.process_block(&data[..16], 1);
            data = &data[16..];
        }

        // Buffer the remainder
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalize and return the 16-byte tag.
    pub fn finalize(mut self) -> [u8; 16] {
        // Process any remaining partial block (with no high bit)
        if self.buf_len > 0 {
            // The final block has a 1 byte appended (not 2^128 but at position buf_len)
            let mut block = [0u8; 17];
            block[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
            block[self.buf_len] = 1; // "1" bit at position 8*buf_len
            // Process as a shorter-than-16-byte block
            // We set hibit=0 since the "1" bit is already included at byte[buf_len]
            // But process_block handles this specially
            let partial = &self.buf[..self.buf_len];
            self.process_block(partial, 0);
        }

        // Full reduction mod p = 2^130 - 5
        // We need to convert from possibly unreduced form
        let mut h = self.h;
        let mut c: u32;

        c = h[1] >> 26; h[1] &= 0x3FFFFFF; h[2] = h[2].wrapping_add(c);
        c = h[2] >> 26; h[2] &= 0x3FFFFFF; h[3] = h[3].wrapping_add(c);
        c = h[3] >> 26; h[3] &= 0x3FFFFFF; h[4] = h[4].wrapping_add(c);
        c = h[4] >> 26; h[4] &= 0x3FFFFFF; h[0] = h[0].wrapping_add(c.wrapping_mul(5));
        c = h[0] >> 26; h[0] &= 0x3FFFFFF; h[1] = h[1].wrapping_add(c);

        // Compute h + -p = h - (2^130 - 5) and conditionally select
        // g = h + 5
        let g0 = h[0].wrapping_add(5);
        c = g0 >> 26; let g0 = g0 & 0x3FFFFFF;
        let g1 = h[1].wrapping_add(c);
        c = g1 >> 26; let g1 = g1 & 0x3FFFFFF;
        let g2 = h[2].wrapping_add(c);
        c = g2 >> 26; let g2 = g2 & 0x3FFFFFF;
        let g3 = h[3].wrapping_add(c);
        c = g3 >> 26; let g3 = g3 & 0x3FFFFFF;
        let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

        // If g4's MSB is set, g overflowed past 2^130 → h < p → use h
        // Otherwise h ≥ p → use g (= h mod p)
        // Constant-time select: mask = 0 if h < p (use h), 0xFFFFFFFF if h ≥ p (use g)
        let mask = (g4 >> 31).wrapping_sub(1); // 0 if overflow, 0xFFFFFFFF if not
        let h0 = (h[0] & !mask) | (g0 & mask);
        let h1 = (h[1] & !mask) | (g1 & mask);
        let h2 = (h[2] & !mask) | (g2 & mask);
        let h3 = (h[3] & !mask) | (g3 & mask);
        let h4 = (h[4] & !mask) | (g4 & mask);

        // Pack h back to 128-bit integer
        let h128: u128 = (h0 as u128)
            | ((h1 as u128) << 26)
            | ((h2 as u128) << 52)
            | ((h3 as u128) << 78)
            | ((h4 as u128) << 104);

        // Add s (mod 2^128 — no carry past 128 bits)
        let s = (self.s[0] as u128)
            | ((self.s[1] as u128) << 32)
            | ((self.s[2] as u128) << 64)
            | ((self.s[3] as u128) << 96);
        let tag_val = h128.wrapping_add(s);

        tag_val.to_le_bytes()
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Zero all sensitive state
        unsafe {
            core::ptr::write_volatile(&mut self.h, [0u32; 5]);
            core::ptr::write_volatile(&mut self.r, [0u32; 5]);
            core::ptr::write_volatile(&mut self.s, [0u32; 4]);
            core::ptr::write_volatile(&mut self.r5, [0u32; 5]);
            secure_zero(&mut self.buf);
        }
    }
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 8439)
//
// Construction:
//   1. Generate one-time Poly1305 key: otk = ChaCha20(key, nonce, counter=0)[0..32]
//   2. Encrypt plaintext: ciphertext = ChaCha20(key, nonce, counter=1) XOR plaintext
//   3. Compute MAC over: AAD || pad(AAD) || ciphertext || pad(ciphertext) || len(AAD) || len(CT)
//   4. Tag = Poly1305(otk, MAC_data)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum ChaChaError {
    AuthenticationFailed,
    OutputTooLarge,
}

impl core::fmt::Display for ChaChaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChaChaError::AuthenticationFailed => write!(f, "ChaCha20-Poly1305: authentication failed — message tampered"),
            ChaChaError::OutputTooLarge => write!(f, "ChaCha20-Poly1305: message too large"),
        }
    }
}

pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }

    /// Generate the one-time Poly1305 key from ChaCha20(key, nonce, counter=0)
    fn poly1305_key_gen(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let block = chacha20_block(&self.key, 0, nonce);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&block[..32]);
        otk
    }

    /// Compute the Poly1305 MAC input per RFC 8439 §2.8.
    /// mac_data = AAD || pad16(AAD) || ciphertext || pad16(CT) || len64(AAD) || len64(CT)
    fn compute_mac_data(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let pad16 = |n: usize| -> usize { if n % 16 == 0 { 0 } else { 16 - n % 16 } };
        let mut mac_data = Vec::new();
        mac_data.extend_from_slice(aad);
        mac_data.extend(core::iter::repeat(0u8).take(pad16(aad.len())));
        mac_data.extend_from_slice(ciphertext);
        mac_data.extend(core::iter::repeat(0u8).take(pad16(ciphertext.len())));
        mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        mac_data
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), ChaChaError> {
        // Generate one-time key
        let otk = self.poly1305_key_gen(nonce);

        // Encrypt with ChaCha20 (counter starts at 1)
        let mut ciphertext = plaintext.to_vec();
        let mut chacha = ChaCha20::new(&self.key, nonce, 1);
        chacha.apply(&mut ciphertext);

        // Compute MAC
        let mac_data = Self::compute_mac_data(aad, &ciphertext);
        let mut poly = Poly1305::new(&otk);
        poly.update(&mac_data);
        let tag = poly.finalize();

        Ok((ciphertext, tag))
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, ChaChaError> {
        let otk = self.poly1305_key_gen(nonce);

        // Verify MAC BEFORE decryption (Encrypt-then-MAC)
        let mac_data = Self::compute_mac_data(aad, ciphertext);
        let mut poly = Poly1305::new(&otk);
        poly.update(&mac_data);
        let expected_tag = poly.finalize();

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in expected_tag.iter().zip(tag.iter()) {
            diff |= a ^ b;
        }
        if black_box(diff) != 0 {
            return Err(ChaChaError::AuthenticationFailed);
        }

        // Decrypt
        let mut plaintext = ciphertext.to_vec();
        let mut chacha = ChaCha20::new(&self.key, nonce, 1);
        chacha.apply(&mut plaintext);

        Ok(plaintext)
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
    }
}

// ---------------------------------------------------------------------------
// XChaCha20-Poly1305
// Uses a 192-bit (24-byte) nonce, safe for random generation.
// HChaCha20 derives a subkey from the first 16 nonce bytes,
// then ChaCha20-Poly1305 uses the remaining 8 nonce bytes.
// ---------------------------------------------------------------------------

pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl XChaCha20Poly1305 {
    pub fn new(key: &[u8; 32]) -> Self {
        XChaCha20Poly1305 { key: *key }
    }

    /// Derive the subkey and sub-nonce from a 24-byte XChaCha20 nonce
    fn derive(&self, nonce: &[u8; 24]) -> ([u8; 32], [u8; 12]) {
        let mut hchacha_input = [0u8; 16];
        hchacha_input.copy_from_slice(&nonce[..16]);
        let subkey = hchacha20(&self.key, &hchacha_input);

        let mut sub_nonce = [0u8; 12];
        sub_nonce[..4].copy_from_slice(&[0u8; 4]); // first 4 bytes are zero
        sub_nonce[4..].copy_from_slice(&nonce[16..]);
        (subkey, sub_nonce)
    }

    pub fn encrypt(
        &self,
        nonce: &[u8; 24],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), ChaChaError> {
        let (subkey, sub_nonce) = self.derive(nonce);
        let inner = ChaCha20Poly1305::new(&subkey);
        inner.encrypt(&sub_nonce, plaintext, aad)
    }

    pub fn decrypt(
        &self,
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, ChaChaError> {
        let (subkey, sub_nonce) = self.derive(nonce);
        let inner = ChaCha20Poly1305::new(&subkey);
        inner.decrypt(&sub_nonce, ciphertext, aad, tag)
    }
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        secure_zero(&mut self.key);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarter_round_rfc_vector() {
        // RFC 7539 §2.1.1 test vector
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(state[0], 0xea2a92f4);
        assert_eq!(state[1], 0xcb1cf8ce);
        assert_eq!(state[2], 0x4581472e);
        assert_eq!(state[3], 0x5881c4bb);
    }

    #[test]
    fn test_chacha20_block_rfc_vector() {
        // RFC 7539 §2.3.2 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];
        let block = chacha20_block(&key, 1, &nonce);
        // First 4 bytes of expected output from RFC
        assert_eq!(block[0], 0x10);
        assert_eq!(block[1], 0xf1);
        assert_eq!(block[2], 0xe7);
        assert_eq!(block[3], 0xe4);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = [0xABu8; 32];
        let nonce = [0x01u8; 12];
        let pt = b"The quick brown fox jumps over the lazy dog — beast mode crypto!";
        let aad = b"associated data";

        let cipher = ChaCha20Poly1305::new(&key);
        let (ct, tag) = cipher.encrypt(&nonce, pt, aad).unwrap();
        let dec = cipher.decrypt(&nonce, &ct, aad, &tag).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_chacha20_poly1305_tamper() {
        let key = [0x01u8; 32];
        let nonce = [0x00u8; 12];
        let pt = b"secret";
        let aad = b"";

        let cipher = ChaCha20Poly1305::new(&key);
        let (mut ct, tag) = cipher.encrypt(&nonce, pt, aad).unwrap();
        ct[0] ^= 1;
        assert_eq!(cipher.decrypt(&nonce, &ct, aad, &tag), Err(ChaChaError::AuthenticationFailed));
    }

    #[test]
    fn test_xchacha20_poly1305_roundtrip() {
        let key = [0xFFu8; 32];
        let nonce = [0x42u8; 24];
        let pt = b"XChaCha20 extended nonce — no collision risk!";
        let aad = b"hdr";

        let cipher = XChaCha20Poly1305::new(&key);
        let (ct, tag) = cipher.encrypt(&nonce, pt, aad).unwrap();
        let dec = cipher.decrypt(&nonce, &ct, aad, &tag).unwrap();
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_poly1305_rfc_vector() {
        // RFC 7539 §2.5.2 — Poly1305 known-answer test
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
            0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
            0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
            0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let expected_tag: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
            0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
        ];
        let mut poly = Poly1305::new(&key);
        poly.update(msg);
        let tag = poly.finalize();
        assert_eq!(tag, expected_tag);
    }
}
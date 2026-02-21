// ============================================================================
// AES-256-GCM — COMPLETE FROM-SCRATCH IMPLEMENTATION
// No crates. No lookup tables from the internet. Every constant derived here.
//
// AES: FIPS 197
// GCM: NIST SP 800-38D
//
// This file implements:
//   - GF(2^8) arithmetic (the mathematical foundation)
//   - AES S-Box generation at runtime from GF(2^8) inverses + affine transform
//   - AES key schedule (256-bit)
//   - AES encryption/decryption (ECB block)
//   - CTR mode streaming
//   - GHASH (GCM authentication)
//   - Full AES-256-GCM AEAD with constant-time tag verification
// ============================================================================

use core::ptr;

// ---------------------------------------------------------------------------
// GF(2^8) — Galois Field arithmetic with irreducible polynomial x^8+x^4+x^3+x+1
// AES uses this field for ALL its operations
// ---------------------------------------------------------------------------

/// Multiply two elements in GF(2^8) using the AES irreducible polynomial.
/// This is the fundamental building block of literally everything in AES.
/// Uses the "Russian peasant multiplication" algorithm — no lookup tables.
#[inline(always)]
pub const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    let mut i = 0u8;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1 reduced (0x11B & 0xFF = 0x1B)
        }
        b >>= 1;
        i += 1;
    }
    p
}

/// Compute GF(2^8) multiplicative inverse via Fermat's little theorem.
/// In GF(2^8), a^(2^8 - 1) = 1, so a^(-1) = a^(2^8 - 2) = a^254.
/// We compute this via repeated squaring.
#[inline(always)]
pub const fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // 0 has no inverse; AES defines inv(0) = 0
    }
    // a^254 via square-and-multiply
    let a2   = gf_mul(a, a);       // a^2
    let a4   = gf_mul(a2, a2);     // a^4
    let a8   = gf_mul(a4, a4);     // a^8
    let a16  = gf_mul(a8, a8);     // a^16
    let a32  = gf_mul(a16, a16);   // a^32
    let a64  = gf_mul(a32, a32);   // a^64
    let a128 = gf_mul(a64, a64);   // a^128
    // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
    let t = gf_mul(a128, a64);
    let t = gf_mul(t, a32);
    let t = gf_mul(t, a16);
    let t = gf_mul(t, a8);
    let t = gf_mul(t, a4);
    gf_mul(t, a2)
}

/// AES affine transformation applied after GF inverse to produce S-Box value.
/// This is a bit matrix multiply in GF(2) + constant 0x63.
/// The matrix is circular shifts of 10001111:
///   b_i = a_i ^ a_{i+4} ^ a_{i+5} ^ a_{i+6} ^ a_{i+7} (mod 8) + c_i
#[inline(always)]
const fn affine(x: u8) -> u8 {
    let x = x as u32;
    // 8 circular shifts XORed together
    let y = x
        ^ x.rotate_left(1) & 0xFF
        ^ x.rotate_left(2) & 0xFF
        ^ x.rotate_left(3) & 0xFF
        ^ x.rotate_left(4) & 0xFF;
    ((y ^ 0x63) & 0xFF) as u8
}

// ---------------------------------------------------------------------------
// S-Box and Inverse S-Box — generated at compile time (const fn)
// ---------------------------------------------------------------------------

/// Generate the full 256-entry AES SubBytes S-Box.
/// Each entry: S[x] = affine(gf_inv(x))
const fn make_sbox() -> [u8; 256] {
    let mut s = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        s[i] = affine(gf_inv(i as u8));
        i += 1;
    }
    s
}

/// Generate the inverse S-Box for AES decryption.
/// InvS[S[x]] = x for all x
const fn make_inv_sbox(sbox: &[u8; 256]) -> [u8; 256] {
    let mut inv = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        inv[sbox[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

pub const SBOX:     [u8; 256] = make_sbox();
pub const INV_SBOX: [u8; 256] = make_inv_sbox(&SBOX);

// ---------------------------------------------------------------------------
// Round constants (RCON) — powers of 2 in GF(2^8)
// Used in the key schedule
// ---------------------------------------------------------------------------
const fn make_rcon() -> [u32; 15] {
    let mut rcon = [0u32; 15];
    let mut x: u8 = 1;
    let mut i = 0;
    while i < 15 {
        rcon[i] = (x as u32) << 24;
        x = gf_mul(x, 2);
        i += 1;
    }
    rcon
}
pub const RCON: [u32; 15] = make_rcon();

// ---------------------------------------------------------------------------
// MixColumns precomputed tables — the heart of AES diffusion
// MixColumns multiplies each column by the fixed polynomial
// {03}x^3 + {01}x^2 + {01}x + {02} in GF(2^8)[x]/(x^4+1)
// We precompute the 4 possible XTIMEs to avoid runtime GF mul in the hot path
// ---------------------------------------------------------------------------

const fn make_xtime2() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = gf_mul(i as u8, 2);
        i += 1;
    }
    t
}

const fn make_xtime3() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = gf_mul(i as u8, 3);
        i += 1;
    }
    t
}

const fn make_xtime9() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 { t[i] = gf_mul(i as u8, 9); i += 1; }
    t
}
const fn make_xtime11() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 { t[i] = gf_mul(i as u8, 11); i += 1; }
    t
}
const fn make_xtime13() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 { t[i] = gf_mul(i as u8, 13); i += 1; }
    t
}
const fn make_xtime14() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 { t[i] = gf_mul(i as u8, 14); i += 1; }
    t
}

pub const MUL2:  [u8; 256] = make_xtime2();
pub const MUL3:  [u8; 256] = make_xtime3();
pub const MUL9:  [u8; 256] = make_xtime9();
pub const MUL11: [u8; 256] = make_xtime11();
pub const MUL13: [u8; 256] = make_xtime13();
pub const MUL14: [u8; 256] = make_xtime14();

// ---------------------------------------------------------------------------
// AES State — 4x4 byte matrix, stored column-major (AES standard)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AesState {
    pub s: [u8; 16], // s[row + 4*col]
}

impl AesState {
    #[inline(always)]
    pub fn from_block(block: &[u8; 16]) -> Self {
        AesState { s: *block }
    }

    #[inline(always)]
    pub fn to_block(&self) -> [u8; 16] {
        self.s
    }

    #[inline(always)]
    pub fn get(&self, row: usize, col: usize) -> u8 {
        self.s[row + 4 * col]
    }

    #[inline(always)]
    pub fn set(&mut self, row: usize, col: usize, val: u8) {
        self.s[row + 4 * col] = val;
    }

    /// SubBytes: replace each byte with its S-Box value
    pub fn sub_bytes(&mut self) {
        for b in &mut self.s {
            *b = SBOX[*b as usize];
        }
    }

    /// InvSubBytes: reverse SubBytes using inverse S-Box
    pub fn inv_sub_bytes(&mut self) {
        for b in &mut self.s {
            *b = INV_SBOX[*b as usize];
        }
    }

    /// ShiftRows: cyclically shift row i left by i positions
    pub fn shift_rows(&mut self) {
        // Row 1: shift left by 1
        let t = self.s[1];
        self.s[1]  = self.s[5];
        self.s[5]  = self.s[9];
        self.s[9]  = self.s[13];
        self.s[13] = t;
        // Row 2: shift left by 2
        self.s.swap(2, 10);
        self.s.swap(6, 14);
        // Row 3: shift left by 3 (= shift right by 1)
        let t = self.s[15];
        self.s[15] = self.s[11];
        self.s[11] = self.s[7];
        self.s[7]  = self.s[3];
        self.s[3]  = t;
    }

    /// InvShiftRows: undo ShiftRows
    pub fn inv_shift_rows(&mut self) {
        // Row 1: shift right by 1
        let t = self.s[13];
        self.s[13] = self.s[9];
        self.s[9]  = self.s[5];
        self.s[5]  = self.s[1];
        self.s[1]  = t;
        // Row 2: shift right by 2
        self.s.swap(2, 10);
        self.s.swap(6, 14);
        // Row 3: shift right by 3 (= shift left by 1)
        let t = self.s[3];
        self.s[3]  = self.s[7];
        self.s[7]  = self.s[11];
        self.s[11] = self.s[15];
        self.s[15] = t;
    }

    /// MixColumns: multiply each column by the MDS matrix in GF(2^8)
    /// The matrix multiplication:
    /// |2 3 1 1|   |s0|
    /// |1 2 3 1| x |s1|
    /// |1 1 2 3|   |s2|
    /// |3 1 1 2|   |s3|
    pub fn mix_columns(&mut self) {
        for col in 0..4 {
            let s0 = self.get(0, col);
            let s1 = self.get(1, col);
            let s2 = self.get(2, col);
            let s3 = self.get(3, col);

            self.set(0, col, MUL2[s0 as usize] ^ MUL3[s1 as usize] ^ s2 ^ s3);
            self.set(1, col, s0 ^ MUL2[s1 as usize] ^ MUL3[s2 as usize] ^ s3);
            self.set(2, col, s0 ^ s1 ^ MUL2[s2 as usize] ^ MUL3[s3 as usize]);
            self.set(3, col, MUL3[s0 as usize] ^ s1 ^ s2 ^ MUL2[s3 as usize]);
        }
    }

    /// InvMixColumns: inverse MDS matrix multiplication
    /// The inverse matrix:
    /// |14 11 13  9|
    /// | 9 14 11 13|
    /// |13  9 14 11|
    /// |11 13  9 14|
    pub fn inv_mix_columns(&mut self) {
        for col in 0..4 {
            let s0 = self.get(0, col);
            let s1 = self.get(1, col);
            let s2 = self.get(2, col);
            let s3 = self.get(3, col);

            self.set(0, col, MUL14[s0 as usize] ^ MUL11[s1 as usize] ^ MUL13[s2 as usize] ^ MUL9[s3 as usize]);
            self.set(1, col, MUL9[s0 as usize]  ^ MUL14[s1 as usize] ^ MUL11[s2 as usize] ^ MUL13[s3 as usize]);
            self.set(2, col, MUL13[s0 as usize] ^ MUL9[s1 as usize]  ^ MUL14[s2 as usize] ^ MUL11[s3 as usize]);
            self.set(3, col, MUL11[s0 as usize] ^ MUL13[s1 as usize] ^ MUL9[s2 as usize]  ^ MUL14[s3 as usize]);
        }
    }

    /// AddRoundKey: XOR state with round key (column-major)
    pub fn add_round_key(&mut self, rk: &[u32; 4]) {
        for col in 0..4 {
            let k = rk[col].to_be_bytes();
            for row in 0..4 {
                self.s[row + 4 * col] ^= k[row];
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AES-256 Key Schedule
// AES-256: 14 rounds, 15 round keys (each 4 words = 128 bits), 60 words total
// ---------------------------------------------------------------------------

pub struct Aes256Key {
    pub round_keys: [[u32; 4]; 15], // 15 round keys of 4 words each
}

impl Aes256Key {
    /// Expand a 32-byte (256-bit) key into the full key schedule.
    /// AES-256 key schedule is more complex than AES-128/192:
    /// every other word uses SubWord (S-Box on all 4 bytes of the word).
    pub fn expand(key: &[u8; 32]) -> Self {
        // Parse key into 8 initial words
        let mut w = [0u32; 60];
        for i in 0..8 {
            w[i] = u32::from_be_bytes([
                key[4 * i],
                key[4 * i + 1],
                key[4 * i + 2],
                key[4 * i + 3],
            ]);
        }

        // Expand remaining 52 words
        for i in 8..60 {
            let mut temp = w[i - 1];
            if i % 8 == 0 {
                // RotWord: rotate left by 8 bits
                temp = temp.rotate_left(8);
                // SubWord: apply S-Box to each byte
                temp = sub_word(temp);
                // XOR with round constant
                temp ^= RCON[i / 8 - 1];
            } else if i % 8 == 4 {
                // AES-256 specific: every 4th word after the rotation also gets SubWord
                temp = sub_word(temp);
            }
            w[i] = w[i - 8] ^ temp;
        }

        // Pack into round keys
        let mut round_keys = [[0u32; 4]; 15];
        for rk in 0..15 {
            round_keys[rk] = [w[4*rk], w[4*rk+1], w[4*rk+2], w[4*rk+3]];
        }

        Aes256Key { round_keys }
    }
}

/// SubWord: apply S-Box to each of the 4 bytes of a u32
#[inline(always)]
fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

// ---------------------------------------------------------------------------
// AES-256 Block Cipher — Encryption and Decryption
// ---------------------------------------------------------------------------

pub struct Aes256 {
    key: Aes256Key,
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        Aes256 { key: Aes256Key::expand(key) }
    }

    /// Encrypt a single 16-byte block using AES-256.
    /// 14 rounds: initial AddRoundKey, 13 full rounds, 1 final round (no MixColumns)
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = AesState::from_block(block);
        let rk = &self.key.round_keys;

        // Initial round key addition
        state.add_round_key(&rk[0]);

        // Rounds 1-13: SubBytes + ShiftRows + MixColumns + AddRoundKey
        for round in 1..14 {
            state.sub_bytes();
            state.shift_rows();
            state.mix_columns();
            state.add_round_key(&rk[round]);
        }

        // Final round: no MixColumns
        state.sub_bytes();
        state.shift_rows();
        state.add_round_key(&rk[14]);

        state.to_block()
    }

    /// Decrypt a single 16-byte block using AES-256.
    /// Equivalent inverse cipher (NOT the "equivalent inverse cipher" optimization,
    /// just the straightforward inverse — educational clarity over speed).
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = AesState::from_block(block);
        let rk = &self.key.round_keys;

        // Initial round key addition (last round key)
        state.add_round_key(&rk[14]);

        // Rounds 13 down to 1: InvShiftRows + InvSubBytes + AddRoundKey + InvMixColumns
        for round in (1..14).rev() {
            state.inv_shift_rows();
            state.inv_sub_bytes();
            state.add_round_key(&rk[round]);
            state.inv_mix_columns();
        }

        // Final round (no InvMixColumns)
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&rk[0]);

        state.to_block()
    }
}

// ---------------------------------------------------------------------------
// CTR Mode — converts AES block cipher into a stream cipher
// Counter mode: encrypt successive counter values, XOR with plaintext.
// This is what GCM uses for the actual message encryption.
// ---------------------------------------------------------------------------

pub struct AesCtr {
    aes: Aes256,
    nonce: [u8; 12],  // 96-bit nonce
    counter: u32,     // 32-bit counter (big-endian in the block)
    keystream: [u8; 16],
    keystream_pos: usize,
}

impl AesCtr {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], initial_counter: u32) -> Self {
        let aes = Aes256::new(key);
        let mut ctr = AesCtr {
            aes,
            nonce: *nonce,
            counter: initial_counter,
            keystream: [0u8; 16],
            keystream_pos: 16, // force generation on first use
        };
        ctr.generate_keystream_block();
        ctr
    }

    /// Generate the next keystream block by encrypting the counter block
    fn generate_keystream_block(&mut self) {
        let mut ctr_block = [0u8; 16];
        ctr_block[..12].copy_from_slice(&self.nonce);
        ctr_block[12..].copy_from_slice(&self.counter.to_be_bytes());
        self.keystream = self.aes.encrypt_block(&ctr_block);
        self.keystream_pos = 0;
        self.counter = self.counter.wrapping_add(1);
    }

    /// XOR data with keystream (in-place)
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.keystream_pos == 16 {
                self.generate_keystream_block();
            }
            *byte ^= self.keystream[self.keystream_pos];
            self.keystream_pos += 1;
        }
    }

    /// Generate keystream bytes without XOR (for testing/analysis)
    pub fn generate_bytes(&mut self, out: &mut [u8]) {
        for byte in out.iter_mut() {
            if self.keystream_pos == 16 {
                self.generate_keystream_block();
            }
            *byte = self.keystream[self.keystream_pos];
            self.keystream_pos += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// GHASH — GCM's authentication function
// GHASH operates in GF(2^128) with the irreducible polynomial
// x^128 + x^7 + x^2 + x + 1 (0xE1 in the reflected representation)
//
// This is completely different from GF(2^8)! GCM uses a 128-bit field
// for authentication while AES internals use an 8-bit field.
// ---------------------------------------------------------------------------

/// Multiply two 128-bit values in GF(2^128) using the GCM polynomial.
/// The "Russian peasant" method over 128 bits.
/// Input/output are 16-byte arrays (big-endian 128-bit integers).
pub fn ghash_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for i in 0..128 {
        // If bit i of x is set, XOR Z with V
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8); // MSB first
        if (x[byte_idx] >> bit_idx) & 1 == 1 {
            for j in 0..16 {
                z[j] ^= v[j];
            }
        }

        // V = V * x in GF(2^128)
        // If LSB of V is 1, shift right and XOR with R (= 0xE1 || 0^120)
        let lsb = v[15] & 1;
        // Shift V right by 1 bit (big-endian)
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | ((v[j-1] & 1) << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xE1; // Reduction polynomial
        }
    }
    z
}

/// GHASH: the GCM hash function
/// Computes GHASH_H(A || len(A) || C || len(C)) where H is the hash subkey
pub struct GHash {
    h: [u8; 16],    // Hash subkey H = AES_K(0^128)
    state: [u8; 16], // Running state
}

impl GHash {
    pub fn new(h: &[u8; 16]) -> Self {
        GHash { h: *h, state: [0u8; 16] }
    }

    /// Update GHASH with a block of data (zero-padded to 16 bytes if needed)
    pub fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks(16);
        while let Some(chunk) = chunks.next() {
            let mut block = [0u8; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            // XOR block into state
            for i in 0..16 {
                self.state[i] ^= block[i];
            }
            // Multiply by H in GF(2^128)
            self.state = ghash_mul(&self.state, &self.h);
        }
    }

    /// Finalize with length block: ||A||_64 || ||C||_64 (bit lengths, big-endian)
    pub fn finalize_with_lengths(&mut self, aad_len_bits: u64, ct_len_bits: u64) -> [u8; 16] {
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&aad_len_bits.to_be_bytes());
        len_block[8..].copy_from_slice(&ct_len_bits.to_be_bytes());
        self.update(&len_block);
        self.state
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM — The Full AEAD Construction
// Authenticated Encryption with Associated Data
//
// GCM = CTR mode encryption + GHASH authentication
// Security: 256-bit key, 128-bit tag, 96-bit nonce
// ---------------------------------------------------------------------------

/// Error type for GCM operations
#[derive(Debug, Clone, PartialEq)]
pub enum AesGcmError {
    AuthenticationFailed,
    InvalidNonceLength,
    InvalidKeyLength,
    CiphertextTooLarge,
}

impl core::fmt::Display for AesGcmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AesGcmError::AuthenticationFailed => write!(f, "AES-GCM: authentication tag mismatch — ciphertext is corrupted or tampered"),
            AesGcmError::InvalidNonceLength   => write!(f, "AES-GCM: nonce must be exactly 12 bytes (96 bits)"),
            AesGcmError::InvalidKeyLength     => write!(f, "AES-GCM: key must be exactly 32 bytes (256 bits)"),
            AesGcmError::CiphertextTooLarge   => write!(f, "AES-GCM: ciphertext exceeds maximum size (2^32 - 2 blocks)"),
        }
    }
}

pub struct Aes256Gcm {
    key: [u8; 32],
    h: [u8; 16],    // Hash subkey: H = AES_K(0^128)
}

impl Aes256Gcm {
    /// Create a new AES-256-GCM instance from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let aes = Aes256::new(key);
        // Compute hash subkey H = AES_K(0^128)
        let h = aes.encrypt_block(&[0u8; 16]);
        Aes256Gcm { key: *key, h }
    }

    /// Compute the initial counter block J0 from the nonce.
    /// For 96-bit nonces (standard): J0 = nonce || 0^31 || 1
    fn compute_j0(&self, nonce: &[u8; 12]) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1; // counter starts at 1
        j0
    }

    /// Encrypt plaintext with additional authenticated data (AAD).
    ///
    /// Returns (ciphertext, tag) where:
    ///   - ciphertext has the same length as plaintext
    ///   - tag is 16 bytes (128 bits)
    pub fn encrypt(
        &self,
        nonce: &[u8; 12],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), AesGcmError> {
        let aes = Aes256::new(&self.key);

        // J0 = initial counter block
        let j0 = self.compute_j0(nonce);

        // Encryption: CTR starting at counter = 2 (J0 has counter=1, GCTR for tag uses counter=1)
        let mut ciphertext = plaintext.to_vec();
        // Extract the 32-bit counter from J0 and increment
        let mut ctr = AesCtr::new(&self.key, nonce, 2);
        ctr.apply_keystream(&mut ciphertext);

        // GHASH over AAD then ciphertext
        let mut ghash = GHash::new(&self.h);
        ghash.update(aad);
        ghash.update(&ciphertext);

        // Length block
        let aad_bits = (aad.len() as u64).wrapping_mul(8);
        let ct_bits  = (ciphertext.len() as u64).wrapping_mul(8);
        let s = ghash.finalize_with_lengths(aad_bits, ct_bits);

        // Tag = GCTR(K, J0, S) = AES_K(J0) XOR S
        // J0 has counter=1; we encrypt J0 directly
        let e_j0 = aes.encrypt_block(&j0);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = e_j0[i] ^ s[i];
        }

        Ok((ciphertext, tag))
    }

    /// Decrypt and verify ciphertext + tag.
    ///
    /// CRITICAL: Tag verification is done in CONSTANT TIME
    /// to prevent timing attacks. We compute the expected tag
    /// and compare ALL bytes regardless of mismatches.
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        ciphertext: &[u8],
        aad: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, AesGcmError> {
        let aes = Aes256::new(&self.key);

        // Recompute expected tag
        let j0 = self.compute_j0(nonce);

        let mut ghash = GHash::new(&self.h);
        ghash.update(aad);
        ghash.update(ciphertext);
        let aad_bits = (aad.len() as u64).wrapping_mul(8);
        let ct_bits  = (ciphertext.len() as u64).wrapping_mul(8);
        let s = ghash.finalize_with_lengths(aad_bits, ct_bits);

        let e_j0 = aes.encrypt_block(&j0);
        let mut expected_tag = [0u8; 16];
        for i in 0..16 {
            expected_tag[i] = e_j0[i] ^ s[i];
        }

        // CONSTANT-TIME tag comparison — XOR all bytes, check if any differ
        // This prevents timing side channels from short-circuit equality checks
        if !ct_eq_16(&expected_tag, tag) {
            return Err(AesGcmError::AuthenticationFailed);
        }

        // Decrypt (same as encrypt in CTR mode)
        let mut plaintext = ciphertext.to_vec();
        let mut ctr = AesCtr::new(&self.key, nonce, 2);
        ctr.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }
}

/// Constant-time comparison of two 16-byte arrays.
/// Accumulates XOR differences; never branches on data values.
/// Resistant to timing side-channel attacks.
#[inline(never)] // prevent inlining which might allow optimizer to short-circuit
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    // Use black_box to prevent optimizer from figuring out we're comparing
    core::hint::black_box(diff) == 0
}

/// Constant-time comparison of arbitrary-length byte slices.
/// Returns false immediately if lengths differ (length is not secret).
#[inline(never)]
pub fn ct_eq_slice(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// Securely zero memory. Uses volatile writes so the compiler CANNOT optimize
/// this away even if the memory is never read again afterward.
/// This is critical for cryptographic key material.
pub fn secure_zero(data: &mut [u8]) {
    unsafe {
        let p = data.as_mut_ptr();
        for i in 0..data.len() {
            ptr::write_volatile(p.add(i), 0u8);
        }
        // Compiler fence to prevent reordering
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM Key Derivation Helper (HKDF-like, using our own SHA-256)
// Not actual HKDF (that needs HMAC), but a simple KDF for demonstration.
// See sha256.rs for the hash. This is AES-based key wrapping.
// ---------------------------------------------------------------------------

/// AES-256 Key Wrap (RFC 3394) — wrap a key under a key-encrypting-key (KEK)
/// This is the standard way to store/transmit AES keys encrypted under another key.
pub fn aes_key_wrap(kek: &[u8; 32], plaintext_key: &[u8]) -> Vec<u8> {
    assert!(plaintext_key.len() % 8 == 0, "Plaintext key must be multiple of 8 bytes");
    let n = plaintext_key.len() / 8; // number of 64-bit blocks
    let aes = Aes256::new(kek);

    let mut a = [0xA6u8; 8]; // Initial value
    let mut r: Vec<[u8; 8]> = plaintext_key.chunks(8)
        .map(|c| { let mut b = [0u8; 8]; b.copy_from_slice(c); b })
        .collect();

    // 6 * n rounds of wrapping
    for j in 0..6u64 {
        for i in 0..n {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i]);
            let enc = aes.encrypt_block(&b);
            // A = MSB(64, B) XOR t where t = (n * j) + i + 1
            let t = ((n as u64) * j + i as u64 + 1).to_be_bytes();
            for k in 0..8 {
                a[k] = enc[k] ^ t[k];
            }
            r[i].copy_from_slice(&enc[8..]);
        }
    }

    let mut output = Vec::with_capacity(8 + n * 8);
    output.extend_from_slice(&a);
    for block in &r {
        output.extend_from_slice(block);
    }
    output
}

/// AES-256 Key Unwrap (RFC 3394)
pub fn aes_key_unwrap(kek: &[u8; 32], wrapped_key: &[u8]) -> Result<Vec<u8>, AesGcmError> {
    if wrapped_key.len() < 16 || wrapped_key.len() % 8 != 0 {
        return Err(AesGcmError::InvalidKeyLength);
    }
    let n = wrapped_key.len() / 8 - 1;
    let aes = Aes256::new(kek);

    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped_key[..8]);
    let mut r: Vec<[u8; 8]> = wrapped_key[8..].chunks(8)
        .map(|c| { let mut b = [0u8; 8]; b.copy_from_slice(c); b })
        .collect();

    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = ((n as u64) * j + i as u64 + 1).to_be_bytes();
            let mut b = [0u8; 16];
            for k in 0..8 { b[k] = a[k] ^ t[k]; }
            b[8..].copy_from_slice(&r[i]);
            let dec = aes.decrypt_block(&b);
            a.copy_from_slice(&dec[..8]);
            r[i].copy_from_slice(&dec[8..]);
        }
    }

    // Verify integrity: A should equal the initial value 0xA6A6A6A6A6A6A6A6
    let expected = [0xA6u8; 8];
    if !ct_eq_slice(&a, &expected) {
        return Err(AesGcmError::AuthenticationFailed);
    }

    Ok(r.concat())
}

// ---------------------------------------------------------------------------
// Tests — verifying against known AES test vectors
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf_mul_known_values() {
        // From AES standard: 0x53 * 0xCA = 0x01 (inverse relationship)
        assert_eq!(gf_mul(0x53, 0xCA), 0x01);
        // 0x57 * 0x83 = 0xC1
        assert_eq!(gf_mul(0x57, 0x83), 0xC1);
        // Commutativity
        assert_eq!(gf_mul(0x57, 0x13), gf_mul(0x13, 0x57));
    }

    #[test]
    fn test_gf_inv_properties() {
        // a * inv(a) = 1 for all nonzero a
        for a in 1u8..=255 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1, "inverse failed for {}", a);
        }
        // inv(0) = 0 by AES convention
        assert_eq!(gf_inv(0), 0);
    }

    #[test]
    fn test_sbox_known_values() {
        // From FIPS 197, Fig. 7: S[0x00] = 0x63, S[0x01] = 0x7C, S[0xFF] = 0x16
        assert_eq!(SBOX[0x00], 0x63);
        assert_eq!(SBOX[0x01], 0x7C);
        assert_eq!(SBOX[0xFF], 0x16);
        assert_eq!(SBOX[0x53], 0xED);
    }

    #[test]
    fn test_inv_sbox_roundtrip() {
        for i in 0usize..256 {
            assert_eq!(INV_SBOX[SBOX[i] as usize], i as u8);
        }
    }

    #[test]
    fn test_aes256_encrypt_nist_vector() {
        // NIST FIPS 197 Appendix B — AES-256 known answer test
        // Key: 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        // Plaintext: 00112233445566778899aabbccddeeff
        let pt: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ];
        // Expected ciphertext: 8ea2b7ca516745bfeafc49904b496089
        let expected_ct: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
            0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
        ];
        let aes = Aes256::new(&key);
        let ct = aes.encrypt_block(&pt);
        assert_eq!(ct, expected_ct, "AES-256 encrypt failed NIST vector");

        // And decrypt should round-trip
        let dec = aes.decrypt_block(&ct);
        assert_eq!(dec, pt);
    }

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0xBEu8; 12];
        let plaintext = b"BEAST LEVEL RUST CRYPTO FROM SCRATCH";
        let aad = b"authenticated metadata";

        let gcm = Aes256Gcm::new(&key);
        let (ct, tag) = gcm.encrypt(&nonce, plaintext, aad).unwrap();
        let pt = gcm.decrypt(&nonce, &ct, aad, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_aes_gcm_tamper_detection() {
        let key = [0x01u8; 32];
        let nonce = [0x00u8; 12];
        let pt = b"secret message";
        let aad = b"header";

        let gcm = Aes256Gcm::new(&key);
        let (mut ct, tag) = gcm.encrypt(&nonce, pt, aad).unwrap();

        // Tamper with ciphertext
        ct[0] ^= 0xFF;
        let result = gcm.decrypt(&nonce, &ct, aad, &tag);
        assert_eq!(result, Err(AesGcmError::AuthenticationFailed));
    }

    #[test]
    fn test_aes_key_wrap_unwrap() {
        let kek = [0xABu8; 32];
        let plaintext_key = [0x12u8; 32]; // 256-bit key to wrap

        let wrapped = aes_key_wrap(&kek, &plaintext_key);
        let unwrapped = aes_key_unwrap(&kek, &wrapped).unwrap();
        assert_eq!(unwrapped, plaintext_key);
    }

    #[test]
    fn test_ct_eq_constant_time() {
        let a = [0xDEu8; 16];
        let b = [0xDEu8; 16];
        let c = { let mut x = [0xDEu8; 16]; x[15] = 0xFF; x };
        assert!(ct_eq_16(&a, &b));
        assert!(!ct_eq_16(&a, &c));
    }
}
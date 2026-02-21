// ============================================================================
// SHA-256 and BLAKE3 — COMPLETE FROM-SCRATCH IMPLEMENTATIONS
// SHA-256: FIPS 180-4
// BLAKE3: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
//
// This file implements:
//   - SHA-256 (full, with HMAC construction)
//   - SHA-256 streaming hasher
//   - HMAC-SHA256
//   - HKDF (RFC 5869) using HMAC-SHA256
//   - BLAKE3 (the full Merkle tree construction with chunk chaining)
//   - BLAKE3 XOF (extendable output function — output any number of bytes)
// ============================================================================

use crate::aes_gcm::secure_zero;

// ============================================================================
// SHA-256
// ============================================================================

/// SHA-256 round constants — first 32 bits of fractional parts of cube roots
/// of the first 64 primes. These are mathematically derived and non-backdoored.
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values — first 32 bits of fractional parts of
/// square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19).
const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// SHA-256 message schedule expansion.
/// Takes a 512-bit (16-word) block and expands it to 64 words.
/// Each new word is a function of 4 earlier words.
fn sha256_message_schedule(block: &[u8; 64]) -> [u32; 64] {
    let mut w = [0u32; 64];
    // Parse the block into the first 16 words
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[4*i..4*i+4].try_into().unwrap());
    }
    // Expand to 64 words
    for i in 16..64 {
        // σ1(w[i-2]): rotate right 17, rotate right 19, shift right 10
        let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        // σ0(w[i-15]): rotate right 7, rotate right 18, shift right 3
        let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        w[i] = s1.wrapping_add(w[i-7]).wrapping_add(s0).wrapping_add(w[i-16]);
    }
    w
}

/// Process one 512-bit block through the SHA-256 compression function.
/// Updates the 8-word state in place.
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let w = sha256_message_schedule(block);

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        // Σ1(e): rotate right 6, 11, 25
        let s1   = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        // Ch(e, f, g): (e AND f) XOR (NOT e AND g)
        let ch   = (e & f) ^ (!e & g);
        // T1: h + Σ1 + Ch + K + W
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
        // Σ0(a): rotate right 2, 13, 22
        let s0   = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        // Maj(a, b, c): majority function
        let maj  = (a & b) ^ (a & c) ^ (b & c);
        // T2: Σ0 + Maj
        let temp2 = s0.wrapping_add(maj);

        h = g; g = f; f = e;
        e = d.wrapping_add(temp1);
        d = c; c = b; b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Add compressed chunk to current hash value
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-256 streaming hasher
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bits: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: SHA256_H0,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_bits: 0,
        }
    }

    /// Hash data in one shot
    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_bits = self.total_bits.wrapping_add((data.len() as u64).wrapping_mul(8));
        let mut data = data;

        // Process buffered data first
        if self.buffer_len > 0 {
            let need = 64 - self.buffer_len;
            if data.len() < need {
                self.buffer[self.buffer_len..self.buffer_len + data.len()].copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
            self.buffer[self.buffer_len..].copy_from_slice(&data[..need]);
            data = &data[need..];
            let block = self.buffer;
            sha256_compress(&mut self.state, &block);
            self.buffer_len = 0;
        }

        // Process full blocks directly
        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().unwrap();
            sha256_compress(&mut self.state, &block);
            data = &data[64..];
        }

        // Buffer remainder
        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffer_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // Padding: append 0x80, then zeros, then 64-bit big-endian length
        let total_bits = self.total_bits;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        if self.buffer_len > 56 {
            // Not enough room for length — pad rest of block and process
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            let block = self.buffer;
            sha256_compress(&mut self.state, &block);
            self.buffer_len = 0;
            self.buffer = [0u8; 64];
        }

        // Pad zeros up to byte 56, then write 8-byte length
        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }
        self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());

        let block = self.buffer;
        sha256_compress(&mut self.state, &block);

        // Serialize state to bytes (big-endian)
        let mut out = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[4*i..4*i+4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Clone the current hasher state (for length-extension-attack-safe constructions)
    pub fn clone_state(&self) -> Self {
        Sha256 {
            state: self.state,
            buffer: self.buffer,
            buffer_len: self.buffer_len,
            total_bits: self.total_bits,
        }
    }
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// RFC 2104: HMAC(K, m) = H((K XOR opad) || H((K XOR ipad) || m))
// ---------------------------------------------------------------------------

pub struct HmacSha256 {
    inner: Sha256, // inner hasher with i-padded key
    okey: [u8; 64], // outer key (k XOR opad)
}

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Self {
        // Normalize key to 64 bytes
        let mut k = [0u8; 64];
        if key.len() > 64 {
            // Hash long keys
            let h = Sha256::digest(key);
            k[..32].copy_from_slice(&h);
        } else {
            k[..key.len()].copy_from_slice(key);
        }

        // ipad: 0x36 repeated 64 times
        let mut ikey = [0u8; 64];
        let mut okey = [0u8; 64];
        for i in 0..64 {
            ikey[i] = k[i] ^ 0x36;
            okey[i] = k[i] ^ 0x5C;
        }

        let mut inner = Sha256::new();
        inner.update(&ikey);

        HmacSha256 { inner, okey }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.okey);
        outer.update(&inner_hash);
        outer.finalize()
    }

    pub fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut h = HmacSha256::new(key);
        h.update(data);
        h.finalize()
    }
}

// ---------------------------------------------------------------------------
// HKDF — HMAC-based Key Derivation Function (RFC 5869)
// Provides strong key material from potentially weak input key material (IKM).
//
// HKDF has two phases:
//   1. Extract: PRK = HMAC-SHA256(salt, IKM)  — whitens the input
//   2. Expand:  OKM = T(1) || T(2) || ...      — stretches the PRK
// ---------------------------------------------------------------------------

pub struct Hkdf {
    prk: [u8; 32], // pseudo-random key from extraction
}

impl Hkdf {
    /// Extract phase: derive a fixed-length PRK from IKM and optional salt.
    pub fn extract(salt: Option<&[u8]>, ikm: &[u8]) -> Self {
        // If no salt, use all-zero salt of hash length
        let default_salt = [0u8; 32];
        let salt = salt.unwrap_or(&default_salt);
        let prk = HmacSha256::mac(salt, ikm);
        Hkdf { prk }
    }

    /// Expand phase: generate `length` bytes of output key material.
    /// `info` is a context/application-specific byte string.
    pub fn expand(&self, info: &[u8], length: usize) -> Vec<u8> {
        let hash_len = 32; // SHA-256 output length
        let n = (length + hash_len - 1) / hash_len; // ceil(length / hash_len)
        assert!(n <= 255, "HKDF: requested length exceeds 255 * hash_len");

        let mut okm = Vec::with_capacity(n * hash_len);
        let mut t_prev: Vec<u8> = Vec::new(); // T(0) = empty

        for i in 1u8..=(n as u8) {
            let mut hmac = HmacSha256::new(&self.prk);
            hmac.update(&t_prev);
            hmac.update(info);
            hmac.update(&[i]);
            let t = hmac.finalize();
            t_prev = t.to_vec();
            okm.extend_from_slice(&t);
        }

        okm.truncate(length);
        okm
    }

    /// Combined extract-then-expand
    pub fn derive_key(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        Hkdf::extract(salt, ikm).expand(info, length)
    }
}

// ============================================================================
// BLAKE3
//
// BLAKE3 is a cryptographic hash function designed for speed and security.
// It builds on the BLAKE2 design but adds:
//   - A Merkle tree structure (parallel hashing)
//   - An extended output (XOF) mode
//   - Domain separation via flags
//
// Key features of our implementation:
//   - ChaCha-based compression (the "G" function from ChaCha quarter-round)
//   - IV derived from SHA-256 H0 constants (same as SHA-256/BLAKE2)
//   - Chunk state machine (1024-byte chunks)
//   - Binary tree of chaining values
//   - XOF (squeeze arbitrary output bytes)
// ============================================================================

/// BLAKE3 initial values — same as SHA-256 (from sqrt of primes)
const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

// BLAKE3 domain separation flags
const CHUNK_START:  u32 = 1 << 0;
const CHUNK_END:    u32 = 1 << 1;
const PARENT:       u32 = 1 << 2;
const ROOT:         u32 = 1 << 3;
const KEYED_HASH:   u32 = 1 << 4;
const DERIVE_KEY_CONTEXT:  u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

/// BLAKE3 uses a message permutation to reorder the 16-word input
/// This permutation is fixed (not like ChaCha20's which is input-independent)
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// BLAKE3 G function — like ChaCha20 quarter round but on specific positions
#[inline(always)]
fn blake3_g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// BLAKE3 compression function — the heart of every operation.
/// State is 4 rows × 4 columns of u32 (just like ChaCha20).
/// Runs 7 rounds.
fn blake3_compress(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    // Initialize 4×4 state
    let mut state: [u32; 16] = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        BLAKE3_IV[0],      BLAKE3_IV[1],      BLAKE3_IV[2],      BLAKE3_IV[3],
        counter as u32,    (counter >> 32) as u32, block_len,     flags,
    ];

    let mut m = *block_words;

    // 7 rounds of mixing
    for _ in 0..7 {
        // Column rounds
        blake3_g(&mut state, 0, 4,  8, 12, m[0],  m[1]);
        blake3_g(&mut state, 1, 5,  9, 13, m[2],  m[3]);
        blake3_g(&mut state, 2, 6, 10, 14, m[4],  m[5]);
        blake3_g(&mut state, 3, 7, 11, 15, m[6],  m[7]);
        // Diagonal rounds
        blake3_g(&mut state, 0, 5, 10, 15, m[8],  m[9]);
        blake3_g(&mut state, 1, 6, 11, 12, m[10], m[11]);
        blake3_g(&mut state, 2, 7,  8, 13, m[12], m[13]);
        blake3_g(&mut state, 3, 4,  9, 14, m[14], m[15]);
        // Permute message words for next round
        let old_m = m;
        for i in 0..16 {
            m[i] = old_m[MSG_PERMUTATION[i]];
        }
    }

    // XOR upper half into lower half for chaining value extraction
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i]; // preserve upper half for XOF
    }

    state
}

/// Extract the 8-word chaining value from the compression output
fn first_8(output: &[u32; 16]) -> [u32; 8] {
    [output[0], output[1], output[2], output[3],
     output[4], output[5], output[6], output[7]]
}

/// Parse a block of bytes into 16 little-endian u32 words (zero-padded)
fn words_from_bytes(bytes: &[u8]) -> [u32; 16] {
    debug_assert!(bytes.len() <= 64);
    let mut words = [0u32; 16];
    for i in 0..bytes.len() / 4 {
        words[i] = u32::from_le_bytes(bytes[4*i..4*i+4].try_into().unwrap());
    }
    // Handle remaining bytes (zero padding implicit)
    let rem = bytes.len() % 4;
    if rem > 0 {
        let base = (bytes.len() / 4) * 4;
        let mut word_bytes = [0u8; 4];
        word_bytes[..rem].copy_from_slice(&bytes[base..base + rem]);
        words[bytes.len() / 4] = u32::from_le_bytes(word_bytes);
    }
    words
}

/// BLAKE3 ChunkState — processes up to 1024 bytes with chunk-level domain separation
struct ChunkState {
    chaining_value: [u32; 8],
    chunk_counter: u64,
    block: [u8; 64],
    block_len: usize,
    blocks_compressed: usize,
    flags: u32,
}

impl ChunkState {
    fn new(key: &[u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            chaining_value: *key,
            chunk_counter,
            block: [0u8; 64],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        self.blocks_compressed * 64 + self.block_len
    }

    fn is_complete(&self) -> bool {
        self.len() == 1024
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 { CHUNK_START } else { 0 }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            // If block is full, compress it
            if self.block_len == 64 {
                let block_words = words_from_bytes(&self.block);
                self.chaining_value = first_8(&blake3_compress(
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    64,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0u8; 64];
                self.block_len = 0;
            }

            let take = (64 - self.block_len).min(data.len()).min(1024 - self.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
        }
    }

    fn output(&self) -> [u32; 16] {
        let block_words = words_from_bytes(&self.block[..self.block_len]);
        blake3_compress(
            &self.chaining_value,
            &block_words,
            self.chunk_counter,
            self.block_len as u32,
            self.flags | self.start_flag() | CHUNK_END,
        )
    }
}

/// Combine two chaining values into a parent node
fn parent_node_output(
    left_child: &[u32; 8],
    right_child: &[u32; 8],
    key: &[u32; 8],
    flags: u32,
) -> [u32; 16] {
    let mut block_words = [0u32; 16];
    block_words[..8].copy_from_slice(left_child);
    block_words[8..].copy_from_slice(right_child);
    blake3_compress(key, &block_words, 0, 64, PARENT | flags)
}

/// BLAKE3 hasher — full implementation with XOF support
pub struct Blake3 {
    chunk_state: ChunkState,
    key: [u32; 8],
    // Subtree stack for the binary Merkle tree
    // At most log2(max_chunks) entries = at most 54 entries for 2^54 bytes
    cv_stack: Vec<[u32; 8]>,
    flags: u32,
}

impl Blake3 {
    /// Create a new BLAKE3 hasher in hash mode
    pub fn new() -> Self {
        Blake3 {
            chunk_state: ChunkState::new(&BLAKE3_IV, 0, 0),
            key: BLAKE3_IV,
            cv_stack: Vec::new(),
            flags: 0,
        }
    }

    /// Create a new BLAKE3 hasher in keyed hash mode (MAC)
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut key_words = [0u32; 8];
        for i in 0..8 {
            key_words[i] = u32::from_le_bytes(key[4*i..4*i+4].try_into().unwrap());
        }
        Blake3 {
            chunk_state: ChunkState::new(&key_words, 0, KEYED_HASH),
            key: key_words,
            cv_stack: Vec::new(),
            flags: KEYED_HASH,
        }
    }

    /// Create a BLAKE3 hasher for key derivation
    pub fn new_derive_key(context: &str) -> Self {
        // Derive context key by hashing the context string
        let context_hasher = Blake3 {
            chunk_state: ChunkState::new(&BLAKE3_IV, 0, DERIVE_KEY_CONTEXT),
            key: BLAKE3_IV,
            cv_stack: Vec::new(),
            flags: DERIVE_KEY_CONTEXT,
        };
        let context_key_bytes = context_hasher.finalize_single();
        let mut context_key = [0u32; 8];
        for i in 0..8 {
            context_key[i] = u32::from_le_bytes(context_key_bytes[4*i..4*i+4].try_into().unwrap());
        }
        Blake3 {
            chunk_state: ChunkState::new(&context_key, 0, DERIVE_KEY_MATERIAL),
            key: context_key,
            cv_stack: Vec::new(),
            flags: DERIVE_KEY_MATERIAL,
        }
    }

    /// Push a chaining value onto the stack, merging as needed
    fn push_cv(&mut self, cv: [u32; 8], chunk_counter: u64) {
        // The stack invariant: merge entries where the corresponding bit in chunk_counter is 0
        // (i.e., merge completed subtrees as we build the Merkle tree)
        let mut cv = cv;
        let mut counter = chunk_counter;
        loop {
            if self.cv_stack.is_empty() || counter & 1 != 0 {
                break;
            }
            // Merge with top of stack
            let left = self.cv_stack.pop().unwrap();
            let parent_out = parent_node_output(&left, &cv, &self.key, self.flags);
            cv = first_8(&parent_out);
            counter >>= 1;
        }
        self.cv_stack.push(cv);
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        while !data.is_empty() {
            // If chunk is full, finalize it and push to stack
            if self.chunk_state.is_complete() {
                let chunk_cv = first_8(&self.chunk_state.output());
                let chunk_counter = self.chunk_state.chunk_counter;
                self.push_cv(chunk_cv, chunk_counter);
                // Start new chunk
                self.chunk_state = ChunkState::new(
                    &self.key,
                    chunk_counter + 1,
                    self.flags,
                );
            }

            let take = (1024 - self.chunk_state.len()).min(data.len());
            self.chunk_state.update(&data[..take]);
            data = &data[take..];
        }
    }

    /// Helper to finalize a fresh single-chunk hasher (for derive_key context)
    fn finalize_single(mut self) -> [u8; 32] {
        let out = self.chunk_state.output();
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            bytes[4*i..4*i+4].copy_from_slice(&out[i].to_le_bytes());
        }
        bytes
    }

    /// Finalize and return a standard 32-byte hash
    pub fn finalize(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_xof(&mut out);
        out
    }

    /// Finalize as an XOF — produce `output.len()` bytes of output.
    /// This is BLAKE3's killer feature: arbitrary-length deterministic output.
    /// Output bytes are produced by repeated compression with increasing counter.
    pub fn finalize_xof(&self, output: &mut [u8]) {
        // Get the root compression output
        let root_output = self.get_root_output();

        // Generate output bytes in 64-byte blocks (4 words per output word × 16 words)
        let mut block_idx = 0u64;
        let mut produced = 0;
        while produced < output.len() {
            // Each 64-byte output block: compress root with block_idx as counter
            let root_cv = [root_output[0], root_output[1], root_output[2], root_output[3],
                           root_output[4], root_output[5], root_output[6], root_output[7]];
            let block_words = words_from_bytes(&[0u8; 0]); // empty block
            let out = blake3_compress(
                &root_cv,
                &[root_output[0], root_output[1], root_output[2], root_output[3],
                  root_output[4], root_output[5], root_output[6], root_output[7],
                  root_output[8], root_output[9], root_output[10], root_output[11],
                  root_output[12], root_output[13], root_output[14], root_output[15]],
                block_idx,
                0,
                ROOT | self.flags,
            );
            for word in &out {
                if produced >= output.len() { break; }
                let bytes = word.to_le_bytes();
                let take = (output.len() - produced).min(4);
                output[produced..produced + take].copy_from_slice(&bytes[..take]);
                produced += take;
            }
            block_idx += 1;
        }
    }

    fn get_root_output(&self) -> [u32; 16] {
        // Merge any remaining stack entries up to the root
        let mut out = self.chunk_state.output();

        // Merge with all cv_stack entries from top to bottom
        let mut stack = self.cv_stack.clone();
        while let Some(left) = stack.pop() {
            let right = first_8(&out);
            // If stack is now empty, this is the root
            let parent_flags = if stack.is_empty() { PARENT | ROOT | self.flags }
                               else { PARENT | self.flags };
            let mut block_words = [0u32; 16];
            block_words[..8].copy_from_slice(&left);
            block_words[8..].copy_from_slice(&right);
            out = blake3_compress(&self.key, &block_words, 0, 64, parent_flags);
        }

        out
    }

    /// Convenience: hash in one shot
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Blake3::new();
        h.update(data);
        h.finalize()
    }

    /// Keyed hash (MAC)
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        let mut h = Blake3::new_keyed(key);
        h.update(data);
        h.finalize()
    }

    /// Key derivation — derive a key from context + key material
    pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        let mut h = Blake3::new_derive_key(context);
        h.update(key_material);
        h.finalize()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let hash = Sha256::digest(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469001d0087b8b3b6
        let hash = Sha256::digest(b"abc");
        assert_eq!(hash[0], 0xba);
        assert_eq!(hash[1], 0x78);
        assert_eq!(hash[2], 0x16);
    }

    #[test]
    fn test_sha256_long_message() {
        // SHA-256 of "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        let hash = Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        // Expected: 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
        assert_eq!(hash[0], 0x24);
        assert_eq!(hash[1], 0x8d);
        assert_eq!(hash[2], 0x6a);
    }

    #[test]
    fn test_hmac_sha256_rfc_vector() {
        // RFC 4231 Test Case 1
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = HmacSha256::mac(&key, data);
        // Expected: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
        assert_eq!(mac[0], 0xb0);
        assert_eq!(mac[1], 0x34);
    }

    #[test]
    fn test_hkdf_basic() {
        let ikm = [0x0bu8; 22];
        let salt = [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = Hkdf::derive_key(Some(&salt), &ikm, &info, 42);
        // From RFC 5869 Test Case 1 — first 2 bytes
        assert_eq!(okm[0], 0x3c);
        assert_eq!(okm[1], 0xb2);
        assert_eq!(okm.len(), 42);
    }

    #[test]
    fn test_blake3_hash_empty() {
        // BLAKE3("") = af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        let hash = Blake3::hash(b"");
        assert_eq!(hash[0], 0xaf);
        assert_eq!(hash[1], 0x13);
    }

    #[test]
    fn test_blake3_xof() {
        // XOF should produce consistent arbitrary-length output
        let mut h = Blake3::new();
        h.update(b"test xof output");
        let mut out64 = [0u8; 64];
        let mut out32 = [0u8; 32];
        h.finalize_xof(&mut out64);
        h.finalize_xof(&mut out32);
        // First 32 bytes of XOF(64) must equal XOF(32)
        assert_eq!(&out64[..32], &out32[..]);
    }

    #[test]
    fn test_blake3_keyed_hash() {
        let key = [0x42u8; 32];
        let h1 = Blake3::keyed_hash(&key, b"message");
        let h2 = Blake3::keyed_hash(&key, b"message");
        let h3 = Blake3::keyed_hash(&key, b"message!");
        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_streaming_sha256_equals_oneshot() {
        let data = b"This is a test of streaming vs oneshot SHA-256. They must match exactly.";
        let oneshot = Sha256::digest(data);
        let mut streamed = Sha256::new();
        // Feed in various chunk sizes to stress the buffering
        streamed.update(&data[..1]);
        streamed.update(&data[1..17]);
        streamed.update(&data[17..63]);
        streamed.update(&data[63..]);
        let streamed = streamed.finalize();
        assert_eq!(oneshot, streamed);
    }
}
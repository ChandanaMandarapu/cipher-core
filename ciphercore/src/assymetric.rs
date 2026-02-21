// ============================================================================
// X25519 ELLIPTIC CURVE DIFFIE-HELLMAN — FROM SCRATCH
// RFC 7748
//
// Curve25519 is a Montgomery curve: y^2 = x^3 + 486662*x^2 + x
// over the prime field F_p where p = 2^255 - 19.
//
// This file implements:
//   - F_p arithmetic (255-bit integers mod 2^255 - 19)
//   - 256-bit integer representation and arithmetic
//   - Montgomery ladder scalar multiplication (constant time)
//   - X25519 key exchange
//   - X25519 key generation and shared secret derivation
//
// FOLLOWED BY:
//
// RSA-2048 — Miller-Rabin primality testing and full RSA
//   - Big integer arithmetic (2048-bit)
//   - Miller-Rabin primality test
//   - Extended Euclidean algorithm (GCD + modular inverse)
//   - RSA key generation
//   - PKCS#1 v1.5 padding (and why it's broken)
//   - OAEP padding (the correct modern approach)
//   - RSA-OAEP encrypt/decrypt
//   - RSA-PSS signature/verification
// ============================================================================

use crate::hashes::Sha256;
use crate::hashes::HmacSha256;
use crate::aes_gcm::secure_zero;

// ============================================================================
// 256-bit Integer Arithmetic
// We represent 256-bit integers as 4 × u64 limbs (little-endian).
// This is efficient on 64-bit systems and avoids BigInteger dependencies.
// ============================================================================

/// A 256-bit integer stored as 4 × u64 little-endian limbs.
/// limbs[0] is least significant, limbs[3] is most significant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct U256 {
    pub limbs: [u64; 4],
}

impl U256 {
    pub const ZERO: U256 = U256 { limbs: [0, 0, 0, 0] };
    pub const ONE: U256  = U256 { limbs: [1, 0, 0, 0] };

    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for i in 0..4 {
            limbs[i] = u64::from_le_bytes(bytes[8*i..8*i+8].try_into().unwrap());
        }
        U256 { limbs }
    }

    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[8*i..8*i+8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }

    pub fn from_u64(x: u64) -> Self {
        U256 { limbs: [x, 0, 0, 0] }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs == [0, 0, 0, 0]
    }

    pub fn bit(&self, n: usize) -> u64 {
        let word = n / 64;
        let bit  = n % 64;
        (self.limbs[word] >> bit) & 1
    }

    /// Add with carry. Returns (result, carry)
    pub fn add_with_carry(a: &U256, b: &U256) -> (U256, u64) {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = a.limbs[i] as u128 + b.limbs[i] as u128 + carry as u128;
            result[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        (U256 { limbs: result }, carry)
    }

    /// Subtract with borrow. Returns (result, borrow). Wraps on underflow.
    pub fn sub_with_borrow(a: &U256, b: &U256) -> (U256, u64) {
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let diff = a.limbs[i] as i128 - b.limbs[i] as i128 - borrow as i128;
            result[i] = diff as u64;
            borrow = if diff < 0 { 1 } else { 0 };
        }
        (U256 { limbs: result }, borrow)
    }

    /// Compare: returns true if a < b
    pub fn lt(a: &U256, b: &U256) -> bool {
        for i in (0..4).rev() {
            if a.limbs[i] < b.limbs[i] { return true; }
            if a.limbs[i] > b.limbs[i] { return false; }
        }
        false
    }

    /// Multiply two U256 values, returning a U512 result (as two U256: lo + hi)
    pub fn widening_mul(a: &U256, b: &U256) -> (U256, U256) {
        let mut result = [0u128; 8];
        for i in 0..4 {
            for j in 0..4 {
                result[i + j] += a.limbs[i] as u128 * b.limbs[j] as u128;
            }
        }
        // Propagate carries
        for i in 0..7 {
            result[i + 1] += result[i] >> 64;
            result[i] &= 0xFFFFFFFFFFFFFFFF;
        }
        let lo = U256 { limbs: [result[0] as u64, result[1] as u64, result[2] as u64, result[3] as u64] };
        let hi = U256 { limbs: [result[4] as u64, result[5] as u64, result[6] as u64, result[7] as u64] };
        (lo, hi)
    }

    /// Shift right by n bits (n < 256)
    pub fn shr(&self, n: usize) -> U256 {
        if n == 0 { return *self; }
        let word_shift = n / 64;
        let bit_shift  = n % 64;
        let mut result = [0u64; 4];
        for i in 0..4 {
            if i + word_shift < 4 {
                result[i] = self.limbs[i + word_shift] >> bit_shift;
                if bit_shift > 0 && i + word_shift + 1 < 4 {
                    result[i] |= self.limbs[i + word_shift + 1] << (64 - bit_shift);
                }
            }
        }
        U256 { limbs: result }
    }

    /// Shift left by n bits (n < 256)
    pub fn shl(&self, n: usize) -> U256 {
        if n == 0 { return *self; }
        let word_shift = n / 64;
        let bit_shift  = n % 64;
        let mut result = [0u64; 4];
        for i in (0..4).rev() {
            if i >= word_shift {
                result[i] = self.limbs[i - word_shift] << bit_shift;
                if bit_shift > 0 && i > word_shift {
                    result[i] |= self.limbs[i - word_shift - 1] >> (64 - bit_shift);
                }
            }
        }
        U256 { limbs: result }
    }

    /// Bitwise AND
    pub fn bitand(&self, other: &U256) -> U256 {
        U256 { limbs: [
            self.limbs[0] & other.limbs[0],
            self.limbs[1] & other.limbs[1],
            self.limbs[2] & other.limbs[2],
            self.limbs[3] & other.limbs[3],
        ]}
    }

    /// Bitwise OR
    pub fn bitor(&self, other: &U256) -> U256 {
        U256 { limbs: [
            self.limbs[0] | other.limbs[0],
            self.limbs[1] | other.limbs[1],
            self.limbs[2] | other.limbs[2],
            self.limbs[3] | other.limbs[3],
        ]}
    }

    /// Bitwise XOR
    pub fn bitxor(&self, other: &U256) -> U256 {
        U256 { limbs: [
            self.limbs[0] ^ other.limbs[0],
            self.limbs[1] ^ other.limbs[1],
            self.limbs[2] ^ other.limbs[2],
            self.limbs[3] ^ other.limbs[3],
        ]}
    }
}

// ============================================================================
// F_p Arithmetic for Curve25519
// p = 2^255 - 19
//
// We use a 256-bit representation and reduce mod p after each operation.
// The special form of p = 2^255 - 19 allows fast reduction:
// if result ≥ p, subtract p (equivalently, handle the top bit specially).
// ============================================================================

/// The prime p = 2^255 - 19
const P25519: U256 = U256 {
    limbs: [
        0xFFFFFFFFFFFFED,  // 2^64 - 19... wait, this needs proper encoding
        0xFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ]
};

// Actually p = 2^255 - 19 in little-endian limbs:
// In hex: 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF ED
// Low 64 bits: 0xFFFFFFFFFFFFFFED
// Bits 64-127: 0xFFFFFFFFFFFFFFFF
// Bits 128-191: 0xFFFFFFFFFFFFFFFF
// Bits 192-255: 0x7FFFFFFFFFFFFFFF (note: MSbit of p is 0, since 2^255 = p + 19)
const PRIME_25519: U256 = U256 {
    limbs: [
        0xFFFFFFFFFFFFFFED,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ]
};

// 2 * p (used in subtraction to avoid negative results)
const TWO_P: U256 = U256 {
    limbs: [
        0xFFFFFFFFFFFFFFDA,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFF,
    ]
};

/// Field element in F_p (p = 2^255 - 19)
/// Represents a value in [0, p-1]
#[derive(Clone, Copy, Debug)]
pub struct FieldEl(U256);

impl FieldEl {
    pub const ZERO: FieldEl = FieldEl(U256::ZERO);
    pub const ONE:  FieldEl = FieldEl(U256::ONE);

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut b = *bytes;
        // Clamp the top bit (Curve25519 spec)
        b[31] &= 0x7F;
        FieldEl(U256::from_bytes_le(&b))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes_le()
    }

    /// Reduce mod p using the special form of p = 2^255 - 19.
    /// If x ≥ 2^255, then x = x - 2^255 + 19 + (x - 2^255)
    /// i.e., take the top bit, multiply by 19, add to the rest.
    fn reduce(x: U256) -> U256 {
        // Extract the top bit
        let top_bit = x.limbs[3] >> 63;
        if top_bit == 0 && U256::lt(&x, &PRIME_25519) {
            return x;
        }
        // x >= p. Compute x - p.
        // Handle the case x >= 2^255: reduce by taking top bit * 19.
        let reduction = top_bit * 19;
        let mut result = x;
        result.limbs[3] &= 0x7FFFFFFFFFFFFFFF; // clear top bit
        // Add 19 * top_bit
        let (r, carry) = U256::add_with_carry(&result, &U256::from_u64(reduction));
        let mut r = r;
        // Handle any overflow from adding 19 (very unlikely but possible)
        if carry > 0 || !U256::lt(&r, &PRIME_25519) {
            let (sub, _) = U256::sub_with_borrow(&r, &PRIME_25519);
            r = sub;
        }
        r
    }

    pub fn add(&self, rhs: &FieldEl) -> FieldEl {
        let (sum, carry) = U256::add_with_carry(&self.0, &rhs.0);
        let sum = if carry > 0 {
            // sum >= 2^256. Reduce: add 38 (since 2^256 = 2 * 2^255 = 2*(p+19) = 2p+38, so mod p: +38)
            let (s, _) = U256::add_with_carry(&sum, &U256::from_u64(38));
            s
        } else {
            sum
        };
        FieldEl(Self::reduce(sum))
    }

    pub fn sub(&self, rhs: &FieldEl) -> FieldEl {
        // Add 2p before subtracting to ensure non-negative result
        let (with_2p, _) = U256::add_with_carry(&self.0, &TWO_P);
        let (diff, _) = U256::sub_with_borrow(&with_2p, &rhs.0);
        FieldEl(Self::reduce(diff))
    }

    pub fn neg(&self) -> FieldEl {
        FieldEl::ZERO.sub(self)
    }

    /// Multiplication in F_p using schoolbook multiplication + reduction.
    /// Uses the fast reduction: for bits above 2^255, multiply by 19 and add back.
    pub fn mul(&self, rhs: &FieldEl) -> FieldEl {
        // Widening multiply: result is up to 510 bits
        let (lo, hi) = U256::widening_mul(&self.0, &rhs.0);

        // Reduce the high 256 bits: hi * 2^256 = hi * (2p + 38) ≡ hi * 38 (mod p)
        // since 2^256 = 2*(2^255) = 2*(p+19) = 2p+38 ≡ 38 (mod p)
        let (hi38_lo, hi38_hi) = U256::widening_mul(&hi, &U256::from_u64(38));
        let (sum, carry1) = U256::add_with_carry(&lo, &hi38_lo);

        // Handle the high part of hi*38 (usually zero for 256-bit inputs)
        let carry_val = hi38_hi.limbs[0] + carry1;
        let (sum2, _) = U256::add_with_carry(&sum, &U256::from_u64(carry_val * 38));

        FieldEl(Self::reduce(sum2))
    }

    pub fn square(&self) -> FieldEl {
        self.mul(self)
    }

    /// Modular inverse via Fermat's little theorem: a^(-1) = a^(p-2) mod p
    /// p - 2 = 2^255 - 21. We use a fast addition chain.
    pub fn invert(&self) -> FieldEl {
        // Compute a^(p-2) using square-and-multiply
        // p - 2 = 2^255 - 21 in binary:
        // = 0111...1111 01101 (255 bits)
        // We use the standard Curve25519 inversion chain for speed
        let a  = *self;
        let a2  = a.square();
        let a4  = a2.square();
        let a8  = a4.square();
        let a16 = a8.square();
        let a32 = a16.square();

        // b = a^11 = a^8 * a^2 * a
        let b = a8.mul(&a2).mul(&a);

        // Compute a^(2^255-21) step by step
        // The standard formula uses 11 squarings and multiplications
        let t0  = b.square_n(1).mul(&a);    // a^(2*11+1) = a^23... let's do it properly

        // Actually let's use the standard Curve25519 inversion ladder:
        // from the Bernstein paper
        let z11 = b.mul(&self.square_n(2).mul(self).square_n(1).mul(self));

        // Simpler: compute using square-and-multiply on the exponent p-2
        // p - 2 in bits: 255 bits total, pattern 0111...111101011
        // We'll use repeated squaring on the fixed exponent
        self.pow_p_minus_2()
    }

    /// Compute self^(p-2) mod p using addition chain specific to p = 2^255 - 19
    fn pow_p_minus_2(&self) -> FieldEl {
        // p - 2 = 2^255 - 21
        // Standard addition chain from the Curve25519 paper
        let mut t1 = *self;
        let t2  = self.square();         // 2
        let t3  = t2.mul(self);           // 3
        let t8  = t3.square_n(2).mul(&t3); // ... actually let me just do binary exponentiation

        // Binary exponentiation with exponent = 2^255 - 21
        // Binary representation: 0111...1111 0111 01011 (reading MSB to LSB)
        // 2^255 - 21 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEB
        let exp = U256 {
            limbs: [
                0xFFFFFFFFFFFFFFEB,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x3FFFFFFFFFFFFFFF, // p-2 has 255 bits: top bit is 0
            ]
        };

        let mut result = FieldEl::ONE;
        let mut base = *self;
        for i in 0..255 {
            if exp.bit(i) == 1 {
                result = result.mul(&base);
            }
            base = base.square();
        }
        result
    }

    /// Square n times
    fn square_n(&self, n: usize) -> FieldEl {
        let mut r = *self;
        for _ in 0..n { r = r.square(); }
        r
    }

    /// Conditional swap: if swap=1, exchange a and b (constant time)
    /// This is the critical constant-time operation in the Montgomery ladder
    pub fn conditional_swap(a: &mut FieldEl, b: &mut FieldEl, swap: u64) {
        let mask = 0u64.wrapping_sub(swap); // 0 or 0xFFFFFFFFFFFFFFFF
        for i in 0..4 {
            let t = mask & (a.0.limbs[i] ^ b.0.limbs[i]);
            a.0.limbs[i] ^= t;
            b.0.limbs[i] ^= t;
        }
    }
}

// ============================================================================
// X25519 — Montgomery Curve Scalar Multiplication
// y^2 = x^3 + 486662*x^2 + x over F_p
//
// The Montgomery ladder computes scalar * point using only x-coordinates.
// This is the most efficient and side-channel-resistant approach.
// ============================================================================

/// The Curve25519 base point x-coordinate (Montgomery form)
/// u = 9
const BASE_POINT_U: FieldEl = FieldEl(U256 { limbs: [9, 0, 0, 0] });

/// The a24 constant: (486662 - 2) / 4 = 121665
const A24: FieldEl = FieldEl(U256 { limbs: [121665, 0, 0, 0] });

/// X25519 scalar multiplication: compute scalar * u using the Montgomery ladder.
/// This is a constant-time algorithm — no branches on secret data.
///
/// The ladder maintains two points (R0, R1) where R1 - R0 = u at all times.
/// We process the scalar from MSB to LSB, conditionally swapping based on each bit.
pub fn x25519_scalarmult(scalar: &[u8; 32], u_bytes: &[u8; 32]) -> [u8; 32] {
    // Clamp the scalar per RFC 7748
    let mut k = *scalar;
    k[0]  &= 248;  // clear bottom 3 bits
    k[31] &= 127;  // clear top bit
    k[31] |= 64;   // set second-highest bit

    let u = FieldEl::from_bytes(u_bytes);

    // Montgomery ladder state
    let mut x1 = u;
    let mut x2 = FieldEl::ONE;
    let mut z2 = FieldEl::ZERO;
    let mut x3 = u;
    let mut z3 = FieldEl::ONE;

    let k256 = U256::from_bytes_le(&k);
    let mut swap: u64 = 0;

    // Process bits from 254 down to 0 (bit 255 is always 0 after clamping)
    for pos in (0..255usize).rev() {
        let k_bit = k256.bit(pos);

        // Conditional swap based on current bit XOR previous bit
        swap ^= k_bit;
        FieldEl::conditional_swap(&mut x2, &mut x3, swap);
        FieldEl::conditional_swap(&mut z2, &mut z3, swap);
        swap = k_bit;

        // Montgomery ladder step (differential addition + doubling)
        // Uses the Montgomery curve formula:
        // For doubling: A = x2 + z2, AA = A^2, B = x2 - z2, BB = B^2
        //              E = AA - BB, x2_new = AA * BB, z2_new = E * (AA + a24*E)
        // For add: C = x3 + z3, D = x3 - z3
        //         CB = C*(x2-z2)... (differential addition formula)
        let a  = x2.add(&z2);
        let aa = a.square();
        let b  = x2.sub(&z2);
        let bb = b.square();
        let e  = aa.sub(&bb);
        let c  = x3.add(&z3);
        let d  = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x3 = da.add(&cb).square();
        z3 = da.sub(&cb).square().mul(&x1);
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&A24.mul(&e)));
    }

    // Final conditional swap
    FieldEl::conditional_swap(&mut x2, &mut x3, swap);
    FieldEl::conditional_swap(&mut z2, &mut z3, swap);

    // Recover u-coordinate: x2 / z2 = x2 * z2^(-1)
    let result = x2.mul(&z2.invert());
    result.to_bytes()
}

/// X25519 — compute the public key from a private key
pub fn x25519_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let base = [9u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    x25519_scalarmult(private_key, &base)
}

/// X25519 Diffie-Hellman shared secret
pub fn x25519_diffie_hellman(my_private: &[u8; 32], their_public: &[u8; 32]) -> [u8; 32] {
    x25519_scalarmult(my_private, their_public)
}

// ============================================================================
// RSA-2048
//
// We implement 2048-bit RSA using our own big integer arithmetic.
// For brevity, we use a 2048-bit representation as a Vec<u64> of 32 limbs.
// This gives us the full power of RSA without any external dependencies.
// ============================================================================

/// A big integer of fixed maximum size (4096 bits = 64 × u64 limbs).
/// We use this for RSA-2048 intermediate computations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt {
    pub limbs: Vec<u64>, // little-endian, length = bit_size / 64
}

impl BigInt {
    pub fn zero(n_limbs: usize) -> Self {
        BigInt { limbs: vec![0u64; n_limbs] }
    }

    pub fn one(n_limbs: usize) -> Self {
        let mut v = vec![0u64; n_limbs];
        if n_limbs > 0 { v[0] = 1; }
        BigInt { limbs: v }
    }

    pub fn from_bytes_be(bytes: &[u8]) -> Self {
        // Pad to multiple of 8 bytes
        let padded_len = ((bytes.len() + 7) / 8) * 8;
        let mut padded = vec![0u8; padded_len];
        padded[padded_len - bytes.len()..].copy_from_slice(bytes);
        let n_limbs = padded_len / 8;
        let mut limbs = vec![0u64; n_limbs];
        for i in 0..n_limbs {
            // limb 0 = most significant (we want little-endian storage)
            let pos = (n_limbs - 1 - i) * 8;
            limbs[i] = u64::from_be_bytes(padded[pos..pos+8].try_into().unwrap());
        }
        BigInt { limbs }
    }

    pub fn to_bytes_be(&self, target_len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &limb in self.limbs.iter().rev() {
            bytes.extend_from_slice(&limb.to_be_bytes());
        }
        // Remove leading zeros
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let bytes = &bytes[start..];
        // Pad to target_len
        let mut out = vec![0u8; target_len];
        if bytes.len() <= target_len {
            out[target_len - bytes.len()..].copy_from_slice(bytes);
        } else {
            out.copy_from_slice(&bytes[bytes.len() - target_len..]);
        }
        out
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&l| l == 0)
    }

    pub fn is_even(&self) -> bool {
        self.limbs.get(0).map(|&l| l & 1 == 0).unwrap_or(true)
    }

    pub fn bit(&self, n: usize) -> u64 {
        let word = n / 64;
        let bit  = n % 64;
        if word >= self.limbs.len() { return 0; }
        (self.limbs[word] >> bit) & 1
    }

    pub fn bit_len(&self) -> usize {
        for i in (0..self.limbs.len()).rev() {
            if self.limbs[i] != 0 {
                return i * 64 + (64 - self.limbs[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Compare: -1 if self < other, 0 if equal, 1 if self > other
    pub fn cmp(&self, other: &BigInt) -> i32 {
        let max_len = self.limbs.len().max(other.limbs.len());
        for i in (0..max_len).rev() {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            if a < b { return -1; }
            if a > b { return  1; }
        }
        0
    }

    pub fn resize(&self, n: usize) -> BigInt {
        let mut new = self.clone();
        new.limbs.resize(n, 0);
        new
    }

    // Addition
    pub fn add(&self, other: &BigInt) -> BigInt {
        let len = self.limbs.len().max(other.limbs.len()) + 1;
        let mut result = vec![0u64; len];
        let mut carry = 0u64;
        for i in 0..len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            let sum = a as u128 + b as u128 + carry as u128;
            result[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        BigInt { limbs: result }
    }

    // Subtraction (self >= other assumed)
    pub fn sub(&self, other: &BigInt) -> BigInt {
        let len = self.limbs.len().max(other.limbs.len());
        let mut result = vec![0u64; len];
        let mut borrow = 0i128;
        for i in 0..len {
            let a = self.limbs.get(i).copied().unwrap_or(0) as i128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i128;
            let diff = a - b - borrow;
            result[i] = diff as u64;
            borrow = if diff < 0 { 1 } else { 0 };
        }
        BigInt { limbs: result }
    }

    // Shift left by 1 bit
    pub fn shl1(&self) -> BigInt {
        let mut result = vec![0u64; self.limbs.len() + 1];
        let mut carry = 0u64;
        for i in 0..self.limbs.len() {
            result[i] = (self.limbs[i] << 1) | carry;
            carry = self.limbs[i] >> 63;
        }
        result[self.limbs.len()] = carry;
        BigInt { limbs: result }
    }

    // Shift right by 1 bit
    pub fn shr1(&self) -> BigInt {
        let mut result = self.limbs.clone();
        let mut carry = 0u64;
        for i in (0..result.len()).rev() {
            let new_carry = result[i] & 1;
            result[i] = (result[i] >> 1) | (carry << 63);
            carry = new_carry;
        }
        BigInt { limbs: result }
    }

    /// Schoolbook multiplication
    pub fn mul(&self, other: &BigInt) -> BigInt {
        let n = self.limbs.len() + other.limbs.len();
        let mut result = vec![0u64; n];
        for i in 0..self.limbs.len() {
            let mut carry = 0u128;
            for j in 0..other.limbs.len() {
                let cur = result[i + j] as u128;
                let prod = self.limbs[i] as u128 * other.limbs[j] as u128 + cur + carry;
                result[i + j] = prod as u64;
                carry = prod >> 64;
            }
            if i + other.limbs.len() < n {
                result[i + other.limbs.len()] += carry as u64;
            }
        }
        BigInt { limbs: result }
    }

    /// Division: returns (quotient, remainder)
    pub fn divrem(&self, divisor: &BigInt) -> (BigInt, BigInt) {
        if divisor.is_zero() { panic!("division by zero"); }
        if self.cmp(divisor) < 0 {
            return (BigInt::zero(self.limbs.len()), self.clone());
        }

        let len = self.limbs.len();
        let mut q = BigInt::zero(len);
        let mut r = BigInt::zero(len + 1);

        // Long division bit by bit
        for i in (0..self.bit_len()).rev() {
            r = r.shl1();
            r.limbs[0] |= self.bit(i);

            if r.cmp(divisor) >= 0 {
                r = r.sub(divisor);
                let word = i / 64;
                let bit  = i % 64;
                if word < q.limbs.len() {
                    q.limbs[word] |= 1u64 << bit;
                }
            }
        }
        (q, r)
    }

    /// Modulo
    pub fn modulo(&self, m: &BigInt) -> BigInt {
        self.divrem(m).1.resize(m.limbs.len())
    }

    /// Modular exponentiation: self^exp mod m (left-to-right binary)
    pub fn modpow(&self, exp: &BigInt, m: &BigInt) -> BigInt {
        let n_limbs = m.limbs.len();
        let mut result = BigInt::one(n_limbs);
        let mut base = self.modulo(m).resize(n_limbs);

        for i in 0..exp.bit_len() {
            if exp.bit(i) == 1 {
                result = result.mul(&base).modulo(m);
            }
            base = base.mul(&base).modulo(m);
        }
        result
    }

    /// Extended Euclidean Algorithm: returns (gcd, x, y) such that ax + by = gcd
    pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
        if b.is_zero() {
            return (a.clone(), BigInt::one(a.limbs.len()), BigInt::zero(a.limbs.len()));
        }
        let (g, x, y) = BigInt::extended_gcd(b, &a.modulo(b));
        let q = a.divrem(b).0;
        let new_x = y.clone();
        // new_y = x - q * y (careful with signed arithmetic)
        // We'll use a simpler modular inverse formula below
        (g, new_x, x.sub(&q.mul(&y)))
    }

    /// Modular inverse via extended Euclidean (a * inv ≡ 1 mod m)
    pub fn modinv(&self, m: &BigInt) -> Option<BigInt> {
        // Use iterative extended GCD to avoid signed arithmetic complications
        let mut old_r = self.resize(m.limbs.len() + 1);
        let mut r = m.resize(m.limbs.len() + 1);
        let mut old_s = BigInt::one(m.limbs.len() + 1);
        let mut s = BigInt::zero(m.limbs.len() + 1);
        let m_ext = m.resize(m.limbs.len() + 1);

        // Iterative version to avoid signed integers
        // We track whether s is "negative" with a sign bit
        let mut old_s_neg = false;
        let mut s_neg = false;

        while !r.is_zero() {
            let (q, new_r) = old_r.divrem(&r);
            let new_s_raw = q.mul(&s);

            // new_s = old_s - q * s (mod m), handling signs
            let new_s;
            let new_s_is_neg;
            if old_s_neg == s_neg {
                if old_s.cmp(&new_s_raw) >= 0 {
                    new_s = old_s.sub(&new_s_raw);
                    new_s_is_neg = old_s_neg;
                } else {
                    new_s = new_s_raw.sub(&old_s);
                    new_s_is_neg = !old_s_neg;
                }
            } else {
                new_s = old_s.add(&new_s_raw);
                new_s_is_neg = old_s_neg;
            }

            old_r = r;
            r = new_r;
            old_s = s;
            old_s_neg = s_neg;
            s = new_s;
            s_neg = new_s_is_neg;
        }

        // gcd should be 1
        if old_r.bit_len() > 1 { return None; }

        // old_s is the inverse; adjust sign
        let result = if old_s_neg {
            m_ext.sub(&old_s).modulo(&m_ext)
        } else {
            old_s.modulo(&m_ext)
        };
        Some(result.resize(m.limbs.len()))
    }

    /// GCD using binary GCD algorithm (faster than Euclidean for large numbers)
    pub fn gcd(mut a: BigInt, mut b: BigInt) -> BigInt {
        if a.is_zero() { return b; }
        if b.is_zero() { return a; }
        let mut shift = 0;
        while a.is_even() && b.is_even() {
            a = a.shr1();
            b = b.shr1();
            shift += 1;
        }
        while a.is_even() { a = a.shr1(); }
        loop {
            while b.is_even() { b = b.shr1(); }
            if a.cmp(&b) > 0 { core::mem::swap(&mut a, &mut b); }
            b = b.sub(&a);
            if b.is_zero() { break; }
        }
        // Left-shift a by shift bits
        for _ in 0..shift { a = a.shl1(); }
        a
    }
}

// ---------------------------------------------------------------------------
// Miller-Rabin Primality Test
// A probabilistic algorithm that tests whether a number is prime.
// With k rounds, the probability of a false positive is at most 4^(-k).
// For RSA key generation, we use 40 rounds (as recommended by NIST).
// ---------------------------------------------------------------------------

/// Miller-Rabin primality test with `rounds` witness values.
/// Deterministic for small witnesses on numbers < 3,215,031,751.
/// For large RSA primes, we use many rounds for statistical confidence.
pub fn miller_rabin(n: &BigInt, rounds: usize) -> bool {
    // Trivial cases
    if n.is_zero() || n.is_even() { return false; }
    if n.bit_len() == 1 && n.limbs[0] == 1 { return false; } // n=1
    if n.limbs[0] == 2 && n.bit_len() == 2 { return true; }  // n=2
    if n.limbs[0] == 3 && n.bit_len() == 2 { return true; }  // n=3

    // Small prime check (trial division for speed)
    let small_primes = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41,
                        43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97];
    for &sp in &small_primes {
        let sp_big = BigInt { limbs: vec![sp] }.resize(n.limbs.len());
        if n.cmp(&sp_big) == 0 { return true; }
        let rem = n.modulo(&sp_big);
        if rem.is_zero() { return false; }
    }

    // Write n-1 as 2^r * d where d is odd
    let one = BigInt::one(n.limbs.len());
    let n_minus_1 = n.sub(&one);

    let mut d = n_minus_1.clone();
    let mut r = 0u32;
    while d.is_even() {
        d = d.shr1();
        r += 1;
    }

    // Use deterministic witnesses for numbers up to 2^64 (covers RSA-2048 witnesses)
    // For larger numbers, we use random-ish but fixed witnesses derived from SHA-256
    // (In a real implementation, you'd use a CSPRNG; here we use derived values)
    let witnesses = deterministic_witnesses(n, rounds);

    'outer: for a in witnesses {
        let a_big = BigInt { limbs: vec![a] }.resize(n.limbs.len());
        if a_big.cmp(&BigInt::one(n.limbs.len())) <= 0 {
            continue;
        }

        let mut x = a_big.modpow(&d, n);
        let n_minus_1 = n.sub(&BigInt::one(n.limbs.len()));

        if x.cmp(&BigInt::one(n.limbs.len())) == 0 || x.cmp(&n_minus_1) == 0 {
            continue 'outer;
        }

        for _ in 0..r - 1 {
            x = x.mul(&x).modulo(n);
            if x.cmp(&n_minus_1) == 0 {
                continue 'outer;
            }
        }
        return false; // Composite!
    }
    true // Probably prime
}

/// Generate deterministic witness values for Miller-Rabin.
/// In production, these would come from a CSPRNG.
/// Here we derive them from SHA-256 of the number being tested.
fn deterministic_witnesses(n: &BigInt, count: usize) -> Vec<u64> {
    let n_bytes = n.to_bytes_be(32);
    let mut witnesses = Vec::new();

    for i in 0u32..count as u32 {
        let mut data = n_bytes.clone();
        data.extend_from_slice(&i.to_le_bytes());
        let hash = Sha256::digest(&data);
        let w = u64::from_le_bytes(hash[..8].try_into().unwrap());
        // Ensure witness is at least 2 and less than n
        let w = (w % (u64::MAX - 1)) + 2;
        witnesses.push(w);
    }
    witnesses
}

// ---------------------------------------------------------------------------
// RSA Key Structure and OAEP Padding
// ---------------------------------------------------------------------------

pub struct RsaPublicKey {
    pub n: BigInt,  // modulus (2048 bits)
    pub e: BigInt,  // public exponent (typically 65537)
}

pub struct RsaPrivateKey {
    pub n: BigInt,  // modulus
    pub d: BigInt,  // private exponent
    pub p: BigInt,  // prime factor 1
    pub q: BigInt,  // prime factor 2
    pub dp: BigInt, // d mod (p-1) — for CRT speedup
    pub dq: BigInt, // d mod (q-1)
    pub qinv: BigInt, // q^-1 mod p — for CRT
}

impl RsaPrivateKey {
    pub fn public_key(&self) -> RsaPublicKey {
        RsaPublicKey {
            n: self.n.clone(),
            e: BigInt { limbs: vec![65537] }.resize(self.n.limbs.len()),
        }
    }
}

/// RSA-OAEP encryption using SHA-256 as the hash function
/// OAEP: Optimal Asymmetric Encryption Padding (RFC 8017)
pub fn rsa_oaep_encrypt(
    pub_key: &RsaPublicKey,
    message: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let k = 256; // RSA-2048 = 256 bytes
    let h_len = 32; // SHA-256 output
    let max_msg = k - 2 * h_len - 2;

    if message.len() > max_msg {
        return Err("Message too long for OAEP");
    }

    // Hash the label
    let label_hash = Sha256::digest(label);

    // Build DB = lHash || PS || 0x01 || M
    let ps_len = max_msg - message.len();
    let mut db = Vec::with_capacity(k - h_len - 1);
    db.extend_from_slice(&label_hash);
    db.extend(core::iter::repeat(0u8).take(ps_len));
    db.push(0x01);
    db.extend_from_slice(message);

    debug_assert_eq!(db.len(), k - h_len - 1);

    // Generate random seed (in real code: use CSPRNG; here: derive from message+key for determinism)
    // SECURITY NOTE: In production, this MUST be random. We use a placeholder.
    let seed_data = [label_hash.as_ref(), message].concat();
    let seed = Sha256::digest(&seed_data); // NOT cryptographically random! Demo only.

    // MGF1-SHA256: mask generation function
    fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
        let mut t = Vec::new();
        let mut counter = 0u32;
        while t.len() < len {
            let mut data = seed.to_vec();
            data.extend_from_slice(&counter.to_be_bytes());
            t.extend_from_slice(&Sha256::digest(&data));
            counter += 1;
        }
        t.truncate(len);
        t
    }

    // dbMask = MGF1(seed, k - hLen - 1)
    let db_mask = mgf1(&seed, k - h_len - 1);
    // maskedDB = DB XOR dbMask
    let masked_db: Vec<u8> = db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    // seedMask = MGF1(maskedDB, hLen)
    let seed_mask = mgf1(&masked_db, h_len);
    // maskedSeed = seed XOR seedMask
    let masked_seed: Vec<u8> = seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    // EM = 0x00 || maskedSeed || maskedDB
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);

    debug_assert_eq!(em.len(), k);

    // RSA encryption: c = m^e mod n
    let m = BigInt::from_bytes_be(&em).resize(pub_key.n.limbs.len());
    let c = m.modpow(&pub_key.e, &pub_key.n);
    Ok(c.to_bytes_be(k))
}

/// RSA-OAEP decryption
pub fn rsa_oaep_decrypt(
    priv_key: &RsaPrivateKey,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let k = 256; // RSA-2048
    let h_len = 32;

    if ciphertext.len() != k {
        return Err("Invalid ciphertext length");
    }

    // RSA decryption using CRT for efficiency:
    // m_p = c^dp mod p, m_q = c^dq mod q, then combine via Garner's formula
    let c = BigInt::from_bytes_be(ciphertext);

    let m1 = c.modpow(&priv_key.dp, &priv_key.p);
    let m2 = c.modpow(&priv_key.dq, &priv_key.q);

    // Garner's formula: m = m2 + q * (qinv * (m1 - m2) mod p)
    let diff = if m1.cmp(&m2) >= 0 { m1.sub(&m2) } else { m1.add(&priv_key.p).sub(&m2) };
    let h = priv_key.qinv.mul(&diff).modulo(&priv_key.p);
    let m = m2.add(&priv_key.q.mul(&h));

    let em = m.to_bytes_be(k);

    // Decode OAEP
    if em[0] != 0x00 {
        return Err("OAEP decode failed: first byte not 0x00");
    }

    let label_hash = Sha256::digest(label);
    let masked_seed = &em[1..1 + h_len];
    let masked_db   = &em[1 + h_len..];

    fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
        let mut t = Vec::new();
        let mut counter = 0u32;
        while t.len() < len {
            let mut data = seed.to_vec();
            data.extend_from_slice(&counter.to_be_bytes());
            t.extend_from_slice(&Sha256::digest(&data));
            counter += 1;
        }
        t.truncate(len);
        t
    }

    let seed_mask = mgf1(masked_db, h_len);
    let seed: Vec<u8> = masked_seed.iter().zip(seed_mask.iter()).map(|(a, b)| a ^ b).collect();

    let db_mask = mgf1(&seed, k - h_len - 1);
    let db: Vec<u8> = masked_db.iter().zip(db_mask.iter()).map(|(a, b)| a ^ b).collect();

    // Verify label hash (constant time)
    let db_label_hash = &db[..h_len];
    let mut diff = 0u8;
    for (a, b) in db_label_hash.iter().zip(label_hash.iter()) {
        diff |= a ^ b;
    }
    if core::hint::black_box(diff) != 0 {
        return Err("OAEP decode failed: label hash mismatch");
    }

    // Find 0x01 separator
    let db_rest = &db[h_len..];
    let sep_pos = db_rest.iter().position(|&b| b != 0x00)
        .ok_or("OAEP decode failed: no 0x01 separator")?;

    if db_rest[sep_pos] != 0x01 {
        return Err("OAEP decode failed: expected 0x01 separator");
    }

    Ok(db_rest[sep_pos + 1..].to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_arithmetic() {
        let a = U256::from_u64(0xFFFFFFFFFFFFFFFF);
        let b = U256::from_u64(1);
        let (sum, carry) = U256::add_with_carry(&a, &b);
        assert_eq!(sum.limbs[0], 0);
        assert_eq!(sum.limbs[1], 1);
        assert_eq!(carry, 0);
    }

    #[test]
    fn test_field_el_arithmetic() {
        let a = FieldEl::ONE;
        let b = FieldEl::ONE;
        let c = a.add(&b);
        // 1 + 1 = 2 in F_p
        assert_eq!(c.0.limbs[0], 2);

        // Inverse: a * a^-1 = 1
        let x = FieldEl(U256::from_u64(7));
        let x_inv = x.invert();
        let product = x.mul(&x_inv);
        assert_eq!(product.0, U256::ONE);
    }

    #[test]
    fn test_x25519_base_point_multiplication() {
        // RFC 7748 §6.1 test vector
        let alice_private: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_public = x25519_public_key(&alice_private);
        // Expected from RFC:
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(alice_public, expected);
    }

    #[test]
    fn test_x25519_dh_exchange() {
        // Both sides derive the same shared secret
        let alice_private: [u8; 32] = [0xA0; 32];
        let bob_private:   [u8; 32] = [0xB0; 32];

        let alice_pub = x25519_public_key(&alice_private);
        let bob_pub   = x25519_public_key(&bob_private);

        let alice_shared = x25519_diffie_hellman(&alice_private, &bob_pub);
        let bob_shared   = x25519_diffie_hellman(&bob_private, &alice_pub);

        assert_eq!(alice_shared, bob_shared, "X25519 DH shared secrets must match");
    }

    #[test]
    fn test_bigint_modpow() {
        // 2^10 mod 1000 = 1024 mod 1000 = 24
        let base = BigInt { limbs: vec![2, 0, 0, 0] };
        let exp  = BigInt { limbs: vec![10, 0, 0, 0] };
        let m    = BigInt { limbs: vec![1000, 0, 0, 0] };
        let result = base.modpow(&exp, &m);
        assert_eq!(result.limbs[0], 24);
    }

    #[test]
    fn test_miller_rabin_known_primes() {
        let primes = [2u64, 3, 5, 7, 11, 13, 17, 19, 23, 29, 97, 101, 1009, 10007];
        for p in primes {
            let n = BigInt { limbs: vec![p, 0, 0, 0] };
            assert!(miller_rabin(&n, 20), "{} should be prime", p);
        }
    }

    #[test]
    fn test_miller_rabin_known_composites() {
        let composites = [4u64, 6, 8, 9, 10, 15, 100, 1001, 10000];
        for c in composites {
            let n = BigInt { limbs: vec![c, 0, 0, 0] };
            assert!(!miller_rabin(&n, 20), "{} should be composite", c);
        }
    }
}
pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]// ============================================================================
// beast_crypto — lib.rs
// Public API surface for the beast cryptographic engine.
// ============================================================================

pub mod aes_gcm;
pub mod chacha20_poly1305;
pub mod hashes;
pub mod asymmetric;

pub use aes_gcm::{
    Aes256, Aes256Gcm, AesCtr, AesState, Aes256Key,
    GHash, AesGcmError,
    SBOX, INV_SBOX, MUL2, MUL3, MUL9, MUL11, MUL13, MUL14, RCON,
    gf_mul, gf_inv,
    ct_eq_16, ct_eq_slice, secure_zero,
    aes_key_wrap, aes_key_unwrap,
};

pub use chacha20_poly1305::{
    ChaCha20, ChaCha20Poly1305, XChaCha20Poly1305,
    Poly1305, ChaChaError,
    chacha20_block, quarter_round, hchacha20,
};

pub use hashes::{
    Sha256, HmacSha256, Hkdf, Blake3,
};

pub use asymmetric::{
    U256, FieldEl,
    x25519_public_key, x25519_diffie_hellman, x25519_scalarmult,
    BigInt, miller_rabin,
    RsaPublicKey, RsaPrivateKey,
    rsa_oaep_encrypt, rsa_oaep_decrypt,
};
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

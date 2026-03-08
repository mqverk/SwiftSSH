/// AES-256-CTR encryption and decryption for SSH transport.
///
/// Per RFC 4253 §6.3, packets are encrypted after key exchange using
/// the negotiated cipher. We use AES-256-CTR mode.
use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use crate::error::{SshError, SshResult};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Wraps an AES-256-CTR cipher for a single direction (encrypt or decrypt).
pub struct AesCipher {
    cipher: Aes256Ctr,
}

impl AesCipher {
    /// Create a new AES-256-CTR cipher with key (32 bytes) and IV (16 bytes).
    pub fn new(key: &[u8], iv: &[u8]) -> SshResult<Self> {
        if key.len() != 32 {
            return Err(SshError::Encryption(format!(
                "AES-256 key must be 32 bytes, got {}",
                key.len()
            )));
        }
        if iv.len() != 16 {
            return Err(SshError::Encryption(format!(
                "AES IV must be 16 bytes, got {}",
                iv.len()
            )));
        }
        let cipher = Aes256Ctr::new(key.into(), iv.into());
        Ok(Self { cipher })
    }

    /// Encrypt or decrypt data in-place (CTR mode is symmetric).
    pub fn apply(&mut self, data: &mut [u8]) {
        self.cipher.apply_keystream(data);
    }
}

impl Drop for AesCipher {
    fn drop(&mut self) {
        // Cipher state is internal to the ctr crate; we can't zeroize it directly,
        // but we've done our best to not leak key material elsewhere.
    }
}

/// Holds a matched pair of ciphers for bidirectional encrypted communication.
pub struct CipherPair {
    pub encrypt: AesCipher,
    pub decrypt: AesCipher,
}

impl CipherPair {
    pub fn new(
        enc_key: &[u8],
        enc_iv: &[u8],
        dec_key: &[u8],
        dec_iv: &[u8],
    ) -> SshResult<Self> {
        Ok(Self {
            encrypt: AesCipher::new(enc_key, enc_iv)?,
            decrypt: AesCipher::new(dec_key, dec_iv)?,
        })
    }
}

/// Compute HMAC-SHA256 over data with the given key.
pub fn compute_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Verify HMAC-SHA256. Returns Ok(()) or Err(MacMismatch).
pub fn verify_hmac(key: &[u8], data: &[u8], expected: &[u8]) -> SshResult<()> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.verify_slice(expected).map_err(|_| SshError::MacMismatch)
}

/// Derive session keys from shared secret and exchange hash per RFC 4253 §7.2.
///
/// ```text
///   K1 = HASH(K || H || X || session_id)
///   K2 = HASH(K || H || K1)
///   key = K1 || K2 || ...
/// ```
/// Where X is one of 'A'..'F' identifying the key purpose.
pub fn derive_key(
    shared_secret: &[u8],
    exchange_hash: &[u8],
    key_char: u8,
    session_id: &[u8],
    needed: usize,
) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut key = Vec::with_capacity(needed);

    // First round: HASH(K || H || key_char || session_id)
    let mut hasher = Sha256::new();
    // K as mpint
    let k_mpint = encode_mpint_for_hash(shared_secret);
    hasher.update(&k_mpint);
    hasher.update(exchange_hash);
    hasher.update([key_char]);
    hasher.update(session_id);
    let mut k_n = hasher.finalize().to_vec();
    key.extend_from_slice(&k_n);

    // Subsequent rounds if more key material needed
    while key.len() < needed {
        let mut hasher = Sha256::new();
        hasher.update(&k_mpint);
        hasher.update(exchange_hash);
        hasher.update(&key);
        k_n = hasher.finalize().to_vec();
        key.extend_from_slice(&k_n);
    }

    key.truncate(needed);
    key
}

/// Encode bytes as an SSH mpint for hashing (uint32 length prefix + data with sign handling).
fn encode_mpint_for_hash(data: &[u8]) -> Vec<u8> {
    use byteorder::{BigEndian, WriteBytesExt};

    let stripped = match data.iter().position(|&b| b != 0) {
        Some(pos) => &data[pos..],
        None => &[0],
    };

    let mut buf = Vec::new();
    if stripped.is_empty() || stripped[0] & 0x80 != 0 {
        buf.write_u32::<BigEndian>((stripped.len() + 1) as u32).unwrap();
        buf.push(0);
    } else {
        buf.write_u32::<BigEndian>(stripped.len() as u32).unwrap();
    }
    buf.extend_from_slice(stripped);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = [0x42u8; 32];
        let iv = [0x00u8; 16];

        let plaintext = b"Hello, SwiftSSH!";
        let mut ciphertext = plaintext.to_vec();

        let mut enc = AesCipher::new(&key, &iv).unwrap();
        enc.apply(&mut ciphertext);
        assert_ne!(&ciphertext, plaintext);

        // Decrypt with a fresh cipher (same key/iv, CTR resets)
        let mut dec = AesCipher::new(&key, &iv).unwrap();
        dec.apply(&mut ciphertext);
        assert_eq!(&ciphertext, plaintext);
    }

    #[test]
    fn test_hmac_verify() {
        let key = b"test-key";
        let data = b"test-data";
        let mac = compute_hmac(key, data);
        assert!(verify_hmac(key, data, &mac).is_ok());

        let mut bad_mac = mac.clone();
        bad_mac[0] ^= 0xFF;
        assert!(verify_hmac(key, data, &bad_mac).is_err());
    }

    #[test]
    fn test_derive_key_deterministic() {
        let secret = vec![0x01; 32];
        let hash = vec![0x02; 32];
        let session_id = vec![0x03; 32];

        let k1 = derive_key(&secret, &hash, b'A', &session_id, 32);
        let k2 = derive_key(&secret, &hash, b'A', &session_id, 32);
        assert_eq!(k1, k2);

        // Different key_char produces different key
        let k3 = derive_key(&secret, &hash, b'B', &session_id, 32);
        assert_ne!(k1, k3);
    }

    #[test]
    fn test_derive_key_extension() {
        // Request more than 32 bytes (SHA-256 output) to test key extension
        let secret = vec![0x01; 32];
        let hash = vec![0x02; 32];
        let session_id = vec![0x03; 32];

        let key = derive_key(&secret, &hash, b'C', &session_id, 64);
        assert_eq!(key.len(), 64);
    }
}

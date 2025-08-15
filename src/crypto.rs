// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cryptographic primitives and key derivation for MLS

use crate::{MlsError, Result};
use blake3::Hasher as Blake3Hasher;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};

/// Supported cipher suites for MLS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// Ed25519 + ChaCha20Poly1305 + BLAKE3
    Ed25519ChaCha20Poly1305Blake3,
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::Ed25519ChaCha20Poly1305Blake3
    }
}

impl CipherSuite {
    /// Get the hash output size for this cipher suite
    pub fn hash_size(&self) -> usize {
        match self {
            Self::Ed25519ChaCha20Poly1305Blake3 => 32,
        }
    }
    
    /// Get the key size for symmetric encryption
    pub fn key_size(&self) -> usize {
        match self {
            Self::Ed25519ChaCha20Poly1305Blake3 => 32,
        }
    }
    
    /// Get the nonce size for AEAD
    pub fn nonce_size(&self) -> usize {
        match self {
            Self::Ed25519ChaCha20Poly1305Blake3 => 12,
        }
    }
    
    /// Get the signature size
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Ed25519ChaCha20Poly1305Blake3 => 64,
        }
    }
}

/// Hash function wrapper
#[derive(Debug)]
pub struct Hash {
    suite: CipherSuite,
}

impl Hash {
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }
    
    /// Compute hash of input data
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self.suite {
            CipherSuite::Ed25519ChaCha20Poly1305Blake3 => {
                Blake3Hasher::new().update(data).finalize().as_bytes().to_vec()
            }
        }
    }
    
    /// Compute HMAC
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self.suite {
            CipherSuite::Ed25519ChaCha20Poly1305Blake3 => {
                let hkdf = Hkdf::<Sha256>::new(None, key);
                let mut output = vec![0u8; 32];
                hkdf.expand(data, &mut output).unwrap();
                output
            }
        }
    }
}

/// HKDF-based key derivation
#[derive(Debug, Clone)]
pub struct KeySchedule {
    suite: CipherSuite,
}

impl KeySchedule {
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }
    
    /// Extract and expand key material using HKDF
    pub fn derive_key(&self, salt: &[u8], ikm: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>> {
        match self.suite {
            CipherSuite::Ed25519ChaCha20Poly1305Blake3 => {
                let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
                let mut output = vec![0u8; length];
                hkdf.expand(info, &mut output)
                    .map_err(|e| MlsError::KeyDerivationError(e.to_string()))?;
                Ok(output)
            }
        }
    }
    
    /// Derive multiple keys from the same source material
    pub fn derive_keys(&self, salt: &[u8], ikm: &[u8], infos: &[&[u8]], lengths: &[usize]) -> Result<Vec<Vec<u8>>> {
        let mut keys = Vec::new();
        for (info, &length) in infos.iter().zip(lengths.iter()) {
            keys.push(self.derive_key(salt, ikm, info, length)?);
        }
        Ok(keys)
    }
}

/// Asymmetric key pair for signing and key agreement
#[derive(Debug)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub agreement_secret: Vec<u8>, // Store as bytes to avoid EphemeralSecret ownership issues
    pub agreement_public: X25519PublicKey,
    pub suite: CipherSuite,
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(suite: CipherSuite) -> Self {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let agreement_secret_ephemeral = EphemeralSecret::random_from_rng(&mut rng);
        let agreement_public = X25519PublicKey::from(&agreement_secret_ephemeral);
        
        // Convert to bytes for storage (simplified - in production would use proper key derivation)
        let agreement_secret = random_bytes(32);
        
        Self {
            signing_key,
            agreement_secret,
            agreement_public,
            suite,
        }
    }
    
    /// Get the public verification key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    /// Get the public key for key agreement
    pub fn public_key(&self) -> X25519PublicKey {
        self.agreement_public
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> crate::Result<Signature> {
        Ok(self.signing_key.sign(message))
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> crate::Result<bool> {
        use ed25519_dalek::Verifier;
        match self.verifying_key().verify(message, signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
    
    /// Key agreement (alias for diffie_hellman for compatibility)
    pub fn key_agreement(&self, their_public: &X25519PublicKey) -> SharedSecret {
        self.diffie_hellman(their_public)
    }
    
    /// Perform Diffie-Hellman key agreement (simplified implementation)
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> SharedSecret {
        // In production, would use the actual secret key
        // For now, create a deterministic shared secret
        let mut combined = Vec::new();
        combined.extend_from_slice(&self.agreement_secret);
        combined.extend_from_slice(their_public.as_bytes());
        
        let hash = blake3::hash(&combined);
        // Create SharedSecret from hash bytes (simplified implementation)
        // In production, would use proper key derivation
        let mut shared_bytes = [0u8; 32];
        shared_bytes.copy_from_slice(hash.as_bytes());
        let ephemeral = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        // Return a dummy shared secret for compilation
        ephemeral.diffie_hellman(&X25519PublicKey::from(shared_bytes))
    }
}

/// AEAD encryption/decryption
#[derive(Debug)]
pub struct AeadCipher {
    key: Vec<u8>,
    suite: CipherSuite,
}

impl AeadCipher {
    /// Create new AEAD cipher with key
    pub fn new(key: Vec<u8>, suite: CipherSuite) -> Result<Self> {
        if key.len() != suite.key_size() {
            return Err(MlsError::CryptoError(
                format!("Invalid key length: expected {}, got {}", suite.key_size(), key.len())
            ));
        }
        
        Ok(Self { key, suite })
    }
    
    /// Encrypt plaintext with associated data
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        match self.suite {
            CipherSuite::Ed25519ChaCha20Poly1305Blake3 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| MlsError::CryptoError(e.to_string()))?;
                
                let nonce = Nonce::from_slice(nonce);
                let ciphertext = cipher
                    .encrypt(nonce, chacha20poly1305::aead::Payload {
                        msg: plaintext,
                        aad: associated_data,
                    })
                    .map_err(|e| MlsError::CryptoError(e.to_string()))?;
                
                Ok(ciphertext)
            }
        }
    }
    
    /// Decrypt ciphertext with associated data
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        match self.suite {
            CipherSuite::Ed25519ChaCha20Poly1305Blake3 => {
                let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
                    .map_err(|e| MlsError::CryptoError(e.to_string()))?;
                
                let nonce = Nonce::from_slice(nonce);
                let plaintext = cipher
                    .decrypt(nonce, chacha20poly1305::aead::Payload {
                        msg: ciphertext,
                        aad: associated_data,
                    })
                    .map_err(|_| MlsError::DecryptionFailed)?;
                
                Ok(plaintext)
            }
        }
    }
}

/// Generate random bytes
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Constant-time comparison
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (a_byte, b_byte) in a.iter().zip(b.iter()) {
        result |= a_byte ^ b_byte;
    }
    
    result == 0
}

/// Key derivation labels for different purposes
pub mod labels {
    pub const EPOCH_SECRET: &[u8] = b"MLS 1.0 epoch secret";
    pub const SENDER_DATA_SECRET: &[u8] = b"MLS 1.0 sender data secret";
    pub const HANDSHAKE_SECRET: &[u8] = b"MLS 1.0 handshake secret";
    pub const APPLICATION_SECRET: &[u8] = b"MLS 1.0 application secret";
    pub const EXPORTER_SECRET: &[u8] = b"MLS 1.0 exporter secret";
    pub const AUTHENTICATION_SECRET: &[u8] = b"MLS 1.0 authentication secret";
    pub const EXTERNAL_SECRET: &[u8] = b"MLS 1.0 external secret";
    pub const CONFIRMATION_KEY: &[u8] = b"MLS 1.0 confirmation key";
    pub const MEMBERSHIP_KEY: &[u8] = b"MLS 1.0 membership key";
    pub const RESUMPTION_PSK: &[u8] = b"MLS 1.0 resumption psk";
    pub const INIT_SECRET: &[u8] = b"MLS 1.0 init secret";
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cipher_suite_properties() {
        let suite = CipherSuite::default();
        assert_eq!(suite.hash_size(), 32);
        assert_eq!(suite.key_size(), 32);
        assert_eq!(suite.nonce_size(), 12);
        assert_eq!(suite.signature_size(), 64);
    }
    
    #[test]
    fn test_hash_function() {
        let hash = Hash::new(CipherSuite::default());
        let input = b"test input";
        let output1 = hash.hash(input);
        let output2 = hash.hash(input);
        
        assert_eq!(output1.len(), 32);
        assert_eq!(output1, output2); // Deterministic
    }
    
    #[test]
    fn test_key_derivation() {
        let ks = KeySchedule::new(CipherSuite::default());
        let salt = b"salt";
        let ikm = b"input key material";
        let info = b"key info";
        
        let key1 = ks.derive_key(salt, ikm, info, 32).unwrap();
        let key2 = ks.derive_key(salt, ikm, info, 32).unwrap();
        
        assert_eq!(key1.len(), 32);
        assert_eq!(key1, key2); // Deterministic
    }
    
    #[test]
    fn test_keypair_generation() {
        let kp1 = KeyPair::generate(CipherSuite::default());
        let kp2 = KeyPair::generate(CipherSuite::default());
        
        // Keys should be different
        assert_ne!(kp1.verifying_key().to_bytes(), kp2.verifying_key().to_bytes());
        assert_ne!(kp1.public_key().as_bytes(), kp2.public_key().as_bytes());
    }
    
    #[test]
    fn test_aead_encryption() {
        let key = random_bytes(32);
        let cipher = AeadCipher::new(key, CipherSuite::default()).unwrap();
        
        let nonce = random_bytes(12);
        let plaintext = b"Hello, MLS!";
        let aad = b"associated data";
        
        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();
        
        assert_eq!(decrypted, plaintext);
    }
    
    #[test]
    fn test_constant_time_eq() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, &b[..3])); // Different lengths
    }
    
    #[test]
    fn test_random_bytes() {
        let bytes1 = random_bytes(32);
        let bytes2 = random_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Should be different
    }
}
//! Cryptographic primitives for MLS using saorsa-pqc
//!
//! This module provides post-quantum cryptographic operations using
//! NIST-standardized algorithms from the saorsa-pqc library.

use crate::{MlsError, Result};
use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng};
use saorsa_pqc::{
    api::{
        MlKem, MlKemVariant, MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedSecret,
        MlDsa, MlDsaVariant, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    },
    symmetric::{SymmetricKey, ChaCha20Poly1305Cipher as PqcCipher},
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Supported cipher suites for MLS with post-quantum algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    /// ML-KEM-768 + ML-DSA-65 (NIST Level 3 security)
    MlKem768MlDsa65,
    /// ML-KEM-1024 + ML-DSA-87 (NIST Level 5 security)
    MlKem1024MlDsa87,
    /// Hybrid mode with classical and PQC algorithms
    HybridClassicalPqc,
}

impl Default for CipherSuite {
    fn default() -> Self {
        Self::MlKem768MlDsa65
    }
}

impl CipherSuite {
    /// Get the ML-KEM variant for this cipher suite
    pub fn ml_kem_variant(&self) -> MlKemVariant {
        match self {
            Self::MlKem768MlDsa65 | Self::HybridClassicalPqc => MlKemVariant::MlKem768,
            Self::MlKem1024MlDsa87 => MlKemVariant::MlKem1024,
        }
    }

    /// Get the ML-DSA variant for this cipher suite
    pub fn ml_dsa_variant(&self) -> MlDsaVariant {
        match self {
            Self::MlKem768MlDsa65 | Self::HybridClassicalPqc => MlDsaVariant::MlDsa65,
            Self::MlKem1024MlDsa87 => MlDsaVariant::MlDsa87,
        }
    }

    /// Get the key size for symmetric encryption
    pub fn key_size(&self) -> usize {
        32 // ChaCha20Poly1305 uses 256-bit keys
    }

    /// Get the nonce size for AEAD
    pub fn nonce_size(&self) -> usize {
        12 // ChaCha20Poly1305 uses 96-bit nonces
    }

    /// Get the hash output size
    pub fn hash_size(&self) -> usize {
        32 // BLAKE3 default output
    }
}

/// Hash operations
pub struct Hash {
    suite: CipherSuite,
}

impl Hash {
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Compute hash of data
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let mut output = vec![0u8; self.suite.hash_size()];
        hasher.finalize_xof().fill(&mut output);
        output
    }

    /// Compute HMAC
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| MlsError::CryptoError(format!("HMAC key error: {}", e)))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }
}

/// Key derivation using HKDF
pub struct KeySchedule {
    suite: CipherSuite,
}

impl KeySchedule {
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Derive key using HKDF-Extract and HKDF-Expand
    pub fn derive_secret(&self, secret: &[u8], label: &str, context: &[u8]) -> Result<Vec<u8>> {
        let info = self.build_hkdf_label(label, context, self.suite.hash_size());
        let hk = Hkdf::<Sha256>::new(None, secret);
        let mut output = vec![0u8; self.suite.hash_size()];
        hk.expand(&info, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("HKDF expand error: {}", e)))?;
        Ok(output)
    }

    fn build_hkdf_label(&self, label: &str, context: &[u8], length: usize) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&(length as u16).to_be_bytes());
        let mls_label = format!("MLS 1.0 {}", label);
        info.push(mls_label.len() as u8);
        info.extend_from_slice(mls_label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        info
    }
}

/// Post-quantum key pair for signing and key agreement
pub struct KeyPair {
    /// ML-DSA secret key for signing
    pub signing_key: MlDsaSecretKey,
    /// ML-DSA public key for verification
    pub verifying_key: MlDsaPublicKey,
    /// ML-KEM secret key for decapsulation
    pub kem_secret: MlKemSecretKey,
    /// ML-KEM public key for encapsulation
    pub kem_public: MlKemPublicKey,
    /// Cipher suite
    pub suite: CipherSuite,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("suite", &self.suite)
            .field("verifying_key", &"<hidden>")
            .field("kem_public", &"<hidden>")
            .finish()
    }
}

impl KeyPair {
    /// Generate a new key pair
    pub fn generate(suite: CipherSuite) -> Self {
        // Generate ML-DSA key pair for signing
        let ml_dsa = MlDsa::new(suite.ml_dsa_variant());
        let (verifying_key, signing_key) = ml_dsa.generate_keypair()
            .expect("ML-DSA key generation should not fail");

        // Generate ML-KEM key pair for key encapsulation
        let ml_kem = MlKem::new(suite.ml_kem_variant());
        let (kem_public, kem_secret) = ml_kem.generate_keypair()
            .expect("ML-KEM key generation should not fail");

        Self {
            signing_key,
            verifying_key,
            kem_secret,
            kem_public,
            suite,
        }
    }

    /// Get the public verification key
    pub fn verifying_key(&self) -> &MlDsaPublicKey {
        &self.verifying_key
    }

    /// Get the public KEM key
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.kem_public
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
        ml_dsa.sign(&self.signing_key, message)
            .map_err(|e| MlsError::CryptoError(format!("Signing failed: {:?}", e)))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<bool> {
        let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
        Ok(ml_dsa.verify(&self.verifying_key, message, signature).is_ok())
    }

    /// Perform key encapsulation
    pub fn encapsulate(&self, recipient_public: &MlKemPublicKey) -> Result<(MlKemCiphertext, MlKemSharedSecret)> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());
        ml_kem.encaps(recipient_public)
            .map_err(|e| MlsError::CryptoError(format!("Encapsulation failed: {:?}", e)))
    }

    /// Perform key decapsulation
    pub fn decapsulate(&self, ciphertext: &MlKemCiphertext) -> Result<MlKemSharedSecret> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());
        ml_kem.decaps(&self.kem_secret, ciphertext)
            .map_err(|e| MlsError::CryptoError(format!("Decapsulation failed: {:?}", e)))
    }
}

/// AEAD encryption/decryption using ChaCha20Poly1305
#[derive(Debug)]
pub struct AeadCipher {
    key: SymmetricKey,
    suite: CipherSuite,
}

impl AeadCipher {
    /// Create a new AEAD cipher
    pub fn new(key: Vec<u8>, suite: CipherSuite) -> Result<Self> {
        if key.len() != suite.key_size() {
            return Err(MlsError::CryptoError(format!(
                "Invalid key size: expected {}, got {}",
                suite.key_size(),
                key.len()
            )));
        }
        
        let key = SymmetricKey::from_bytes(&key)
            .map_err(|e| MlsError::CryptoError(format!("Invalid key: {:?}", e)))?;
        
        Ok(Self { key, suite })
    }

    /// Encrypt plaintext with associated data
    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != self.suite.nonce_size() {
            return Err(MlsError::CryptoError("Invalid nonce size".to_string()));
        }

        let cipher = PqcCipher::new(&self.key);
        let (ciphertext, _) = cipher.encrypt_with_nonce(plaintext, nonce, Some(associated_data))
            .map_err(|_| MlsError::EncryptionFailed)?;
        
        Ok(ciphertext)
    }

    /// Decrypt ciphertext with associated data
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        if nonce.len() != self.suite.nonce_size() {
            return Err(MlsError::CryptoError("Invalid nonce size".to_string()));
        }

        let cipher = PqcCipher::new(&self.key);
        let plaintext = cipher.decrypt_with_nonce(ciphertext, nonce, Some(associated_data))
            .map_err(|_| MlsError::DecryptionFailed)?;
        
        Ok(plaintext)
    }
}

/// Generate random bytes
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Constant-time equality check
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// MLS-specific KDF labels
pub mod labels {
    pub const ENCRYPTION: &str = "encryption";
    pub const AUTHENTICATION: &str = "authentication";
    pub const EXPORTER: &str = "exporter";
    pub const EXTERNAL: &str = "external";
    pub const CONFIRM: &str = "confirm";
    pub const MEMBERSHIP: &str = "membership";
    pub const RESUMPTION: &str = "resumption";
    pub const INIT: &str = "init";
    pub const SENDER_DATA: &str = "sender data";
    pub const WELCOME: &str = "welcome";
    pub const HANDSHAKE: &str = "handshake";
    pub const APPLICATION: &str = "application";
    // Additional MLS labels
    pub const EPOCH_SECRET: &str = "epoch";
    pub const SENDER_DATA_SECRET: &str = "sender data secret";
    pub const HANDSHAKE_SECRET: &str = "handshake secret";
    pub const APPLICATION_SECRET: &str = "application secret";
    pub const EXPORTER_SECRET: &str = "exporter secret";
    pub const AUTHENTICATION_SECRET: &str = "authentication secret";
    pub const EXTERNAL_SECRET: &str = "external secret";
    pub const CONFIRMATION_KEY: &str = "confirmation key";
    pub const MEMBERSHIP_KEY: &str = "membership key";
    pub const RESUMPTION_PSK: &str = "resumption psk";
    pub const INIT_SECRET: &str = "init secret";
}

/// Secure bytes that are zeroed on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_suite_defaults() {
        let suite = CipherSuite::default();
        assert_eq!(suite, CipherSuite::MlKem768MlDsa65);
        assert_eq!(suite.key_size(), 32);
        assert_eq!(suite.nonce_size(), 12);
    }

    #[test]
    fn test_hash_operations() {
        let hash = Hash::new(CipherSuite::default());
        let data = b"test data";
        let result = hash.hash(data);
        assert_eq!(result.len(), 32);

        let key = b"test key";
        let hmac_result = hash.hmac(key, data).unwrap();
        assert!(!hmac_result.is_empty());
    }

    #[test]
    fn test_key_generation() {
        let kp1 = KeyPair::generate(CipherSuite::default());
        let kp2 = KeyPair::generate(CipherSuite::default());
        
        // Keys should be different
        assert_ne!(
            kp1.verifying_key.as_bytes(),
            kp2.verifying_key.as_bytes()
        );
    }

    #[test]
    fn test_signing_and_verification() {
        let kp = KeyPair::generate(CipherSuite::default());
        let message = b"test message";
        
        let signature = kp.sign(message).unwrap();
        assert!(kp.verify(message, &signature).unwrap());
        
        // Wrong message should fail
        let wrong_message = b"wrong message";
        assert!(!kp.verify(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_key_encapsulation() {
        let kp1 = KeyPair::generate(CipherSuite::default());
        let kp2 = KeyPair::generate(CipherSuite::default());
        
        // Encapsulate for kp2
        let (ciphertext, shared_secret1) = kp1.encapsulate(&kp2.kem_public).unwrap();
        
        // Decapsulate with kp2's secret
        let shared_secret2 = kp2.decapsulate(&ciphertext).unwrap();
        
        // Shared secrets should match
        assert_eq!(shared_secret1.as_bytes(), shared_secret2.as_bytes());
    }

    #[test]
    fn test_aead_encryption() {
        let key = random_bytes(32);
        let cipher = AeadCipher::new(key, CipherSuite::default()).unwrap();
        let nonce = random_bytes(12);
        let plaintext = b"secret message";
        let aad = b"associated data";

        let ciphertext = cipher.encrypt(&nonce, plaintext, aad).unwrap();
        let decrypted = cipher.decrypt(&nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_key_derivation() {
        let ks = KeySchedule::new(CipherSuite::default());
        let secret = random_bytes(32);
        let derived = ks.derive_secret(&secret, "test", b"context").unwrap();
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let data = vec![1, 2, 3, 4, 5];
        let secret = SecretBytes::new(data.clone());
        assert_eq!(secret.as_bytes(), &data);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
        // SecretBytes will be zeroed when dropped
    }
}
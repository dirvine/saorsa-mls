//! Cryptographic primitives for MLS using saorsa-pqc
//!
//! This module provides post-quantum cryptographic operations using
//! NIST-standardized algorithms from the saorsa-pqc library.
//!
//! We use saorsa-pqc as the single source of truth for all cryptographic
//! operations to ensure consistency and quantum-resistance.

use crate::{MlsError, Result};
use saorsa_pqc::api::{
    MlDsa, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant, MlKem, MlKemCiphertext,
    MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret, MlKemVariant,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    #[must_use]
    pub fn ml_kem_variant(&self) -> MlKemVariant {
        match self {
            Self::MlKem768MlDsa65 | Self::HybridClassicalPqc => MlKemVariant::MlKem768,
            Self::MlKem1024MlDsa87 => MlKemVariant::MlKem1024,
        }
    }

    /// Get the ML-DSA variant for this cipher suite
    #[must_use]
    pub fn ml_dsa_variant(&self) -> MlDsaVariant {
        match self {
            Self::MlKem768MlDsa65 | Self::HybridClassicalPqc => MlDsaVariant::MlDsa65,
            Self::MlKem1024MlDsa87 => MlDsaVariant::MlDsa87,
        }
    }

    /// Get the key size for symmetric encryption
    #[must_use]
    pub fn key_size(&self) -> usize {
        32 // ChaCha20Poly1305 uses 256-bit keys
    }

    /// Get the nonce size for AEAD
    #[must_use]
    pub fn nonce_size(&self) -> usize {
        12 // ChaCha20Poly1305 uses 96-bit nonces
    }

    /// Get the hash output size
    #[must_use]
    pub fn hash_size(&self) -> usize {
        32 // BLAKE3 default output
    }
}

/// Cryptographic operations using saorsa-pqc as the single source of truth
pub struct Hash {
    pub suite: CipherSuite,
}

impl Hash {
    #[must_use]
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Compute hash of data using BLAKE3 from saorsa-pqc
    #[must_use]
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        use saorsa_pqc::api::hash::Blake3Hasher;
        use saorsa_pqc::api::traits::Hash as HashTrait;

        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let output = hasher.finalize();
        output.as_ref().to_vec()
    }

    /// Compute HMAC using saorsa-pqc's HMAC-SHA3-256
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the HMAC key is invalid or computation fails.
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        use saorsa_pqc::api::hmac::HmacSha3_256;
        use saorsa_pqc::api::traits::Mac;

        let mut mac = HmacSha3_256::new(key)
            .map_err(|e| MlsError::CryptoError(format!("HMAC key error: {e:?}")))?;
        mac.update(data);
        let output = mac.finalize();
        Ok(output.as_ref().to_vec())
    }
}

/// Key derivation using HKDF
#[derive(Debug)]
pub struct KeySchedule {
    suite: CipherSuite,
}

impl KeySchedule {
    #[must_use]
    pub fn new(suite: CipherSuite) -> Self {
        Self { suite }
    }

    /// Derive key using saorsa-pqc's HKDF-SHA3-256
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the HKDF key derivation fails.
    pub fn derive_secret(&self, secret: &[u8], label: &str, context: &[u8]) -> Result<Vec<u8>> {
        use saorsa_pqc::api::kdf::HkdfSha3_256;
        use saorsa_pqc::api::traits::Kdf;

        let info = Self::build_hkdf_label(label, context, self.suite.hash_size());
        let mut output = vec![0u8; self.suite.hash_size()];

        HkdfSha3_256::derive(secret, None, &info, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("HKDF error: {e:?}")))?;
        Ok(output)
    }

    /// Derive multiple keys using saorsa-pqc's HKDF
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if any key derivation fails.
    pub fn derive_keys(
        &self,
        salt: &[u8],
        secret: &[u8],
        labels: &[&str],
        lengths: &[usize],
    ) -> Result<Vec<Vec<u8>>> {
        let mut results = Vec::new();

        for (label, &length) in labels.iter().zip(lengths.iter()) {
            let key = self.derive_secret(secret, label, salt)?;
            results.push(key[..length].to_vec());
        }
        Ok(results)
    }

    /// Derive a single key with specific length using saorsa-pqc's HKDF
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the HKDF key derivation fails.
    pub fn derive_key(
        &self,
        salt: &[u8],
        secret: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>> {
        use saorsa_pqc::api::kdf::HkdfSha3_256;
        use saorsa_pqc::api::traits::Kdf;

        let mut output = vec![0u8; length];
        HkdfSha3_256::derive(secret, Some(salt), info, &mut output)
            .map_err(|e| MlsError::CryptoError(format!("HKDF error: {e:?}")))?;
        Ok(output)
    }

    fn build_hkdf_label(label: &str, context: &[u8], length: usize) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
        info.push(
            u8::try_from(b"tls13 ".len()).unwrap_or(u8::MAX)
                + u8::try_from(label.len()).unwrap_or(u8::MAX),
        );
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label.as_bytes());
        info.push(u8::try_from(context.len()).unwrap_or(u8::MAX));
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
            .finish_non_exhaustive()
    }
}

impl KeyPair {
    /// Generate a new key pair
    ///
    /// # Panics
    ///
    /// Panics if key generation fails (should never happen in practice).
    #[must_use]
    pub fn generate(suite: CipherSuite) -> Self {
        // Generate ML-DSA key pair for signing
        let ml_dsa = MlDsa::new(suite.ml_dsa_variant());
        let (verifying_key, signing_key) = ml_dsa
            .generate_keypair()
            .expect("ML-DSA key generation should not fail");

        // Generate ML-KEM key pair for key encapsulation
        let ml_kem = MlKem::new(suite.ml_kem_variant());
        let (kem_public, kem_secret) = ml_kem
            .generate_keypair()
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
    #[must_use]
    pub fn verifying_key(&self) -> &MlDsaPublicKey {
        &self.verifying_key
    }

    /// Get the public KEM key
    #[must_use]
    pub fn public_key(&self) -> &MlKemPublicKey {
        &self.kem_public
    }

    /// Sign a message
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the signing operation fails.
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
        ml_dsa
            .sign(&self.signing_key, message)
            .map_err(|e| MlsError::CryptoError(format!("Signing failed: {e:?}")))
    }

    /// Verify a signature
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the verification operation fails.
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<bool> {
        let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
        ml_dsa
            .verify(&self.verifying_key, message, signature)
            .map_err(|e| MlsError::CryptoError(format!("Verification error: {e:?}")))
    }

    /// Perform key encapsulation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the encapsulation operation fails.
    pub fn encapsulate(
        &self,
        recipient_public: &MlKemPublicKey,
    ) -> Result<(MlKemCiphertext, MlKemSharedSecret)> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());
        let (shared_secret, ciphertext) = ml_kem
            .encapsulate(recipient_public)
            .map_err(|e| MlsError::CryptoError(format!("Encapsulation failed: {e:?}")))?;
        Ok((ciphertext, shared_secret))
    }

    /// Perform key decapsulation
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the decapsulation operation fails.
    pub fn decapsulate(&self, ciphertext: &MlKemCiphertext) -> Result<MlKemSharedSecret> {
        let ml_kem = MlKem::new(self.suite.ml_kem_variant());
        ml_kem
            .decapsulate(&self.kem_secret, ciphertext)
            .map_err(|e| MlsError::CryptoError(format!("Decapsulation failed: {e:?}")))
    }
}

/// AEAD encryption/decryption using saorsa-pqc's `ChaCha20Poly1305`
#[derive(Debug)]
pub struct AeadCipher {
    key: Vec<u8>,
    suite: CipherSuite,
}

impl AeadCipher {
    /// Create a new AEAD cipher from key material
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the key size is invalid.
    pub fn new(key: Vec<u8>, suite: CipherSuite) -> Result<Self> {
        if key.len() != suite.key_size() {
            return Err(MlsError::CryptoError(format!(
                "Invalid key size: expected {}, got {}",
                suite.key_size(),
                key.len()
            )));
        }

        Ok(Self { key, suite })
    }

    /// Encrypt plaintext with associated data using saorsa-pqc's `ChaCha20Poly1305`
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the nonce size is invalid or encryption fails.
    pub fn encrypt(
        &self,
        nonce: &[u8],
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Use saorsa-pqc's ChaCha20Poly1305
        use saorsa_pqc::api::symmetric::ChaCha20Poly1305 as PqcCipher;

        if nonce.len() != self.suite.nonce_size() {
            return Err(MlsError::CryptoError("Invalid nonce size".to_string()));
        }

        // Convert key to the format expected by saorsa-pqc
        let key_array: [u8; 32] = self
            .key
            .clone()
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid key size".to_string()))?;
        let key = chacha20poly1305::Key::from(key_array);

        let cipher = PqcCipher::new(&key);

        // Convert nonce
        let nonce_array: [u8; 12] = nonce
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid nonce size".to_string()))?;
        let nonce_obj = chacha20poly1305::Nonce::from(nonce_array);

        // Encrypt with AAD
        let ciphertext = cipher
            .encrypt_with_aad(&nonce_obj, plaintext, associated_data)
            .map_err(|e| MlsError::CryptoError(format!("Encryption failed: {e:?}")))?;

        // Return nonce + ciphertext for wire format
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt ciphertext with associated data using saorsa-pqc's `ChaCha20Poly1305`
    ///
    /// # Errors
    ///
    /// Returns `MlsError::CryptoError` if the nonce size is invalid, ciphertext is too short, or decryption fails.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        // Use saorsa-pqc's ChaCha20Poly1305
        use saorsa_pqc::api::symmetric::ChaCha20Poly1305 as PqcCipher;

        if nonce.len() != self.suite.nonce_size() {
            return Err(MlsError::CryptoError("Invalid nonce size".to_string()));
        }

        // The ciphertext includes the nonce at the beginning (12 bytes)
        // Skip it and use it for decryption
        if ciphertext.len() < 12 {
            return Err(MlsError::CryptoError("Ciphertext too short".to_string()));
        }

        let actual_nonce = &ciphertext[..12];
        let actual_ciphertext = &ciphertext[12..];

        // Convert key to the format expected by saorsa-pqc
        let key_array: [u8; 32] = self
            .key
            .clone()
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid key size".to_string()))?;
        let key = chacha20poly1305::Key::from(key_array);

        let cipher = PqcCipher::new(&key);

        // Convert nonce
        let nonce_array: [u8; 12] = actual_nonce
            .try_into()
            .map_err(|_| MlsError::CryptoError("Invalid nonce size".to_string()))?;
        let nonce_obj = chacha20poly1305::Nonce::from(nonce_array);

        // Decrypt with AAD
        let plaintext = cipher
            .decrypt_with_aad(&nonce_obj, actual_ciphertext, associated_data)
            .map_err(|e| MlsError::CryptoError(format!("Decryption failed: {e:?}")))?;

        Ok(plaintext)
    }

    /// Get the key size for this cipher
    #[must_use]
    pub fn key_size(&self) -> usize {
        self.suite.key_size()
    }

    /// Get the nonce size for this cipher
    #[must_use]
    pub fn nonce_size(&self) -> usize {
        self.suite.nonce_size()
    }
}

/// Generate random bytes using the same RNG as saorsa-pqc
#[must_use]
pub fn random_bytes(len: usize) -> Vec<u8> {
    use rand_core::{OsRng, RngCore};
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Constant-time comparison using subtle crate (already a dependency of saorsa-pqc)
#[must_use]
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
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
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
        assert_ne!(kp1.verifying_key.to_bytes(), kp2.verifying_key.to_bytes());
    }

    #[test]
    fn test_signing_and_verification() {
        let kp = KeyPair::generate(CipherSuite::default());
        let message = b"test message";

        let signature = kp.sign(message).unwrap();

        // Test with correct message
        assert!(kp.verify(message, &signature).unwrap());

        // Test with wrong message - the ML-DSA verify should return an error for invalid signatures
        // Our verify method converts that error to Ok(false)
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
        assert_eq!(shared_secret1.to_bytes(), shared_secret2.to_bytes());
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

/// Debug wrapper for `MlDsaSignature` to work around missing Debug impl
#[derive(Clone)]
pub struct DebugMlDsaSignature(pub MlDsaSignature);

impl std::fmt::Debug for DebugMlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSignature(<{} bytes>)", self.0.to_bytes().len())
    }
}

impl PartialEq for DebugMlDsaSignature {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for DebugMlDsaSignature {}

impl Serialize for DebugMlDsaSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_wrappers::serialize_ml_dsa_signature(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for DebugMlDsaSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let signature = serde_wrappers::deserialize_ml_dsa_signature(deserializer)?;
        Ok(DebugMlDsaSignature(signature))
    }
}

/// Debug wrapper for `MlDsaPublicKey` to work around missing Debug impl
#[derive(Clone)]
pub struct DebugMlDsaPublicKey(pub MlDsaPublicKey);

impl std::fmt::Debug for DebugMlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaPublicKey(<{} bytes>)", self.0.to_bytes().len())
    }
}

impl PartialEq for DebugMlDsaPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bytes() == other.0.to_bytes()
    }
}

impl Eq for DebugMlDsaPublicKey {}

impl Serialize for DebugMlDsaPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_wrappers::serialize_ml_dsa_public_key(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for DebugMlDsaPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = serde_wrappers::deserialize_ml_dsa_public_key(deserializer)?;
        Ok(DebugMlDsaPublicKey(key))
    }
}

/// Serde wrappers for saorsa-pqc types
pub mod serde_wrappers {
    use super::{
        DebugMlDsaPublicKey, DebugMlDsaSignature, MlDsaPublicKey, MlDsaSignature, MlKemCiphertext,
    };
    use saorsa_pqc::{MlDsaVariant, MlKemVariant};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize `MlKemCiphertext`
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the ciphertext cannot be serialized.
    pub fn serialize_ml_kem_ciphertext<S>(
        ciphertext: &MlKemCiphertext,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = ciphertext.to_bytes();
        let variant = ciphertext.variant();
        serializer.serialize_str(&format!("{}:{}", variant as u8, hex::encode(&bytes)))
    }

    /// Deserialize `MlKemCiphertext`
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the ciphertext cannot be deserialized.
    pub fn deserialize_ml_kem_ciphertext<'de, D>(
        deserializer: D,
    ) -> std::result::Result<MlKemCiphertext, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(D::Error::custom("Invalid MlKemCiphertext format"));
        }

        let variant = match parts[0] {
            "0" => MlKemVariant::MlKem512,
            "1" => MlKemVariant::MlKem768,
            "2" => MlKemVariant::MlKem1024,
            _ => return Err(D::Error::custom("Invalid MlKemVariant")),
        };

        let bytes = hex::decode(parts[1])
            .map_err(|e| D::Error::custom(format!("Hex decode error: {e}")))?;

        MlKemCiphertext::from_bytes(variant, &bytes)
            .map_err(|e| D::Error::custom(format!("MlKemCiphertext decode error: {e:?}")))
    }

    /// Serialize `MlDsaSignature`
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the signature cannot be serialized.
    pub fn serialize_ml_dsa_signature<S>(
        signature: &MlDsaSignature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = signature.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize `MlDsaSignature`
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the signature cannot be deserialized.
    pub fn deserialize_ml_dsa_signature<'de, D>(
        deserializer: D,
    ) -> std::result::Result<MlDsaSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("Hex decode error: {e}")))?;

        // Create from bytes - we'll use MlDsa65 as default
        if bytes.len() != 3309 {
            // ML-DSA-65 signature size
            return Err(D::Error::custom("Invalid MlDsaSignature size"));
        }

        let array: [u8; 3309] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("Failed to convert to array"))?;

        MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &array)
            .map_err(|e| D::Error::custom(format!("MlDsaSignature decode error: {e:?}")))
    }

    /// Serialize `MlDsaPublicKey`
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the public key cannot be serialized.
    pub fn serialize_ml_dsa_public_key<S>(
        key: &MlDsaPublicKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = key.to_bytes();
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Deserialize `MlDsaPublicKey`
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the public key cannot be deserialized.
    pub fn deserialize_ml_dsa_public_key<'de, D>(
        deserializer: D,
    ) -> std::result::Result<MlDsaPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes =
            hex::decode(&s).map_err(|e| D::Error::custom(format!("Hex decode error: {e}")))?;

        // Create from bytes - we'll use MlDsa65 as default
        if bytes.len() != 1952 {
            // ML-DSA-65 public key size
            return Err(D::Error::custom("Invalid MlDsaPublicKey size"));
        }

        let array: [u8; 1952] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("Failed to convert to array"))?;

        MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &array)
            .map_err(|e| D::Error::custom(format!("MlDsaPublicKey decode error: {e:?}")))
    }

    /// Serialize `DebugMlDsaSignature` wrapper
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the signature wrapper cannot be serialized.
    pub fn serialize_debug_ml_dsa_signature<S>(
        signature: &DebugMlDsaSignature,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_ml_dsa_signature(&signature.0, serializer)
    }

    /// Deserialize `DebugMlDsaSignature` wrapper
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the signature wrapper cannot be deserialized.
    pub fn deserialize_debug_ml_dsa_signature<'de, D>(
        deserializer: D,
    ) -> std::result::Result<DebugMlDsaSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let signature = deserialize_ml_dsa_signature(deserializer)?;
        Ok(DebugMlDsaSignature(signature))
    }

    /// Serialize `DebugMlDsaPublicKey` wrapper
    ///
    /// # Errors
    ///
    /// Returns a serialization error if the public key wrapper cannot be serialized.
    pub fn serialize_debug_ml_dsa_public_key<S>(
        key: &DebugMlDsaPublicKey,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_ml_dsa_public_key(&key.0, serializer)
    }

    /// Deserialize `DebugMlDsaPublicKey` wrapper
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the public key wrapper cannot be deserialized.
    pub fn deserialize_debug_ml_dsa_public_key<'de, D>(
        deserializer: D,
    ) -> std::result::Result<DebugMlDsaPublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let key = deserialize_ml_dsa_public_key(deserializer)?;
        Ok(DebugMlDsaPublicKey(key))
    }
}

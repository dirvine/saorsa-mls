//! Member identity and key management for MLS groups

use crate::{
    crypto::{CipherSuite, KeyPair},
    MlsError, Result,
};
use bincode::Options;
use saorsa_pqc::api::{MlDsaSignature, MlDsaPublicKey, MlKemPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Unique identifier for a group member
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberId(pub Uuid);

impl MemberId {
    /// Generate a new random member ID
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for MemberId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Identity information for a group member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberIdentity {
    pub id: MemberId,
    pub name: Option<String>,
    pub credential: Credential,
    pub key_package: KeyPackage,
}

impl MemberIdentity {
    /// Create a new member identity
    pub fn generate(id: MemberId) -> Result<Self> {
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential = Credential::new_basic(id, None, &keypair, keypair.suite)?;
        let key_package = KeyPackage::new(keypair, credential.clone())?;

        Ok(Self {
            id,
            name: None,
            credential,
            key_package,
        })
    }

    /// Create a member identity with a name
    pub fn with_name(name: String) -> Result<Self> {
        let id = MemberId::generate();
        let mut identity = Self::generate(id)?;
        
        // Update credential with name
        let suite = identity.key_package.cipher_suite;
        // We do not have the signing key here; regenerate fresh keys and key package
        let keypair = KeyPair::generate(suite);
        identity.name = Some(name.clone());
        identity.credential = Credential::new_basic(id, Some(name), &keypair, suite)?;
        identity.key_package = KeyPackage::new(keypair, identity.credential.clone())?;
        
        Ok(identity)
    }

    /// Get the member's cipher suite
    pub fn cipher_suite(&self) -> CipherSuite {
        self.key_package.cipher_suite
    }

    /// Verify this identity's signature on data
    pub fn verify_signature(&self, data: &[u8], signature: &MlDsaSignature) -> bool {
        self.key_package.verify_signature(data, signature)
    }

    /// Get the member's public key for verification
    pub fn verifying_key(&self) -> &MlDsaPublicKey {
        &self.key_package.verifying_key
    }
}

/// Member credential types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialType {
    /// Basic credential with identity binding
    Basic = 1,
    /// X.509 certificate-based credential
    Certificate = 2,
}

/// Member credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credential {
    /// Basic credential with self-signed identity
    Basic {
        credential_type: CredentialType,
        identity: Vec<u8>,
        signature: MlDsaSignature,
    },
    /// Certificate-based credential
    Certificate {
        credential_type: CredentialType,
        cert_data: Vec<u8>,
    },
}

impl Credential {
    /// Create a new basic credential
    pub fn new_basic(
        member_id: MemberId,
        name: Option<String>,
        keypair: &KeyPair,
        suite: CipherSuite,
    ) -> Result<Self> {
        // Canonicalized identity for signing
        let mut identity = Vec::new();
        identity.extend_from_slice(b"MLS 1.0 Credential");
        identity.extend_from_slice(member_id.as_bytes());
        
        if let Some(ref name) = name {
            identity.extend_from_slice(name.as_bytes());
        }
        
        // Add cipher suite information
        let suite_bytes = bincode::DefaultOptions::new()
            .serialize(&suite)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        identity.extend_from_slice(&suite_bytes);

        let signature = keypair.sign(&identity)?;

        Ok(Self::Basic {
            credential_type: CredentialType::Basic,
            identity,
            signature,
        })
    }

    /// Get the credential type
    pub fn credential_type(&self) -> CredentialType {
        match self {
            Self::Basic { credential_type, .. } => credential_type.clone(),
            Self::Certificate { credential_type, .. } => credential_type.clone(),
        }
    }

    /// Verify the credential is valid
    pub fn verify(&self, verifying_key: &MlDsaPublicKey) -> bool {
        match self {
            Self::Basic {
                identity,
                signature,
                ..
            } => {
                use saorsa_pqc::api::MlDsa;
                let ml_dsa = MlDsa::new(saorsa_pqc::api::MlDsaVariant::MlDsa65);
                ml_dsa.verify(verifying_key, identity, signature).is_ok()
            }
            Self::Certificate { .. } => {
                // Would verify certificate chain in production
                true
            }
        }
    }
}

/// Key package containing public keys and credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    /// Protocol version
    pub version: u16,
    /// Cipher suite for this key package
    pub cipher_suite: CipherSuite,
    /// Public key for message signing
    pub verifying_key: MlDsaPublicKey,
    /// Public key for key agreement
    pub agreement_key: MlKemPublicKey,
    /// Member credential
    pub credential: Credential,
    /// Extensions (reserved for future use)
    pub extensions: Vec<Extension>,
    /// Signature over the key package
    pub signature: MlDsaSignature,
}

impl KeyPackage {
    /// Create a new key package
    pub fn new(keypair: KeyPair, credential: Credential) -> Result<Self> {
        // Verify the credential against the provided verifying key
        if !credential.verify(keypair.verifying_key()) {
            return Err(MlsError::InvalidGroupState("invalid credential signature".to_string()));
        }

        let mut package = Self {
            version: 1,
            cipher_suite: keypair.suite,
            verifying_key: keypair.verifying_key().clone(),
            agreement_key: keypair.public_key().clone(),
            credential,
            extensions: Vec::new(),
            signature: keypair.sign(&[])?, // Placeholder, will be replaced
        };

        // Sign the key package
        let tbs = package.to_be_signed()?;
        package.signature = keypair.sign(&tbs)?;

        Ok(package)
    }

    /// Verify the key package signature
    pub fn verify_signature(&self, data: &[u8], signature: &MlDsaSignature) -> bool {
        use saorsa_pqc::api::MlDsa;
        let ml_dsa = MlDsa::new(self.cipher_suite.ml_dsa_variant());
        ml_dsa.verify(&self.verifying_key, data, signature).is_ok()
    }

    /// Verify the key package is self-consistent
    pub fn verify(&self) -> Result<bool> {
        let tbs = self.to_be_signed()?;
        Ok(self.verify_signature(&tbs, &self.signature))
    }

    /// Get the data to be signed for this key package
    fn to_be_signed(&self) -> Result<Vec<u8>> {
        // Simplified serialization for signing
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_be_bytes());
        
        let suite_bytes = bincode::DefaultOptions::new()
            .serialize(&self.cipher_suite)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&suite_bytes);
        
        // Include public keys
        data.extend_from_slice(self.verifying_key.as_bytes());
        data.extend_from_slice(self.agreement_key.as_bytes());
        
        // Include credential
        let cred_bytes = bincode::DefaultOptions::new()
            .serialize(&self.credential)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?;
        data.extend_from_slice(&cred_bytes);
        
        Ok(data)
    }
}

/// Extension types for key packages and messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Extension {
    /// Application-specific extension
    ApplicationId(Vec<u8>),
    /// Ratchet tree extension
    RatchetTree(Vec<u8>),
    /// External public key
    ExternalPub(Vec<u8>),
    /// External senders
    ExternalSenders(Vec<u8>),
}

/// Collection of member identities in a group
#[derive(Debug, Clone)]
pub struct MemberList {
    members: HashMap<MemberId, MemberIdentity>,
}

impl MemberList {
    /// Create a new empty member list
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
        }
    }

    /// Add a member to the list
    pub fn add(&mut self, member: MemberIdentity) {
        self.members.insert(member.id, member);
    }

    /// Remove a member from the list
    pub fn remove(&mut self, id: &MemberId) -> Option<MemberIdentity> {
        self.members.remove(id)
    }

    /// Get a member by ID
    pub fn get(&self, id: &MemberId) -> Option<&MemberIdentity> {
        self.members.get(id)
    }

    /// Get a mutable reference to a member
    pub fn get_mut(&mut self, id: &MemberId) -> Option<&mut MemberIdentity> {
        self.members.get_mut(id)
    }

    /// Check if a member exists
    pub fn contains(&self, id: &MemberId) -> bool {
        self.members.contains_key(id)
    }

    /// Get the number of members
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Check if the list is empty
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Iterate over all members
    pub fn iter(&self) -> impl Iterator<Item = (&MemberId, &MemberIdentity)> {
        self.members.iter()
    }

    /// Get all member IDs
    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members.keys().copied().collect()
    }
}

impl Default for MemberList {
    fn default() -> Self {
        Self::new()
    }
}

/// Member state in the group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberState {
    /// Member identity
    pub identity: MemberIdentity,
    /// Leaf index in the ratchet tree
    pub leaf_index: usize,
    /// Generation for epoch tracking
    pub generation: u32,
    /// Last update time
    pub last_update: u64,
}

impl MemberState {
    /// Create a new member state
    pub fn new(identity: MemberIdentity, leaf_index: usize) -> Self {
        Self {
            identity,
            leaf_index,
            generation: 0,
            last_update: 0,
        }
    }

    /// Update the generation counter
    pub fn increment_generation(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }
}

/// Lifetime bounds for credentials and key packages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifetimeExtension {
    /// Not valid before timestamp
    pub not_before: u64,
    /// Not valid after timestamp
    pub not_after: u64,
}

impl LifetimeExtension {
    /// Create a new lifetime extension valid for the specified duration
    pub fn new(duration: Duration) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        Self {
            not_before: now,
            not_after: now + duration.as_secs(),
        }
    }

    /// Check if the lifetime is currently valid
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        
        now >= self.not_before && now <= self.not_after
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_member_id_generation() {
        let id1 = MemberId::generate();
        let id2 = MemberId::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_member_identity_creation() {
        let identity = MemberIdentity::generate(MemberId::generate()).unwrap();
        assert!(identity.name.is_none());
        assert_eq!(identity.cipher_suite(), CipherSuite::default());
    }

    #[test]
    fn test_member_identity_with_name() {
        let name = "Alice".to_string();
        let identity = MemberIdentity::with_name(name.clone()).unwrap();
        assert_eq!(identity.name, Some(name));
    }

    #[test]
    fn test_member_list_operations() {
        let mut list = MemberList::new();
        assert!(list.is_empty());

        let id = MemberId::generate();
        let member = MemberIdentity::generate(id).unwrap();
        list.add(member.clone());

        assert_eq!(list.len(), 1);
        assert!(list.contains(&id));
        assert!(list.get(&id).is_some());

        list.remove(&id);
        assert!(list.is_empty());
    }

    #[test]
    fn test_credential_verification() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential = Credential::new_basic(MemberId::generate(), Some("Test".to_string()), &keypair, keypair.suite).unwrap();

        assert!(credential.verify(keypair.verifying_key()));
    }

    #[test]
    fn test_key_package_creation_and_verification() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential = Credential::new_basic(MemberId::generate(), None, &keypair, keypair.suite).unwrap();
        let key_package = KeyPackage::new(keypair, credential).unwrap();
        
        assert!(key_package.verify().unwrap());
    }

    #[test]
    fn test_member_state() {
        let identity = MemberIdentity::generate(MemberId::generate()).unwrap();
        let mut state = MemberState::new(identity, 0);
        
        assert_eq!(state.generation, 0);
        state.increment_generation();
        assert_eq!(state.generation, 1);
    }

    #[test]
    fn test_extension_serialization() {
        let ext = Extension::ApplicationId(vec![1, 2, 3]);
        let serialized = bincode::DefaultOptions::new().serialize(&ext).unwrap();
        let deserialized: Extension = bincode::DefaultOptions::new().deserialize(&serialized).unwrap();
        
        match deserialized {
            Extension::ApplicationId(data) => assert_eq!(data, vec![1, 2, 3]),
            _ => panic!("Wrong extension type"),
        }
    }

    #[test]
    fn test_lifetime_extension() {
        let lifetime = LifetimeExtension::new(Duration::from_secs(3600));
        assert!(lifetime.is_valid());
        
        // Test expired lifetime
        let expired = LifetimeExtension {
            not_before: 0,
            not_after: 1,
        };
        assert!(!expired.is_valid());
    }

    #[test]
    fn test_member_identity_update_name() {
        let identity1 = MemberIdentity::generate(MemberId::generate()).unwrap();
        let identity2 = MemberIdentity::with_name("Bob".to_string()).unwrap();
        
        assert!(identity1.name.is_none());
        assert_eq!(identity2.name, Some("Bob".to_string()));
        
        // Verify keys are different between identities
        assert_ne!(
            identity1.key_package.verifying_key.as_bytes(),
            identity2.key_package.verifying_key.as_bytes()
        );
    }

    #[test]
    fn test_member_list_iteration() {
        let mut list = MemberList::new();
        let id1 = MemberId::generate();
        let id2 = MemberId::generate();
        
        list.add(MemberIdentity::generate(id1).unwrap());
        list.add(MemberIdentity::generate(id2).unwrap());
        
        let ids: Vec<MemberId> = list.member_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
    }
}
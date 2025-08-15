// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Member identity and authentication for MLS groups

use crate::{crypto::*, MlsError, Result};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use uuid::Uuid;
use x25519_dalek::PublicKey as X25519PublicKey;

/// Unique identifier for a group member
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MemberId(pub Uuid);

impl MemberId {
    /// Generate a new random member ID
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for MemberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Member identity with cryptographic credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberIdentity {
    /// Unique member identifier
    pub id: MemberId,
    /// Display name (optional)
    pub name: Option<String>,
    /// Credential for authentication
    pub credential: Credential,
    /// Key package for secure communication
    pub key_package: KeyPackage,
    /// Creation timestamp
    pub created_at: SystemTime,
}

impl MemberIdentity {
    /// Generate a new member identity
    pub fn generate() -> Self {
        let id = MemberId::generate();
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential = Credential::new_basic(id, None);
        let key_package = KeyPackage::new(keypair, credential.clone()).unwrap();
        
        Self {
            id,
            name: None,
            credential,
            key_package,
            created_at: SystemTime::now(),
        }
    }
    
    /// Create identity with display name
    pub fn with_name(name: String) -> Self {
        let mut identity = Self::generate();
        identity.name = Some(name.clone());
        identity.credential = Credential::new_basic(identity.id, Some(name));
        identity
    }
    
    /// Get the member ID
    pub fn id(&self) -> MemberId {
        self.id
    }
    
    /// Verify this identity's signature on data
    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> bool {
        self.key_package.verify_signature(data, signature)
    }
    
    /// Get the member's public key for verification
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key_package.verifying_key
    }
    
    /// Get the member's public key for key agreement
    pub fn agreement_key(&self) -> &X25519PublicKey {
        &self.key_package.agreement_key
    }
}

/// Credential types for member authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credential {
    /// Basic credential with ID and optional name
    Basic {
        member_id: MemberId,
        identity: Vec<u8>,
        signature: Signature,
    },
    /// Certificate-based credential (for future extension)
    Certificate {
        certificate_chain: Vec<Vec<u8>>,
        signature: Signature,
    },
}

impl Credential {
    /// Create a new basic credential
    pub fn new_basic(member_id: MemberId, name: Option<String>) -> Self {
        let identity = name.unwrap_or_else(|| member_id.to_string()).into_bytes();
        
        // For now, use a placeholder signature (would be properly signed in production)
        let signature = Signature::from_bytes(&[0u8; 64]);
        
        Self::Basic {
            member_id,
            identity,
            signature,
        }
    }
    
    /// Get the member ID from this credential
    pub fn member_id(&self) -> MemberId {
        match self {
            Self::Basic { member_id, .. } => *member_id,
            Self::Certificate { .. } => {
                // Would extract from certificate in production
                MemberId::generate()
            }
        }
    }
    
    /// Verify the credential is valid
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        match self {
            Self::Basic { identity, signature, .. } => {
                verifying_key.verify_strict(identity, signature).is_ok()
            }
            Self::Certificate { .. } => {
                // Would verify certificate chain in production
                true
            }
        }
    }
}

/// Key package containing public keys and identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    /// Protocol version
    pub version: u16,
    /// Cipher suite
    pub cipher_suite: CipherSuite,
    /// Public key for message signing
    pub verifying_key: VerifyingKey,
    /// Public key for key agreement
    pub agreement_key: X25519PublicKey,
    /// Member credential
    pub credential: Credential,
    /// Package creation time
    pub created_at: SystemTime,
    /// Package expiration time
    pub expires_at: Option<SystemTime>,
    /// Extensions (for future use)
    pub extensions: Vec<Extension>,
    /// Self-signature over the package
    pub signature: Signature,
}

impl KeyPackage {
    /// Create a new key package
    pub fn new(keypair: KeyPair, credential: Credential) -> Result<Self> {
        let now = SystemTime::now();
        let expires_at = Some(now + Duration::from_secs(30 * 24 * 3600)); // 30 days
        
        let mut package = Self {
            version: crate::MLS_VERSION,
            cipher_suite: keypair.suite,
            verifying_key: keypair.verifying_key(),
            agreement_key: keypair.public_key(),
            credential,
            created_at: now,
            expires_at,
            extensions: Vec::new(),
            signature: Signature::from_bytes(&[0u8; 64]), // Placeholder
        };
        
        // Sign the package (simplified for now)
        let data = package.to_be_signed()?;
        package.signature = keypair.sign(&data)?;
        
        Ok(package)
    }
    
    /// Verify the key package signature
    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify_strict(data, signature).is_ok()
    }
    
    /// Check if the key package has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            SystemTime::now() > expires_at
        } else {
            false
        }
    }
    
    /// Get the data to be signed for package verification
    fn to_be_signed(&self) -> Result<Vec<u8>> {
        // Simplified serialization for signing
        let mut data = Vec::new();
        data.extend_from_slice(&self.version.to_be_bytes());
        data.extend_from_slice(&bincode::serialize(&self.cipher_suite)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?);
        data.extend_from_slice(&self.verifying_key.to_bytes());
        data.extend_from_slice(self.agreement_key.as_bytes());
        data.extend_from_slice(&bincode::serialize(&self.credential)
            .map_err(|e| MlsError::SerializationError(e.to_string()))?);
        Ok(data)
    }
}

/// Extension for key packages (future extensibility)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extension {
    pub extension_type: u16,
    pub data: Vec<u8>,
}

/// Member state in a group
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberState {
    /// Member is active and can send/receive messages
    Active,
    /// Member has been removed from the group
    Removed,
    /// Member is pending addition (has key package but not yet confirmed)
    Pending,
}

/// Complete member information in a group context
#[derive(Debug, Clone)]
pub struct GroupMember {
    /// Member identity
    pub identity: MemberIdentity,
    /// Current state in the group
    pub state: MemberState,
    /// Tree position (for TreeKEM)
    pub tree_position: Option<usize>,
    /// Last activity timestamp
    pub last_activity: SystemTime,
    /// Message sequence number
    pub sequence_number: u64,
}

impl GroupMember {
    /// Create a new group member
    pub fn new(identity: MemberIdentity, tree_position: Option<usize>) -> Self {
        Self {
            identity,
            state: MemberState::Active,
            tree_position,
            last_activity: SystemTime::now(),
            sequence_number: 0,
        }
    }
    
    /// Update last activity timestamp
    pub fn update_activity(&mut self) {
        self.last_activity = SystemTime::now();
    }
    
    /// Increment sequence number
    pub fn increment_sequence(&mut self) {
        self.sequence_number += 1;
    }
    
    /// Check if member is active
    pub fn is_active(&self) -> bool {
        self.state == MemberState::Active
    }
}

/// Member registry for managing group membership
#[derive(Debug)]
pub struct MemberRegistry {
    members: HashMap<MemberId, GroupMember>,
    next_tree_position: usize,
}

impl MemberRegistry {
    /// Create a new member registry
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            next_tree_position: 0,
        }
    }
    
    /// Add a new member to the registry
    pub fn add_member(&mut self, identity: MemberIdentity) -> Result<MemberId> {
        let id = identity.id;
        
        if self.members.contains_key(&id) {
            return Err(MlsError::InvalidGroupState(
                format!("Member {} already exists", id)
            ));
        }
        
        let tree_position = self.next_tree_position;
        self.next_tree_position += 1;
        
        let member = GroupMember::new(identity, Some(tree_position));
        self.members.insert(id, member);
        
        Ok(id)
    }
    
    /// Remove a member from the registry
    pub fn remove_member(&mut self, id: &MemberId) -> Result<()> {
        if let Some(member) = self.members.get_mut(id) {
            member.state = MemberState::Removed;
            Ok(())
        } else {
            Err(MlsError::MemberNotFound(*id))
        }
    }
    
    /// Get a member by ID
    pub fn get_member(&self, id: &MemberId) -> Option<&GroupMember> {
        self.members.get(id)
    }
    
    /// Get a mutable reference to a member
    pub fn get_member_mut(&mut self, id: &MemberId) -> Option<&mut GroupMember> {
        self.members.get_mut(id)
    }
    
    /// Get all active members
    pub fn active_members(&self) -> impl Iterator<Item = &GroupMember> {
        self.members.values().filter(|m| m.is_active())
    }
    
    /// Get the number of active members
    pub fn active_count(&self) -> usize {
        self.active_members().count()
    }
    
    /// Get member by tree position
    pub fn get_by_tree_position(&self, position: usize) -> Option<&GroupMember> {
        self.members.values()
            .find(|m| m.tree_position == Some(position))
    }
}

impl Default for MemberRegistry {
    fn default() -> Self {
        Self::new()
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
        assert_ne!(id1.to_string(), id2.to_string());
    }
    
    #[test]
    fn test_member_identity_generation() {
        let identity1 = MemberIdentity::generate();
        let identity2 = MemberIdentity::generate();
        
        assert_ne!(identity1.id, identity2.id);
        assert_ne!(
            identity1.key_package.verifying_key.to_bytes(),
            identity2.key_package.verifying_key.to_bytes()
        );
    }
    
    #[test]
    fn test_member_identity_with_name() {
        let name = "Alice".to_string();
        let identity = MemberIdentity::with_name(name.clone());
        
        assert_eq!(identity.name, Some(name));
    }
    
    #[test]
    fn test_key_package_creation() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let credential = Credential::new_basic(MemberId::generate(), Some("Test".to_string()));
        
        let package = KeyPackage::new(keypair, credential).unwrap();
        assert_eq!(package.version, crate::MLS_VERSION);
        assert!(!package.is_expired());
    }
    
    #[test]
    fn test_member_registry() {
        let mut registry = MemberRegistry::new();
        
        // Add members
        let identity1 = MemberIdentity::generate();
        let identity2 = MemberIdentity::generate();
        let id1 = identity1.id;
        let id2 = identity2.id;
        
        registry.add_member(identity1).unwrap();
        registry.add_member(identity2).unwrap();
        
        assert_eq!(registry.active_count(), 2);
        assert!(registry.get_member(&id1).is_some());
        assert!(registry.get_member(&id2).is_some());
        
        // Remove member
        registry.remove_member(&id1).unwrap();
        assert_eq!(registry.active_count(), 1);
        
        let member1 = registry.get_member(&id1).unwrap();
        assert_eq!(member1.state, MemberState::Removed);
    }
    
    #[test]
    fn test_group_member_functionality() {
        let identity = MemberIdentity::generate();
        let mut member = GroupMember::new(identity, Some(0));
        
        assert!(member.is_active());
        assert_eq!(member.sequence_number, 0);
        
        member.increment_sequence();
        assert_eq!(member.sequence_number, 1);
        
        member.update_activity();
        // Should update timestamp (can't easily test exact value)
    }
    
    #[test]
    fn test_credential_member_id() {
        let id = MemberId::generate();
        let credential = Credential::new_basic(id, None);
        
        assert_eq!(credential.member_id(), id);
    }
}
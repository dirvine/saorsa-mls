//! MLS protocol messages and state machine

use crate::{EpochNumber, MessageSequence, MlsError, Result, crypto::*, member::*};
use bincode::Options;
use saorsa_pqc::api::MlDsaSignature;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// MLS message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MlsMessage {
    /// Handshake message for group operations
    Handshake(HandshakeMessage),
    /// Application message with encrypted content
    Application(ApplicationMessage),
    /// Welcome message for new members
    Welcome(WelcomeMessage),
}

impl MlsMessage {
    /// Get the epoch number for this message
    pub fn epoch(&self) -> EpochNumber {
        match self {
            Self::Handshake(msg) => msg.epoch,
            Self::Application(msg) => msg.epoch,
            Self::Welcome(msg) => msg.epoch,
        }
    }

    /// Get the sender of this message
    pub fn sender(&self) -> MemberId {
        match self {
            Self::Handshake(msg) => msg.sender,
            Self::Application(msg) => msg.sender,
            Self::Welcome(msg) => msg.sender,
        }
    }

    /// Verify the message signature
    pub fn verify_signature(&self, verifying_key: &saorsa_pqc::api::MlDsaPublicKey) -> bool {
        let (data, signature) = match self {
            Self::Handshake(msg) => (&msg.content, &msg.signature),
            Self::Application(msg) => (&msg.ciphertext, &msg.signature),
            Self::Welcome(msg) => (&msg.group_info, &msg.signature),
        };

        use saorsa_pqc::api::MlDsa;
        let ml_dsa = MlDsa::new(saorsa_pqc::api::MlDsaVariant::MlDsa65);
        ml_dsa.verify(verifying_key, data, signature).is_ok()
    }
}

/// Handshake message content types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeContent {
    /// Add a new member to the group
    Add(AddProposal),
    /// Remove a member from the group
    Remove(RemoveProposal),
    /// Update member's key material
    Update(UpdateProposal),
    /// Commit pending proposals
    Commit(CommitMessage),
}

/// Handshake message for group operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub content: Vec<u8>,
    pub signature: MlDsaSignature,
}

/// Application message with encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMessage {
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub generation: u32,
    pub sequence: MessageSequence,
    pub ciphertext: Vec<u8>,
    pub signature: MlDsaSignature,
}

/// Welcome message for new members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMessage {
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub cipher_suite: CipherSuite,
    pub group_info: Vec<u8>,
    pub secrets: Vec<EncryptedGroupSecrets>,
    pub signature: MlDsaSignature,
}

/// Proposal to add a new member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddProposal {
    pub key_package: KeyPackage,
}

/// Proposal to remove a member
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveProposal {
    pub removed: MemberId,
}

/// Proposal to update member's keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProposal {
    pub key_package: KeyPackage,
    pub signature: MlDsaSignature,
}

/// Commit message containing proposals and path updates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitMessage {
    pub proposals: Vec<ProposalRef>,
    pub path: Option<UpdatePath>,
}

/// Reference to a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalRef {
    /// Reference to a proposal by hash
    Reference(Vec<u8>),
    /// Inline proposal
    Inline(ProposalContent),
}

/// Proposal content wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalContent {
    Add(AddProposal),
    Remove(RemoveProposal),
    Update(UpdateProposal),
}

/// Update path for tree operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePath {
    pub leaf_key_package: KeyPackage,
    pub nodes: Vec<UpdatePathNode>,
}

/// Node in an update path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePathNode {
    pub public_key: saorsa_pqc::api::MlKemPublicKey,
    pub encrypted_path_secret: Vec<EncryptedPathSecret>,
}

/// Encrypted group secrets for welcome messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGroupSecrets {
    pub recipient_key_package_hash: Vec<u8>,
    pub encrypted_group_info: Vec<u8>,
    pub encrypted_path_secret: Vec<u8>,
}

/// Message framing with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFrame {
    pub schema_version: u8,
    pub message_type: MessageType,
    pub epoch: EpochNumber,
    pub sender: MemberId,
    pub authenticated_data: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: MlDsaSignature,
}

/// Message types in the protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    Handshake = 1,
    Application = 2,
    Welcome = 3,
    GroupInfo = 4,
    KeyPackage = 5,
}

/// Group information for synchronization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    pub group_id: Vec<u8>,
    pub epoch: EpochNumber,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub confirmation_tag: Vec<u8>,
    pub signer: MemberId,
}

/// Tree structure for key management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeKemState {
    pub nodes: Vec<TreeNode>,
    pub epoch: EpochNumber,
}

/// Node in the TreeKEM structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeNode {
    Leaf(LeafNode),
    Parent(ParentNode),
}

/// Leaf node containing member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafNode {
    pub key_package: Option<KeyPackage>,
    pub unmerged_leaves: Vec<MemberId>,
}

/// Parent node in the tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    pub public_key: Option<saorsa_pqc::api::MlKemPublicKey>,
    pub unmerged_leaves: Vec<MemberId>,
}

/// Encrypted path secret for tree operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPathSecret {
    /// Recipient of this encrypted secret
    pub recipient: MemberId,
    /// Encrypted path secret using ML-KEM
    pub ciphertext: saorsa_pqc::api::MlKemCiphertext,
}

/// Protocol constants
pub mod constants {
    /// Maximum group size
    pub const MAX_GROUP_SIZE: usize = 1000;
    /// Maximum message size in bytes
    pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024; // 1MB
    /// Default epoch lifetime in seconds
    pub const EPOCH_LIFETIME: u64 = 86400; // 24 hours
}

/// Validation functions for protocol messages
impl HandshakeMessage {
    /// Validate the handshake message
    pub fn validate(&self) -> Result<()> {
        if self.content.is_empty() {
            return Err(MlsError::InvalidMessage("Empty handshake content".to_string()));
        }
        if self.content.len() > constants::MAX_MESSAGE_SIZE {
            return Err(MlsError::InvalidMessage("Message too large".to_string()));
        }
        Ok(())
    }
}

impl ApplicationMessage {
    /// Validate the application message
    pub fn validate(&self) -> Result<()> {
        if self.ciphertext.is_empty() {
            return Err(MlsError::InvalidMessage("Empty ciphertext".to_string()));
        }
        if self.ciphertext.len() > constants::MAX_MESSAGE_SIZE {
            return Err(MlsError::InvalidMessage("Message too large".to_string()));
        }
        Ok(())
    }
}

impl WelcomeMessage {
    /// Validate the welcome message
    pub fn validate(&self) -> Result<()> {
        if self.group_info.is_empty() {
            return Err(MlsError::InvalidMessage("Empty group info".to_string()));
        }
        if self.secrets.is_empty() {
            return Err(MlsError::InvalidMessage("No encrypted secrets".to_string()));
        }
        Ok(())
    }
}

/// State machine for protocol message processing
#[derive(Debug, Clone)]
pub struct ProtocolState {
    pub epoch: EpochNumber,
    pub pending_proposals: Vec<ProposalContent>,
    pub confirmed_transcript_hash: Vec<u8>,
}

impl ProtocolState {
    /// Create a new protocol state
    pub fn new(epoch: EpochNumber) -> Self {
        Self {
            epoch,
            pending_proposals: Vec::new(),
            confirmed_transcript_hash: Vec::new(),
        }
    }

    /// Add a proposal to pending list
    pub fn add_proposal(&mut self, proposal: ProposalContent) {
        self.pending_proposals.push(proposal);
    }

    /// Clear pending proposals after commit
    pub fn clear_proposals(&mut self) {
        self.pending_proposals.clear();
    }

    /// Update transcript hash
    pub fn update_transcript(&mut self, data: &[u8]) {
        let hasher = Hash::new(CipherSuite::default());
        let mut input = self.confirmed_transcript_hash.clone();
        input.extend_from_slice(data);
        self.confirmed_transcript_hash = hasher.hash(&input);
    }
}

/// Serialization helpers
impl MlsMessage {
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::DefaultOptions::new()
            .serialize(self)
            .map_err(|e| MlsError::SerializationError(e.to_string()))
    }

    /// Deserialize message from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::DefaultOptions::new()
            .deserialize(data)
            .map_err(|e| MlsError::DeserializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_message_serialization() {
        let msg = HandshakeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            content: vec![1, 2, 3],
            signature: create_test_signature(),
        };

        let mls_msg = MlsMessage::Handshake(msg);
        let bytes = mls_msg.to_bytes().unwrap();
        let decoded = MlsMessage::from_bytes(&bytes).unwrap();

        assert_eq!(mls_msg.epoch(), decoded.epoch());
        assert_eq!(mls_msg.sender(), decoded.sender());
    }

    #[test]
    fn test_handshake_validation() {
        let valid = HandshakeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            content: vec![1, 2, 3],
            signature: create_test_signature(),
        };
        assert!(valid.validate().is_ok());

        let empty = HandshakeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            content: vec![],
            signature: create_test_signature(),
        };
        assert!(empty.validate().is_err());
    }

    #[test]
    fn test_protocol_state() {
        let mut state = ProtocolState::new(0);
        assert!(state.pending_proposals.is_empty());

        let proposal = ProposalContent::Remove(RemoveProposal {
            removed: MemberId::generate(),
        });
        state.add_proposal(proposal);
        assert_eq!(state.pending_proposals.len(), 1);

        state.clear_proposals();
        assert!(state.pending_proposals.is_empty());
    }

    #[test]
    fn test_tree_node_types() {
        let leaf = TreeNode::Leaf(LeafNode {
            key_package: None,
            unmerged_leaves: vec![],
        });

        let parent = TreeNode::Parent(ParentNode {
            public_key: None,
            unmerged_leaves: vec![],
        });

        match leaf {
            TreeNode::Leaf(_) => (),
            _ => panic!("Expected leaf node"),
        }

        match parent {
            TreeNode::Parent(_) => (),
            _ => panic!("Expected parent node"),
        }
    }

    #[test]
    fn test_message_type_equality() {
        assert_eq!(MessageType::Handshake, MessageType::Handshake);
        assert_ne!(MessageType::Handshake, MessageType::Application);
    }

    #[test]
    fn test_group_info_serialization() {
        let info = GroupInfo {
            group_id: vec![1, 2, 3],
            epoch: 42,
            tree_hash: vec![4, 5, 6],
            confirmed_transcript_hash: vec![7, 8, 9],
            extensions: vec![],
            confirmation_tag: vec![10, 11, 12],
            signer: MemberId::generate(),
        };

        let bytes = bincode::DefaultOptions::new().serialize(&info).unwrap();
        let decoded: GroupInfo = bincode::DefaultOptions::new().deserialize(&bytes).unwrap();

        assert_eq!(info.group_id, decoded.group_id);
        assert_eq!(info.epoch, decoded.epoch);
    }

    #[test]
    fn test_update_path_construction() {
        let keypair = KeyPair::generate(CipherSuite::default());
        let member_id = MemberId::generate();
        let cred = Credential::new_basic(member_id, None, &keypair, keypair.suite).unwrap();
        let key_package = KeyPackage::new(keypair, cred).unwrap();

        let path = UpdatePath {
            leaf_key_package: key_package,
            nodes: vec![],
        };

        assert!(path.nodes.is_empty());
    }

    // Helper function to create test signature
    fn create_test_signature() -> MlDsaSignature {
        let keypair = KeyPair::generate(CipherSuite::default());
        keypair.sign(b"test").unwrap()
    }

    #[test]
    fn test_encrypted_path_secret() {
        let keypair1 = KeyPair::generate(CipherSuite::default());
        let keypair2 = KeyPair::generate(CipherSuite::default());
        let member_id = MemberId::generate();
        
        // Create encrypted path secret using ML-KEM
        let (ciphertext, _shared_secret) = keypair1.encapsulate(keypair2.public_key()).unwrap();
        
        let eps = EncryptedPathSecret {
            recipient: member_id,
            ciphertext,
        };
        
        assert_eq!(eps.recipient, member_id);
    }

    #[test]
    fn test_welcome_message_validation() {
        let valid = WelcomeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            cipher_suite: CipherSuite::default(),
            group_info: vec![1, 2, 3],
            secrets: vec![EncryptedGroupSecrets {
                recipient_key_package_hash: vec![1],
                encrypted_group_info: vec![2],
                encrypted_path_secret: vec![3],
            }],
            signature: create_test_signature(),
        };
        assert!(valid.validate().is_ok());

        let no_secrets = WelcomeMessage {
            epoch: 0,
            sender: MemberId::generate(),
            cipher_suite: CipherSuite::default(),
            group_info: vec![1, 2, 3],
            secrets: vec![],
            signature: create_test_signature(),
        };
        assert!(no_secrets.validate().is_err());
    }
}
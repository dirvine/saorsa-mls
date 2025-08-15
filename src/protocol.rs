// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MLS protocol messages and state machine

use crate::{EpochNumber, MessageSequence, MlsError, Result, crypto::*, member::*};
use bincode::Options;
use ed25519_dalek::Signature;
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
    pub fn verify_signature(&self, verifying_key: &ed25519_dalek::VerifyingKey) -> bool {
        let (data, signature) = match self {
            Self::Handshake(msg) => (&msg.content, &msg.signature),
            Self::Application(msg) => (&msg.ciphertext, &msg.signature),
            Self::Welcome(msg) => (&msg.group_info, &msg.signature),
        };

        verifying_key.verify_strict(data, signature).is_ok()
    }
}

/// Handshake message for group management operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeMessage {
    /// Group identifier
    pub group_id: GroupId,
    /// Current epoch number
    pub epoch: EpochNumber,
    /// Message sender
    pub sender: MemberId,
    /// Message sequence number
    pub sequence: MessageSequence,
    /// Handshake content
    pub content: Vec<u8>,
    /// Digital signature
    pub signature: Signature,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Application message with encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationMessage {
    /// Group identifier
    pub group_id: GroupId,
    /// Current epoch number
    pub epoch: EpochNumber,
    /// Message sender
    pub sender: MemberId,
    /// Message sequence number
    pub sequence: MessageSequence,
    /// Encrypted content
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    pub signature: Signature,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Welcome message for new group members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WelcomeMessage {
    /// Group identifier
    pub group_id: GroupId,
    /// Epoch when member was added
    pub epoch: EpochNumber,
    /// Member who sent the welcome
    pub sender: MemberId,
    /// Encrypted group information
    pub group_info: Vec<u8>,
    /// List of new member IDs
    pub new_members: Vec<MemberId>,
    /// Digital signature
    pub signature: Signature,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Group proposal types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proposal {
    /// Add a new member to the group
    Add {
        key_package: KeyPackage,
        proposer: MemberId,
    },
    /// Remove a member from the group
    Remove {
        member_id: MemberId,
        proposer: MemberId,
    },
    /// Update own key package
    Update {
        key_package: KeyPackage,
        member_id: MemberId,
    },
    /// Pre-shared key proposal
    PreSharedKey {
        psk_id: Vec<u8>,
        psk_nonce: Vec<u8>,
        proposer: MemberId,
    },
}

impl Proposal {
    /// Get the member who made this proposal
    pub fn proposer(&self) -> MemberId {
        match self {
            Self::Add { proposer, .. } => *proposer,
            Self::Remove { proposer, .. } => *proposer,
            Self::Update { member_id, .. } => *member_id,
            Self::PreSharedKey { proposer, .. } => *proposer,
        }
    }

    /// Get the proposal type as a string
    pub fn proposal_type(&self) -> &'static str {
        match self {
            Self::Add { .. } => "add",
            Self::Remove { .. } => "remove",
            Self::Update { .. } => "update",
            Self::PreSharedKey { .. } => "psk",
        }
    }
}

/// Commit message that finalizes pending proposals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Group identifier
    pub group_id: GroupId,
    /// Current epoch (before commit)
    pub epoch: EpochNumber,
    /// Member making the commit
    pub sender: MemberId,
    /// Proposals being committed
    pub proposals: Vec<Proposal>,
    /// Path update for TreeKEM
    pub path: Option<UpdatePath>,
    /// Confirmation tag
    pub confirmation_tag: Vec<u8>,
    /// Digital signature
    pub signature: Signature,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// TreeKEM update path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePath {
    /// New public key for the sender
    pub leaf_key_package: KeyPackage,
    /// Encrypted path secrets for tree update
    pub nodes: Vec<UpdatePathNode>,
}

/// Node in the TreeKEM update path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePathNode {
    /// Public key for this tree level
    pub public_key: Vec<u8>,
    /// Encrypted secrets for this level
    pub encrypted_path_secret: Vec<EncryptedPathSecret>,
}

/// Encrypted path secret for TreeKEM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPathSecret {
    /// Recipient of this encrypted secret
    pub recipient: MemberId,
    /// Encrypted secret data
    pub ciphertext: Vec<u8>,
}

/// Group information shared with new members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Group identifier
    pub group_id: GroupId,
    /// Current epoch
    pub epoch: EpochNumber,
    /// Group configuration
    pub config: GroupConfig,
    /// Current member list
    pub roster: Vec<MemberId>,
    /// Group state tree
    pub tree_hash: Vec<u8>,
    /// Confirmation tag
    pub confirmation_tag: Vec<u8>,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Message framing for wire protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageFrame {
    /// Protocol version
    pub version: u16,
    /// Wire format
    pub wire_format: crate::WireFormat,
    /// Message content
    pub content: MlsMessage,
    /// Frame size (for streaming)
    pub frame_size: u32,
}

impl MessageFrame {
    /// Create a new message frame
    pub fn new(content: MlsMessage) -> Self {
        let serialized_size = bincode::serialized_size(&content).unwrap_or(0) as u32;

        Self {
            version: crate::MLS_VERSION,
            wire_format: crate::WireFormat::default(),
            content,
            frame_size: serialized_size,
        }
    }

    /// Serialize the frame for transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let cfg = bincode::DefaultOptions::new().with_limit(1_048_576);
        cfg.serialize(self)
            .map_err(|e| MlsError::SerializationError(e.to_string()))
    }

    /// Deserialize frame from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let cfg = bincode::DefaultOptions::new().with_limit(1_048_576);
        cfg.deserialize(data)
            .map_err(|e| MlsError::SerializationError(e.to_string()))
    }
}

/// Protocol state machine for processing messages
#[derive(Debug)]
pub struct ProtocolStateMachine {
    current_epoch: EpochNumber,
    pending_proposals: Vec<Proposal>,
    #[allow(dead_code)] // Future use for message ordering
    message_cache: Vec<MlsMessage>,
}

impl ProtocolStateMachine {
    /// Create a new protocol state machine
    pub fn new(initial_epoch: EpochNumber) -> Self {
        Self {
            current_epoch: initial_epoch,
            pending_proposals: Vec::new(),
            message_cache: Vec::new(),
        }
    }

    /// Process an incoming MLS message
    pub fn process_message(&mut self, message: MlsMessage) -> Result<Vec<ProtocolEvent>> {
        let mut events = Vec::new();

        // Validate epoch
        if message.epoch() < self.current_epoch {
            return Err(MlsError::InvalidEpoch {
                expected: self.current_epoch,
                actual: message.epoch(),
            });
        }

        match message {
            MlsMessage::Handshake(handshake) => {
                events.extend(self.process_handshake(handshake)?);
            }
            MlsMessage::Application(app) => {
                events.push(ProtocolEvent::ApplicationMessage {
                    sender: app.sender,
                    ciphertext: app.ciphertext,
                });
            }
            MlsMessage::Welcome(welcome) => {
                events.push(ProtocolEvent::WelcomeReceived {
                    new_members: welcome.new_members,
                    group_info: welcome.group_info,
                });
            }
        }

        Ok(events)
    }

    /// Process a handshake message
    fn process_handshake(&mut self, handshake: HandshakeMessage) -> Result<Vec<ProtocolEvent>> {
        let mut events = Vec::new();

        // Parse handshake content (simplified)
        if let Ok(proposal) = bincode::deserialize::<Proposal>(&handshake.content) {
            self.pending_proposals.push(proposal.clone());
            events.push(ProtocolEvent::ProposalReceived(proposal));
        } else if let Ok(commit) = bincode::deserialize::<Commit>(&handshake.content) {
            events.extend(self.process_commit(commit)?);
        }

        Ok(events)
    }

    /// Process a commit message
    fn process_commit(&mut self, commit: Commit) -> Result<Vec<ProtocolEvent>> {
        let mut events = Vec::new();

        // Apply committed proposals
        for proposal in &commit.proposals {
            match proposal {
                Proposal::Add { key_package, .. } => {
                    events.push(ProtocolEvent::MemberAdded {
                        member_id: key_package.credential.member_id(),
                        key_package: key_package.clone(),
                    });
                }
                Proposal::Remove { member_id, .. } => {
                    events.push(ProtocolEvent::MemberRemoved {
                        member_id: *member_id,
                    });
                }
                Proposal::Update {
                    key_package,
                    member_id,
                } => {
                    events.push(ProtocolEvent::MemberUpdated {
                        member_id: *member_id,
                        key_package: key_package.clone(),
                    });
                }
                Proposal::PreSharedKey { .. } => {
                    events.push(ProtocolEvent::PreSharedKeyAdded);
                }
            }
        }

        // Clear pending proposals
        self.pending_proposals.clear();

        // Advance epoch
        self.current_epoch = commit.epoch + 1;
        events.push(ProtocolEvent::EpochAdvanced {
            new_epoch: self.current_epoch,
        });

        Ok(events)
    }

    /// Get current epoch
    pub fn current_epoch(&self) -> EpochNumber {
        self.current_epoch
    }

    /// Get pending proposals
    pub fn pending_proposals(&self) -> &[Proposal] {
        &self.pending_proposals
    }

    /// Set current epoch (for group management)
    pub fn set_epoch(&mut self, epoch: EpochNumber) {
        self.current_epoch = epoch;
    }
}

/// Events generated by the protocol state machine
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    /// A proposal was received
    ProposalReceived(Proposal),
    /// A member was added to the group
    MemberAdded {
        member_id: MemberId,
        key_package: KeyPackage,
    },
    /// A member was removed from the group
    MemberRemoved { member_id: MemberId },
    /// A member updated their key package
    MemberUpdated {
        member_id: MemberId,
        key_package: KeyPackage,
    },
    /// Pre-shared key was added
    PreSharedKeyAdded,
    /// Epoch advanced
    EpochAdvanced { new_epoch: EpochNumber },
    /// Application message received
    ApplicationMessage {
        sender: MemberId,
        ciphertext: Vec<u8>,
    },
    /// Welcome message received
    WelcomeReceived {
        new_members: Vec<MemberId>,
        group_info: Vec<u8>,
    },
}

/// Group identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl GroupId {
    /// Generate a new random group ID
    pub fn generate() -> Self {
        let bytes = random_bytes(32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self(arr)
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupConfig {
    /// Cipher suite for the group
    pub cipher_suite: CipherSuite,
    /// Maximum group size
    pub max_members: usize,
    /// Key rotation interval
    pub key_rotation_interval: std::time::Duration,
    /// Group extensions
    pub extensions: Vec<Extension>,
}

impl Default for GroupConfig {
    fn default() -> Self {
        Self {
            cipher_suite: CipherSuite::default(),
            max_members: crate::MAX_GROUP_SIZE,
            key_rotation_interval: crate::DEFAULT_KEY_ROTATION_INTERVAL,
            extensions: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_id_generation() {
        let id1 = GroupId::generate();
        let id2 = GroupId::generate();

        assert_ne!(id1, id2);
        assert_ne!(id1.to_string(), id2.to_string());
    }

    #[test]
    fn test_message_frame() {
        let app_msg = ApplicationMessage {
            group_id: GroupId::generate(),
            epoch: 1,
            sender: MemberId::generate(),
            sequence: 1,
            ciphertext: vec![1, 2, 3, 4],
            signature: Signature::from_bytes(&[0u8; 64]),
            timestamp: SystemTime::now(),
        };

        let frame = MessageFrame::new(MlsMessage::Application(app_msg));
        assert_eq!(frame.version, crate::MLS_VERSION);
        assert!(frame.frame_size > 0);
    }

    #[test]
    fn test_protocol_state_machine() {
        let state = ProtocolStateMachine::new(0);
        assert_eq!(state.current_epoch(), 0);
        assert!(state.pending_proposals().is_empty());
    }

    #[test]
    fn test_proposal_types() {
        let member_id = MemberId::generate();
        let key_package = KeyPackage::new(
            KeyPair::generate(CipherSuite::default()),
            Credential::new_basic(member_id, None).unwrap(),
        )
        .unwrap();

        let add_proposal = Proposal::Add {
            key_package: key_package.clone(),
            proposer: member_id,
        };

        assert_eq!(add_proposal.proposer(), member_id);
        assert_eq!(add_proposal.proposal_type(), "add");
    }

    #[test]
    fn test_message_epoch_extraction() {
        let group_id = GroupId::generate();
        let sender = MemberId::generate();
        let epoch = 42;

        let handshake = MlsMessage::Handshake(HandshakeMessage {
            group_id,
            epoch,
            sender,
            sequence: 1,
            content: vec![],
            signature: Signature::from_bytes(&[0u8; 64]),
            timestamp: SystemTime::now(),
        });

        assert_eq!(handshake.epoch(), epoch);
        assert_eq!(handshake.sender(), sender);
    }
}

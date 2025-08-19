// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Fixed version of group.rs that resolves deadlock issues

use crate::{crypto::*, member::*, protocol::*, EpochNumber, MlsError, MlsStats, Result};
use bincode::Options;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::SystemTime,
};

/// Sliding replay window for sequences
#[derive(Debug, Default)]
struct ReplayWindow {
    max_seen: u64,
    window: u64,
}

impl ReplayWindow {
    // Allow if sequence is new within a 64-slot window; update state
    fn allow_and_update(&mut self, seq: u64) -> bool {
        if seq > self.max_seen {
            let shift = seq - self.max_seen;
            if shift >= 64 {
                self.window = 0;
            } else {
                self.window <<= shift;
            }
            self.window |= 1;
            self.max_seen = seq;
            true
        } else {
            let offset = self.max_seen - seq;
            if offset >= 64 {
                false
            } else {
                let mask = 1u64 << offset;
                if self.window & mask != 0 {
                    false
                } else {
                    self.window |= mask;
                    true
                }
            }
        }
    }
}

pub use crate::protocol::{GroupConfig, GroupId};

/// MLS group state with TreeKEM key management - FIXED VERSION
#[derive(Debug)]
pub struct MlsGroup {
    config: GroupConfig,
    group_id: GroupId,
    epoch: AtomicU64,
    creator: MemberIdentity,
    members: Arc<RwLock<MemberRegistry>>,
    tree: Arc<RwLock<TreeKemState>>,
    key_schedule: Arc<RwLock<Option<KeySchedule>>>,
    // Per-sender send sequence numbers
    send_sequences: Arc<DashMap<MemberId, u64>>,
    protocol_state: Arc<RwLock<ProtocolStateMachine>>,
    stats: Arc<RwLock<MlsStats>>,
    secrets: Arc<DashMap<String, crate::crypto::SecretBytes>>,
    // Per-sender replay windows
    recv_windows: Arc<DashMap<MemberId, ReplayWindow>>,
}

impl MlsGroup {
    /// Create a new MLS group
    pub async fn new(config: GroupConfig, creator: MemberIdentity) -> Result<Self> {
        let group_id = GroupId::generate();

        let mut members = MemberRegistry::new();
        members.add_member(creator.clone())?;

        let tree = TreeKemState::new(creator.key_package.agreement_key.clone())?;

        let group = Self {
            config,
            group_id,
            epoch: AtomicU64::new(0),
            creator,
            members: Arc::new(RwLock::new(members)),
            tree: Arc::new(RwLock::new(tree)),
            key_schedule: Arc::new(RwLock::new(None)),
            send_sequences: Arc::new(DashMap::new()),
            protocol_state: Arc::new(RwLock::new(ProtocolStateMachine::new(0))),
            stats: Arc::new(RwLock::new(MlsStats::default())),
            secrets: Arc::new(DashMap::new()),
            recv_windows: Arc::new(DashMap::new()),
        };

        // Initialize key schedule for epoch 0
        group.initialize_epoch_keys().await?;

        Ok(group)
    }

    /// Add a new member to the group - FIXED to avoid deadlock
    pub async fn add_member(&mut self, identity: &MemberIdentity) -> Result<WelcomeMessage> {
        // Scope locks to release before any await
        let (_member_id, _tree_position, should_advance) = {
            let mut members = self.members.write();
            let mut tree = self.tree.write();
            let mut stats = self.stats.write();

            // Check group size limit
            if members.active_member_count() >= self.config.max_members.unwrap_or(1000) as usize {
                return Err(MlsError::InvalidGroupState(
                    "Group has reached maximum size".to_string(),
                ));
            }

            // Add member to registry
            let member_id = identity.id;
            let member_index = members.add_member(identity.clone())?;

            // Update TreeKEM - use member index as tree position
            let tree_position = member_index as usize;
            tree.add_leaf(tree_position, identity.key_package.agreement_key.clone())?;

            // Update statistics
            stats.member_additions += 1;
            stats.groups_active = members.active_member_count();

            (member_id, tree_position, true)
        }; // All locks released here

        // Create welcome message (no locks held)
        let welcome = WelcomeMessage {
            epoch: self.current_epoch(),
            sender: self.creator.id,
            cipher_suite: CipherSuite::default(),
            group_info: {
                let opts = bincode::DefaultOptions::new().with_limit(1_048_576);
                opts.serialize(&self.create_group_info()?)
                    .map_err(|e| MlsError::SerializationError(e.to_string()))?
            },
            secrets: vec![], // Simplified for now
            signature: self.creator.key_package.signature.clone(),
        };

        // Advance epoch if needed (separate lock scope)
        if should_advance {
            self.advance_epoch().await?;
        }

        Ok(welcome)
    }

    /// Remove a member from the group - FIXED to avoid deadlock
    pub async fn remove_member(&mut self, member_id: &MemberId) -> Result<()> {
        // Scope locks to release before any await
        let should_advance = {
            let mut members = self.members.write();
            let mut tree = self.tree.write();
            let mut stats = self.stats.write();

            // Find member index first
            let member_index = members
                .find_member_index(member_id)
                .ok_or(MlsError::MemberNotFound(*member_id))?;

            // Remove from registry
            let _removed_member = members.remove_member(member_index)?;
            let tree_position = member_index as usize;

            // Update TreeKEM
            tree.remove_leaf(tree_position)?;

            // Update statistics
            stats.member_removals += 1;
            stats.groups_active = members.active_member_count();

            true
        }; // All locks released here

        // Advance epoch if needed (no locks held)
        if should_advance {
            self.advance_epoch().await?;
        }

        Ok(())
    }

    /// Encrypt a message for the group - FIXED to avoid deadlock
    pub async fn encrypt_message(&self, plaintext: &[u8]) -> Result<ApplicationMessage> {
        // Derive per-sender application key and base nonce
        let sender_id = self.creator.id;
        let (app_key, base_nonce) = self.get_sender_application_key_and_nonce(sender_id).await?;

        let cipher = AeadCipher::new(app_key, CipherSuite::default())?;

        // Per-sender sequence number
        let sequence = self
            .send_sequences
            .entry(sender_id)
            .and_modify(|s| *s += 1)
            .or_insert(0)
            .to_owned();
        let nonce = Self::xor_nonce_with_sequence(&base_nonce, sequence);
        let aad = self.create_application_aad_with_seq_sender(sequence, sender_id);
        let ciphertext = cipher.encrypt(&nonce, plaintext, &aad)?;

        // Combine nonce + ciphertext for wire format
        let mut wire_ciphertext = nonce;
        wire_ciphertext.extend_from_slice(&ciphertext);

        let message = ApplicationMessage {
            epoch: self.current_epoch(),
            sender: self.creator.id,
            generation: 0, // Simplified
            sequence,
            ciphertext: wire_ciphertext,
            signature: self.creator.key_package.signature.clone(),
        };

        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.messages_sent += 1;
        } // Lock released

        Ok(message)
    }

    /// Decrypt an application message - FIXED to avoid deadlock
    pub async fn decrypt_message(&self, message: &ApplicationMessage) -> Result<Vec<u8>> {
        // Verify epoch
        if message.epoch != self.current_epoch() {
            return Err(MlsError::InvalidEpoch {
                expected: self.current_epoch(),
                actual: message.epoch,
            });
        }

        // Derive per-sender key/nonce for the sender of this message
        let (receiver_key, base_nonce) = self
            .get_sender_application_key_and_nonce(message.sender)
            .await?;
        let cipher = AeadCipher::new(receiver_key, CipherSuite::default())?;

        // Extract nonce and ciphertext
        let nonce_size = CipherSuite::default().nonce_size();
        if message.ciphertext.len() < nonce_size {
            return Err(MlsError::DecryptionFailed);
        }

        let (nonce, ciphertext) = message.ciphertext.split_at(nonce_size);
        let aad = self.create_application_aad_with_seq_sender(message.sequence, message.sender);

        // Recompute expected nonce from base and sequence and compare
        let expected_nonce = Self::xor_nonce_with_sequence(&base_nonce, message.sequence);
        if nonce != expected_nonce.as_slice() {
            return Err(MlsError::DecryptionFailed);
        }

        let plaintext = cipher.decrypt(nonce, ciphertext, &aad)?;

        // Replay protection using per-sender sliding window
        if !self
            .recv_windows
            .entry(message.sender)
            .or_default()
            .allow_and_update(message.sequence)
        {
            return Err(MlsError::ProtocolError("replay detected".to_string()));
        }

        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.messages_received += 1;
        } // Lock released

        Ok(plaintext)
    }

    /// Derive and cache per-sender application key and base nonce
    async fn get_sender_application_key_and_nonce(
        &self,
        sender: MemberId,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let key_cache = format!("application_key::{}", sender);
        let nonce_cache = format!("application_nonce::{}", sender);

        if let (Some(k), Some(n)) = (self.secrets.get(&key_cache), self.secrets.get(&nonce_cache)) {
            return Ok((k.as_bytes().to_vec(), n.as_bytes().to_vec()));
        }

        // Load application secret
        let app_secret = self
            .secrets
            .get("application")
            .ok_or(MlsError::KeyDerivationError(
                "Application secret not found".to_string(),
            ))?
            .as_bytes()
            .to_vec();

        // Create a fresh key schedule instead of accessing the stored one
        let key_schedule = KeySchedule::new(CipherSuite::default());

        // Derive per-sender key and base nonce using HKDF labels
        let mut info_key = Vec::new();
        info_key.extend_from_slice(b"mls application key");
        info_key.extend_from_slice(sender.0.as_bytes());
        let app_key = key_schedule.derive_key(
            &self.current_epoch().to_be_bytes(),
            &app_secret,
            &info_key,
            32,
        )?;

        let mut info_nonce = Vec::new();
        info_nonce.extend_from_slice(b"mls application nonce");
        info_nonce.extend_from_slice(sender.0.as_bytes());
        let base_nonce = key_schedule.derive_key(
            &self.current_epoch().to_be_bytes(),
            &app_secret,
            &info_nonce,
            CipherSuite::default().nonce_size(),
        )?;

        // Cache
        self.secrets
            .insert(key_cache, crate::crypto::SecretBytes::from(app_key.clone()));
        self.secrets.insert(
            nonce_cache,
            crate::crypto::SecretBytes::from(base_nonce.clone()),
        );

        Ok((app_key, base_nonce))
    }

    /// Advance to next epoch - FIXED to avoid deadlock
    async fn advance_epoch(&self) -> Result<()> {
        let new_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;

        // Update protocol state with scoped lock
        {
            let mut state = self.protocol_state.write();
            state.set_epoch(new_epoch);
        } // Lock released

        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.epoch_transitions += 1;
        } // Lock released

        // Reinitialize keys (no locks held during async operation)
        self.initialize_epoch_keys().await?;

        Ok(())
    }

    /// Initialize cryptographic keys for current epoch - FIXED
    async fn initialize_epoch_keys(&self) -> Result<()> {
        // Get root secret with scoped lock
        let root_secret = {
            let tree = self.tree.read();
            tree.get_root_secret()?
        }; // Lock released

        let ks = KeySchedule::new(CipherSuite::default());
        let epoch_bytes = self.current_epoch().to_be_bytes();

        // Derive epoch-specific secrets (no locks held)
        let secrets = ks.derive_keys(
            &epoch_bytes,
            &root_secret,
            &[
                labels::EPOCH_SECRET,
                labels::SENDER_DATA_SECRET,
                labels::HANDSHAKE_SECRET,
                labels::APPLICATION_SECRET,
                labels::EXPORTER_SECRET,
                labels::AUTHENTICATION_SECRET,
                labels::EXTERNAL_SECRET,
                labels::CONFIRMATION_KEY,
                labels::MEMBERSHIP_KEY,
                labels::RESUMPTION_PSK,
                labels::INIT_SECRET,
            ],
            &[32; 11],
        )?;

        // Store secrets (DashMap handles concurrency)
        self.secrets.clear();
        let labels = [
            "epoch",
            "sender_data",
            "handshake",
            "application",
            "exporter",
            "authentication",
            "external",
            "confirmation",
            "membership",
            "resumption_psk",
            "init",
        ];

        for (label, secret) in labels.iter().zip(secrets.iter()) {
            self.secrets.insert(
                label.to_string(),
                crate::crypto::SecretBytes::from(secret.clone()),
            );
        }

        // Update key schedule with scoped lock
        {
            let mut key_schedule = self.key_schedule.write();
            *key_schedule = Some(ks);
        } // Lock released

        Ok(())
    }

    // Other methods remain the same but follow the pattern:
    // - Use scoped locks { } to ensure release before await
    // - Clone data if needed after lock release
    // - Never hold locks across await points

    pub fn current_epoch(&self) -> EpochNumber {
        self.epoch.load(Ordering::SeqCst)
    }

    pub async fn update_epoch(&self) -> Result<()> {
        self.advance_epoch().await
    }

    pub fn group_id(&self) -> GroupId {
        self.group_id.clone()
    }

    pub fn stats(&self) -> MlsStats {
        self.stats.read().clone()
    }

    pub fn member_count(&self) -> usize {
        self.members.read().active_member_count()
    }

    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members
            .read()
            .active_members()
            .map(|m| m.identity.id)
            .collect()
    }

    pub fn is_member_active(&self, member_id: &MemberId) -> bool {
        let members = self.members.read();
        if let Some(index) = members.find_member_index(member_id) {
            if let Some(member) = members.get_member(index) {
                return member.is_active();
            }
        }
        false
    }

    fn create_group_info(&self) -> Result<GroupInfo> {
        Ok(GroupInfo {
            group_id: self.group_id.as_bytes().to_vec(),
            epoch: self.current_epoch(),
            tree_hash: {
                let tree = self.tree.read();
                tree.compute_tree_hash()?
            }, // Lock released after getting hash
            confirmed_transcript_hash: vec![0; 32], // Simplified
            extensions: vec![],
            confirmation_tag: vec![0; 32], // Simplified
            signer: self.creator.id,
        })
    }

    fn create_application_aad(&self) -> Vec<u8> {
        let mut aad = Vec::new();
        aad.extend_from_slice(self.group_id.as_bytes());
        aad.extend_from_slice(&self.current_epoch().to_be_bytes());
        aad
    }

    fn create_application_aad_with_seq_sender(&self, sequence: u64, sender: MemberId) -> Vec<u8> {
        let mut aad = self.create_application_aad();
        aad.extend_from_slice(&sequence.to_be_bytes());
        aad.extend_from_slice(sender.0.as_bytes());
        aad
    }

    /// MLS-style nonce = base_nonce XOR seq (seq in 12 bytes BE)
    fn xor_nonce_with_sequence(base_nonce: &[u8], sequence: u64) -> Vec<u8> {
        let mut seq_bytes = [0u8; 12];
        // Put sequence in the last 8 bytes, big-endian
        seq_bytes[4..].copy_from_slice(&sequence.to_be_bytes());
        base_nonce
            .iter()
            .zip(seq_bytes.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }
}

/// TreeKEM state for managing group key derivation
#[derive(Debug)]
pub struct TreeKemState {
    /// Binary tree nodes
    nodes: Vec<Option<TreeNode>>,
    /// Tree size (number of leaves)
    size: usize,
    /// Root secret
    root_secret: Vec<u8>,
}

impl TreeKemState {
    /// Create new TreeKEM state with initial member
    pub fn new(initial_key: Vec<u8>) -> Result<Self> {
        let root_secret = random_bytes(32);
        let mut state = Self {
            nodes: Vec::new(),
            size: 0,
            root_secret,
        };

        // Add initial member
        state.add_leaf(0, initial_key)?;

        Ok(state)
    }

    /// Add a leaf node (new member)
    pub fn add_leaf(&mut self, position: usize, public_key: Vec<u8>) -> Result<()> {
        // Ensure tree capacity
        let required_size = (position + 1) * 2; // Binary tree property
        if self.nodes.len() < required_size {
            self.nodes.resize(required_size, None);
        }

        // Create leaf node
        let leaf = TreeNode {
            public_key,
            secret: random_bytes(32),
            parent: self.parent_index(position),
        };

        self.nodes[position] = Some(leaf);
        self.size = self.size.max(position + 1);

        // Update parent nodes up to root
        self.update_path(position)?;

        Ok(())
    }

    /// Remove a leaf node
    pub fn remove_leaf(&mut self, position: usize) -> Result<()> {
        if position >= self.nodes.len() {
            return Err(MlsError::TreeKemError("Invalid leaf position".to_string()));
        }

        self.nodes[position] = None;

        // Update parent path
        self.update_path(position)?;

        Ok(())
    }

    /// Get the root secret for key derivation
    pub fn get_root_secret(&self) -> Result<Vec<u8>> {
        Ok(self.root_secret.clone())
    }

    /// Compute tree hash for integrity verification
    pub fn compute_tree_hash(&self) -> Result<Vec<u8>> {
        let hash = Hash::new(CipherSuite::default());
        let mut tree_data = Vec::new();

        for n in self.nodes.iter().flatten() {
            tree_data.extend_from_slice(&n.public_key);
        }

        Ok(hash.hash(&tree_data))
    }

    // Private helper methods

    /// Update path from leaf to root
    fn update_path(&mut self, leaf_position: usize) -> Result<()> {
        let mut current = leaf_position;

        while let Some(parent_idx) = self.parent_index(current) {
            if parent_idx >= self.nodes.len() {
                self.nodes.resize(parent_idx + 1, None);
            }

            // Create or update parent node
            let left_child = self.left_child(parent_idx);
            let right_child = self.right_child(parent_idx);

            let mut parent_secret = Vec::new();

            // Combine secrets from children
            if let Some(left_idx) = left_child {
                if let Some(Some(left_node)) = self.nodes.get(left_idx) {
                    parent_secret.extend_from_slice(&left_node.secret);
                }
            }

            if let Some(right_idx) = right_child {
                if let Some(Some(right_node)) = self.nodes.get(right_idx) {
                    parent_secret.extend_from_slice(&right_node.secret);
                }
            }

            // Hash combined secrets for parent
            let hash = Hash::new(CipherSuite::default());
            let new_secret = hash.hash(&parent_secret);

            self.nodes[parent_idx] = Some(TreeNode {
                public_key: new_secret[..32].to_vec(), // Use hash as public key
                secret: new_secret.clone(),
                parent: self.parent_index(parent_idx),
            });

            current = parent_idx;
        }

        // Update root secret
        if let Some(root_node) = &self.nodes.get(self.root_index()).and_then(|n| n.as_ref()) {
            self.root_secret = root_node.secret.clone();
        }

        Ok(())
    }

    /// Get parent index for a given node
    fn parent_index(&self, index: usize) -> Option<usize> {
        if index == 0 {
            None
        } else {
            Some((index - 1) / 2)
        }
    }

    /// Get left child index
    fn left_child(&self, index: usize) -> Option<usize> {
        let child = 2 * index + 1;
        if child < self.nodes.len() {
            Some(child)
        } else {
            None
        }
    }

    /// Get right child index
    fn right_child(&self, index: usize) -> Option<usize> {
        let child = 2 * index + 2;
        if child < self.nodes.len() {
            Some(child)
        } else {
            None
        }
    }

    /// Get root index (always 0 for our tree)
    fn root_index(&self) -> usize {
        0
    }
}

/// Node in the TreeKEM binary tree
#[derive(Debug, Clone)]
struct TreeNode {
    /// Public key for this node
    public_key: Vec<u8>,
    /// Secret key material
    secret: Vec<u8>,
    /// Parent node index
    #[allow(dead_code)] // Future use for tree navigation
    parent: Option<usize>,
}

/// Group state snapshot for persistence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupState {
    pub group_id: GroupId,
    pub epoch: EpochNumber,
    pub config: GroupConfig,
    pub members: Vec<MemberId>,
    pub created_at: SystemTime,
    pub last_activity: SystemTime,
}

impl GroupState {
    /// Create state snapshot from group
    pub fn from_group(group: &MlsGroup) -> Self {
        Self {
            group_id: group.group_id.clone(),
            epoch: group.current_epoch(),
            config: group.config.clone(),
            members: group.member_ids(),
            created_at: SystemTime::now(), // Simplified
            last_activity: SystemTime::now(),
        }
    }
}

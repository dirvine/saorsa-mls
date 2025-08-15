// Copyright 2024 Saorsa Labs
//
// Fixed version of group.rs that resolves deadlock issues

use crate::{
    crypto::*, member::*, protocol::*, EpochNumber, MlsError, MlsStats, Result,
};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::{
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::SystemTime,
};

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
    message_sequence: AtomicU64,
    protocol_state: Arc<RwLock<ProtocolStateMachine>>,
    stats: Arc<RwLock<MlsStats>>,
    secrets: Arc<DashMap<String, Vec<u8>>>,
}

impl MlsGroup {
    /// Create a new MLS group
    pub async fn new(config: GroupConfig, creator: MemberIdentity) -> Result<Self> {
        let group_id = GroupId::generate();
        
        let mut members = MemberRegistry::new();
        members.add_member(creator.clone())?;
        
        let tree = TreeKemState::new(creator.key_package.agreement_key)?;
        
        let group = Self {
            config,
            group_id,
            epoch: AtomicU64::new(0),
            creator,
            members: Arc::new(RwLock::new(members)),
            tree: Arc::new(RwLock::new(tree)),
            key_schedule: Arc::new(RwLock::new(None)),
            message_sequence: AtomicU64::new(0),
            protocol_state: Arc::new(RwLock::new(ProtocolStateMachine::new(0))),
            stats: Arc::new(RwLock::new(MlsStats::default())),
            secrets: Arc::new(DashMap::new()),
        };
        
        // Initialize key schedule for epoch 0
        group.initialize_epoch_keys().await?;
        
        Ok(group)
    }
    
    /// Add a new member to the group - FIXED to avoid deadlock
    pub async fn add_member(&mut self, identity: &MemberIdentity) -> Result<WelcomeMessage> {
        // Scope locks to release before any await
        let (member_id, tree_position, should_advance) = {
            let mut members = self.members.write();
            let mut tree = self.tree.write();
            let mut stats = self.stats.write();
            
            // Check group size limit
            if members.active_count() >= self.config.max_members {
                return Err(MlsError::InvalidGroupState(
                    "Group has reached maximum size".to_string()
                ));
            }
            
            // Add member to registry
            let member_id = identity.id;
            members.add_member(identity.clone())?;
            
            // Update TreeKEM
            let tree_position = members.get_member(&member_id)
                .unwrap()
                .tree_position
                .unwrap();
            tree.add_leaf(tree_position, identity.key_package.agreement_key)?;
            
            // Update statistics
            stats.member_additions += 1;
            stats.groups_active = members.active_count();
            
            (member_id, tree_position, true)
        }; // All locks released here
        
        // Create welcome message (no locks held)
        let welcome = WelcomeMessage {
            group_id: self.group_id,
            epoch: self.current_epoch(),
            sender: self.creator.id,
            group_info: self.create_group_info()?,
            new_members: vec![member_id],
            signature: self.creator.key_package.signature,
            timestamp: SystemTime::now(),
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
            
            // Get member's tree position before removal
            let tree_position = members.get_member(member_id)
                .ok_or(MlsError::MemberNotFound(*member_id))?
                .tree_position;
            
            // Remove from registry
            members.remove_member(member_id)?;
            
            // Update TreeKEM
            if let Some(position) = tree_position {
                tree.remove_leaf(position)?;
            }
            
            // Update statistics
            stats.member_removals += 1;
            stats.groups_active = members.active_count();
            
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
        // Get application key without holding lock across await
        let sender_key = self.get_application_key_safe("sender").await?;
        
        let cipher = AeadCipher::new(sender_key, self.config.cipher_suite)?;
        
        let nonce = random_bytes(self.config.cipher_suite.nonce_size());
        let aad = self.create_application_aad()?;
        let ciphertext = cipher.encrypt(&nonce, plaintext, &aad)?;
        
        // Combine nonce + ciphertext for wire format
        let mut wire_ciphertext = nonce;
        wire_ciphertext.extend_from_slice(&ciphertext);
        
        let sequence = self.message_sequence.fetch_add(1, Ordering::SeqCst);
        
        let message = ApplicationMessage {
            group_id: self.group_id,
            epoch: self.current_epoch(),
            sender: self.creator.id,
            sequence,
            ciphertext: wire_ciphertext,
            signature: self.creator.key_package.signature,
            timestamp: SystemTime::now(),
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
        
        // Get application key without holding lock
        let receiver_key = self.get_application_key_safe("receiver").await?;
        
        let cipher = AeadCipher::new(receiver_key, self.config.cipher_suite)?;
        
        // Extract nonce and ciphertext
        let nonce_size = self.config.cipher_suite.nonce_size();
        if message.ciphertext.len() < nonce_size {
            return Err(MlsError::DecryptionFailed);
        }
        
        let (nonce, ciphertext) = message.ciphertext.split_at(nonce_size);
        let aad = self.create_application_aad()?;
        
        let plaintext = cipher.decrypt(nonce, ciphertext, &aad)?;
        
        // Update statistics with scoped lock
        {
            let mut stats = self.stats.write();
            stats.messages_received += 1;
        } // Lock released
        
        Ok(plaintext)
    }
    
    /// Get application key safely without deadlock
    async fn get_application_key_safe(&self, purpose: &str) -> Result<Vec<u8>> {
        // Check secrets cache first (DashMap is safe for concurrent access)
        if let Some(key) = self.secrets.get(purpose) {
            return Ok(key.clone());
        }
        
        // If not cached, derive it (with scoped lock)
        let key = {
            let key_schedule = self.key_schedule.read();
            if let Some(ks) = key_schedule.as_ref() {
                let epoch_bytes = self.current_epoch().to_be_bytes();
                ks.derive_key(&epoch_bytes, purpose.as_bytes(), 32)?
            } else {
                return Err(MlsError::InvalidGroupState("No key schedule".into()));
            }
        }; // Lock released
        
        // Cache the key
        self.secrets.insert(purpose.to_string(), key.clone());
        
        Ok(key)
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
        
        let ks = KeySchedule::new(self.config.cipher_suite);
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
            "epoch", "sender_data", "handshake", "application",
            "exporter", "authentication", "external", "confirmation",
            "membership", "resumption_psk", "init",
        ];
        
        for (label, secret) in labels.iter().zip(secrets.iter()) {
            self.secrets.insert(label.to_string(), secret.clone());
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
        self.group_id
    }
    
    pub fn stats(&self) -> MlsStats {
        self.stats.read().clone()
    }
    
    pub fn member_count(&self) -> usize {
        self.members.read().active_count()
    }
    
    pub fn member_ids(&self) -> Vec<MemberId> {
        self.members.read()
            .active_members()
            .map(|m| m.id)
            .collect()
    }
    
    pub fn is_member_active(&self, member_id: &MemberId) -> bool {
        self.members.read()
            .get_member(member_id)
            .map(|m| m.state == MemberState::Active)
            .unwrap_or(false)
    }
    
    fn create_group_info(&self) -> Result<GroupInfo> {
        Ok(GroupInfo {
            group_id: self.group_id,
            epoch: self.current_epoch(),
            tree_hash: {
                let tree = self.tree.read();
                tree.compute_tree_hash()?
            }, // Lock released after getting hash
            confirmed_transcript_hash: vec![0; 32], // Simplified
            group_extensions: vec![],
            confirmation_tag: vec![0; 32], // Simplified
            signer: self.creator.id,
        })
    }
    
    fn create_application_aad(&self) -> Result<Vec<u8>> {
        let mut aad = Vec::new();
        aad.extend_from_slice(&self.group_id.0);
        aad.extend_from_slice(&self.current_epoch().to_be_bytes());
        aad.extend_from_slice(&self.message_sequence.load(Ordering::SeqCst).to_be_bytes());
        Ok(aad)
    }
}

// The rest of the file (TreeKemState, GroupState, etc.) remains the same
// but follows the same principle: never hold locks across await points
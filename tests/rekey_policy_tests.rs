// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rekey policy tests per SPEC-PROD §3 and SPEC-2 §3
//!
//! Both specifications require:
//! - Rekey on membership change (already implemented)
//! - Rekey at least every 24 hours OR 10,000 messages (whichever comes first)

use saorsa_mls::{GroupConfig, MemberId, MemberIdentity, MlsGroup};
use std::time::Duration;

/// Test that group config has rekey policy fields
#[test]
fn test_group_config_has_rekey_policy() {
    let config = GroupConfig::default();

    // Should have max_epoch_age (default 24 hours)
    let max_age = config.max_epoch_age();
    assert_eq!(
        max_age,
        Duration::from_secs(24 * 3600),
        "Default max epoch age should be 24 hours"
    );

    // Should have max_messages_per_epoch (default 10,000)
    let max_messages = config.max_messages_per_epoch();
    assert_eq!(
        max_messages, 10_000,
        "Default max messages per epoch should be 10,000"
    );
}

/// Test that rekey policy can be customized
#[test]
fn test_custom_rekey_policy() {
    let config = GroupConfig::default()
        .with_max_epoch_age(Duration::from_secs(3600)) // 1 hour
        .with_max_messages_per_epoch(5000);

    assert_eq!(config.max_epoch_age(), Duration::from_secs(3600));
    assert_eq!(config.max_messages_per_epoch(), 5000);
}

/// Test that group tracks epoch start time
#[tokio::test]
async fn test_group_tracks_epoch_start_time() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let epoch_age = group.epoch_age();
    assert!(
        epoch_age < Duration::from_secs(1),
        "Epoch age should be < 1 second for new group"
    );
}

/// Test that group tracks message count
#[tokio::test]
async fn test_group_tracks_message_count() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let count = group.epoch_message_count();
    assert_eq!(count, 0, "New group should have 0 messages in epoch");
}

/// Test that needs_rekey() returns false for new group
#[tokio::test]
async fn test_new_group_does_not_need_rekey() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    assert!(!group.needs_rekey(), "New group should not need rekey");
}

/// Test that needs_rekey() returns true after time threshold
#[tokio::test]
async fn test_needs_rekey_after_time_threshold() {
    // Set very short epoch age for testing
    let config = GroupConfig::default().with_max_epoch_age(Duration::from_millis(100));

    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    assert!(!group.needs_rekey(), "Should not need rekey immediately");

    // Wait for threshold
    tokio::time::sleep(Duration::from_millis(150)).await;

    assert!(
        group.needs_rekey(),
        "Should need rekey after time threshold"
    );
}

/// Test that needs_rekey() returns true after message count threshold
#[tokio::test]
async fn test_needs_rekey_after_message_threshold() {
    // Set very low message count for testing
    let config = GroupConfig::default().with_max_messages_per_epoch(5);

    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    assert!(!group.needs_rekey(), "Should not need rekey initially");

    // Send messages to increment counter
    for _ in 0..5 {
        let msg = b"test message";
        let _ = group.encrypt_message(msg);
    }

    assert!(
        group.needs_rekey(),
        "Should need rekey after message threshold"
    );
}

/// Test that needs_rekey() uses OR logic (either threshold triggers)
#[tokio::test]
async fn test_needs_rekey_or_logic() {
    let config = GroupConfig::default()
        .with_max_epoch_age(Duration::from_secs(1000)) // Long time
        .with_max_messages_per_epoch(3); // Few messages

    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    // Hit message threshold before time threshold
    for _ in 0..3 {
        let _ = group.encrypt_message(b"test");
    }

    assert!(
        group.needs_rekey(),
        "Should need rekey when message threshold hit (even if time threshold not hit)"
    );
}

/// Test that performing rekey resets counters
#[tokio::test]
async fn test_rekey_resets_counters() {
    let config = GroupConfig::default().with_max_messages_per_epoch(5);

    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    // Send messages
    for _ in 0..5 {
        let _ = group.encrypt_message(b"test");
    }

    assert!(group.needs_rekey(), "Should need rekey");

    // Perform rekey
    group
        .perform_epoch_update()
        .await
        .expect("rekey should succeed");

    assert!(!group.needs_rekey(), "Should not need rekey after rekeying");
    assert_eq!(group.epoch_message_count(), 0, "Message count should reset");
    assert!(
        group.epoch_age() < Duration::from_secs(1),
        "Epoch age should reset"
    );
}

/// Test that membership changes trigger rekey
#[tokio::test]
async fn test_membership_change_triggers_rekey() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("create identity");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    let initial_epoch = group.epoch();

    // Add a member - should trigger epoch change
    let new_member = MemberIdentity::generate(MemberId::generate()).expect("create member");

    group.add_member(&new_member).await.expect("add member");

    let new_epoch = group.epoch();
    assert!(
        new_epoch > initial_epoch,
        "Adding member should advance epoch"
    );
}

/// Test SPEC-2 compliance: 24h OR 10k messages requirement
#[tokio::test]
async fn test_spec2_rekey_requirement_compliance() {
    // SPEC-2 §3: "Rekey on membership change and at least every 24 h or 10k messages"

    let config = GroupConfig::default();

    // Verify defaults match spec
    assert_eq!(
        config.max_epoch_age(),
        Duration::from_secs(24 * 3600),
        "Default max epoch age must be 24 hours per SPEC-2 §3"
    );

    assert_eq!(
        config.max_messages_per_epoch(),
        10_000,
        "Default max messages per epoch must be 10,000 per SPEC-2 §3"
    );
}

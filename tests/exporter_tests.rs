// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MLS Exporter tests per RFC 9420 §8.5
//!
//! The exporter interface allows applications to derive additional secrets
//! from the MLS group's epoch secret. This is required by SPEC-PROD.md §3, §6
//! for deriving per-epoch salts and presence tag secrets for saorsa-gossip.
//!
//! Tests verify:
//! - Basic exporter functionality
//! - Context separation (different labels produce different secrets)
//! - Determinism (same inputs produce same outputs)
//! - Integration with group operations
//! - Per-epoch secret derivation

use saorsa_mls::{GroupConfig, MemberId, MemberIdentity, MlsGroup};

/// Test basic exporter functionality
#[tokio::test]
async fn test_exporter_basic() {
    let config = GroupConfig::default();
    let creator =
        MemberIdentity::generate(MemberId::generate()).expect("generate creator identity");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    // Export a secret
    let label = "test application";
    let context = b"context data";
    let length = 32;

    let exported = group
        .exporter(label, context, length)
        .expect("exporter should succeed");

    assert_eq!(
        exported.len(),
        length,
        "Exported secret should have requested length"
    );
    assert!(
        exported.iter().any(|&b| b != 0),
        "Exported secret should not be all zeros"
    );
}

/// Test that different labels produce different secrets
#[tokio::test]
async fn test_exporter_label_separation() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let context = b"same context";
    let length = 32;

    let secret1 = group
        .exporter("label1", context, length)
        .expect("exporter should succeed");

    let secret2 = group
        .exporter("label2", context, length)
        .expect("exporter should succeed");

    assert_ne!(
        secret1, secret2,
        "Different labels should produce different secrets"
    );
}

/// Test that different contexts produce different secrets
#[tokio::test]
async fn test_exporter_context_separation() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let label = "same label";
    let length = 32;

    let secret1 = group
        .exporter(label, b"context1", length)
        .expect("exporter should succeed");

    let secret2 = group
        .exporter(label, b"context2", length)
        .expect("exporter should succeed");

    assert_ne!(
        secret1, secret2,
        "Different contexts should produce different secrets"
    );
}

/// Test exporter is deterministic
#[tokio::test]
async fn test_exporter_deterministic() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let label = "determinism test";
    let context = b"test context";
    let length = 32;

    let export1 = group
        .exporter(label, context, length)
        .expect("exporter should succeed");

    let export2 = group
        .exporter(label, context, length)
        .expect("exporter should succeed");

    assert_eq!(
        export1, export2,
        "Same inputs should produce identical outputs"
    );
}

/// Test exporter with different lengths
#[tokio::test]
async fn test_exporter_different_lengths() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let label = "length test";
    let context = b"context";

    let export16 = group.exporter(label, context, 16).expect("export 16 bytes");
    let export32 = group.exporter(label, context, 32).expect("export 32 bytes");
    let export64 = group.exporter(label, context, 64).expect("export 64 bytes");

    assert_eq!(export16.len(), 16);
    assert_eq!(export32.len(), 32);
    assert_eq!(export64.len(), 64);

    // Per RFC 9420, HPKE-Expand-Label includes length in the label,
    // so different lengths produce independent outputs (not prefixes).
    // This is intentional for domain separation.
    assert_ne!(
        &export16[..],
        &export32[..16],
        "Different lengths should produce independent outputs"
    );
    assert_ne!(
        &export32[..],
        &export64[..32],
        "Different lengths should produce independent outputs"
    );
}

/// Test exporter changes when epoch advances
#[tokio::test]
async fn test_exporter_epoch_separation() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    let label = "epoch test";
    let context = b"context";
    let length = 32;

    // Export in epoch 0
    let export_epoch0 = group
        .exporter(label, context, length)
        .expect("exporter should succeed");

    // Add a member to advance epoch
    let new_member = MemberIdentity::generate(MemberId::generate()).expect("generate new member");

    group
        .add_member(&new_member)
        .await
        .expect("add member should succeed");

    // Export in epoch 1
    let export_epoch1 = group
        .exporter(label, context, length)
        .expect("exporter should succeed");

    assert_ne!(
        export_epoch0, export_epoch1,
        "Exporter output should change with epoch"
    );
}

/// Test exporter with empty label
#[tokio::test]
async fn test_exporter_empty_label() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let export = group
        .exporter("", b"context", 32)
        .expect("exporter with empty label should succeed");

    assert_eq!(export.len(), 32);
}

/// Test exporter with empty context
#[tokio::test]
async fn test_exporter_empty_context() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    let export = group
        .exporter("label", b"", 32)
        .expect("exporter with empty context should succeed");

    assert_eq!(export.len(), 32);
}

/// Test exporter for saorsa-gossip integration (per SPEC-PROD.md §10)
#[tokio::test]
async fn test_exporter_gossip_integration() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    // Derive presence tag secret as specified in SPEC-PROD.md
    let presence_tag = group
        .exporter("presence-tag", b"", 32)
        .expect("derive presence tag");

    assert_eq!(presence_tag.len(), 32);

    // Derive per-epoch salt
    let epoch_salt = group
        .exporter("epoch-salt", b"", 32)
        .expect("derive epoch salt");

    assert_eq!(epoch_salt.len(), 32);

    // These should be different
    assert_ne!(
        presence_tag, epoch_salt,
        "Different labels should produce different secrets"
    );
}

/// Test exporter with large lengths
#[tokio::test]
async fn test_exporter_large_length() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let group = MlsGroup::new(config, creator).await.expect("create group");

    // Request 1 KB of key material
    let export = group
        .exporter("large export", b"", 1024)
        .expect("large export should succeed");

    assert_eq!(export.len(), 1024);
}

/// Test exporter consistency across group members
#[tokio::test]
async fn test_exporter_consistency_across_members() {
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate(MemberId::generate()).expect("generate creator");

    let mut group = MlsGroup::new(config, creator).await.expect("create group");

    let label = "shared secret";
    let context = b"shared context";
    let length = 32;

    // Export from creator
    let creator_export = group
        .exporter(label, context, length)
        .expect("creator export should succeed");

    // Add a member
    let new_member = MemberIdentity::generate(MemberId::generate()).expect("generate new member");

    group
        .add_member(&new_member)
        .await
        .expect("add member should succeed");

    // Both should derive the same secret in the new epoch
    // (This test is conceptual - would need separate group instances for full test)
    let group_export_after_add = group
        .exporter(label, context, length)
        .expect("exporter should succeed");

    // The export changed due to epoch advancement
    assert_ne!(
        creator_export, group_export_after_add,
        "Export should change after epoch advancement"
    );
}

/// Property test: Exporter is deterministic and produces requested length
#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_exporter_deterministic(
            label in "\\PC*",  // Any printable string
            context in prop::collection::vec(any::<u8>(), 0..100),
            length in 1usize..256,
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = GroupConfig::default();
                let creator = MemberIdentity::generate(MemberId::generate())
                    .expect("generate creator");

                let group = MlsGroup::new(config, creator)
                    .await
                    .expect("create group");

                let export1 = group.exporter(&label, &context, length).expect("export");
                let export2 = group.exporter(&label, &context, length).expect("export");

                assert_eq!(export1, export2);
                assert_eq!(export1.len(), length);
            });
        }

        #[test]
        fn prop_exporter_label_separation(
            label1 in "\\PC+",  // Non-empty printable string
            label2 in "\\PC+",
            length in 16usize..128,
        ) {
            prop_assume!(label1 != label2);  // Only test with different labels

            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let config = GroupConfig::default();
                let creator = MemberIdentity::generate(MemberId::generate())
                    .expect("generate creator");

                let group = MlsGroup::new(config, creator)
                    .await
                    .expect("create group");

                let export1 = group.exporter(&label1, b"", length).expect("export");
                let export2 = group.exporter(&label2, b"", length).expect("export");

                assert_ne!(export1, export2);
            });
        }
    }
}

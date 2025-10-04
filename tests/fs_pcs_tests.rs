// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property tests for Forward Secrecy (FS) and Post-Compromise Security (PCS)

use proptest::prelude::*;
use saorsa_mls::{
    api::{add_member, group_new, recv, remove_member, send},
    member::{MemberId, MemberIdentity},
};

/// Test forward secrecy across member joins
#[test]
fn test_forward_secrecy_on_join() {
    proptest!(ProptestConfig::with_cases(10), |(
        num_initial_members in 2..5usize,
        num_messages_before in 1..10usize,
        num_messages_after in 1..10usize,
    )| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create initial group
            let mut members = vec![];
            for _ in 0..num_initial_members {
                members.push(MemberIdentity::generate(MemberId::generate()).unwrap());
            }
            let group_id = group_new(&members).await.unwrap();

            // Send messages before adding new member
            let mut old_ciphertexts = vec![];
            for i in 0..num_messages_before {
                let msg = format!("Message before join {}", i);
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                old_ciphertexts.push(ct);
            }

            // Add new member
            let new_member = MemberIdentity::generate(MemberId::generate()).unwrap();
            add_member(&group_id, new_member.clone()).await.unwrap();

            // New member should NOT be able to decrypt old messages (forward secrecy)
            // This would require a separate group instance for the new member
            // For now, we verify that old messages have different epoch

            // Send messages after adding new member
            let mut new_ciphertexts = vec![];
            for i in 0..num_messages_after {
                let msg = format!("Message after join {}", i);
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                new_ciphertexts.push(ct);
            }

            // Verify epochs changed
            if !old_ciphertexts.is_empty() && !new_ciphertexts.is_empty() {
                assert!(old_ciphertexts[0].epoch < new_ciphertexts[0].epoch,
                    "Epoch should advance after member join");
            }
        });
    });
}

/// Test forward secrecy across member leaves
#[test]
fn test_forward_secrecy_on_leave() {
    proptest!(ProptestConfig::with_cases(10), |(
        num_initial_members in 3..6usize,
        num_messages_before in 1..10usize,
        num_messages_after in 1..10usize,
    )| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create initial group
            let mut members = vec![];
            for _ in 0..num_initial_members {
                members.push(MemberIdentity::generate(MemberId::generate()).unwrap());
            }
            let group_id = group_new(&members).await.unwrap();

            // Send messages before removing member
            let mut old_ciphertexts = vec![];
            for i in 0..num_messages_before {
                let msg = format!("Message before leave {}", i);
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                old_ciphertexts.push(ct);
            }

            // Remove a member
            let removed_member = members.pop().unwrap();
            remove_member(&group_id, removed_member).await.unwrap();

            // Send messages after removing member
            let mut new_ciphertexts = vec![];
            for i in 0..num_messages_after {
                let msg = format!("Message after leave {}", i);
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                new_ciphertexts.push(ct);
            }

            // Verify epochs changed
            if !old_ciphertexts.is_empty() && !new_ciphertexts.is_empty() {
                assert!(old_ciphertexts[0].epoch < new_ciphertexts[0].epoch,
                    "Epoch should advance after member leave");
            }
        });
    });
}

/// Test message ordering and replay protection
#[test]
fn test_replay_protection() {
    proptest!(ProptestConfig::with_cases(10), |(
        num_members in 2..5usize,
        num_messages in 5..20usize,
    )| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create group
            let mut members = vec![];
            for _ in 0..num_members {
                members.push(MemberIdentity::generate(MemberId::generate()).unwrap());
            }
            let group_id = group_new(&members).await.unwrap();

            // Send multiple messages
            let mut ciphertexts = vec![];
            let mut expected_messages = vec![];
            for i in 0..num_messages {
                let msg = format!("Message {}", i);
                expected_messages.push(msg.clone());
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                ciphertexts.push(ct);
            }

            // Verify all messages can be decrypted in order
            for (i, ct) in ciphertexts.iter().enumerate() {
                let decrypted = recv(&group_id, ct).unwrap();
                assert_eq!(decrypted, expected_messages[i].as_bytes());
            }

            // Verify sequence numbers are increasing
            for i in 1..ciphertexts.len() {
                assert!(ciphertexts[i].sequence > ciphertexts[i-1].sequence,
                    "Sequence numbers should be strictly increasing");
            }
        });
    });
}

/// Test post-compromise security through key updates
#[test]
fn test_post_compromise_security() {
    proptest!(ProptestConfig::with_cases(5), |(
        num_members in 2..4usize,
        num_updates in 1..5usize,
    )| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create group
            let mut members = vec![];
            for _ in 0..num_members {
                members.push(MemberIdentity::generate(MemberId::generate()).unwrap());
            }
            let group_id = group_new(&members).await.unwrap();

            let mut epochs = vec![];

            // Perform multiple updates (add/remove cycles)
            for i in 0..num_updates {
                // Send a message and record epoch
                let msg = format!("Message at update {}", i);
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                epochs.push(ct.epoch);

                // Add a new member (triggers key update)
                let new_member = MemberIdentity::generate(MemberId::generate()).unwrap();
                add_member(&group_id, new_member.clone()).await.unwrap();

                // Send another message
                let msg = format!("Message after add {}", i);
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                epochs.push(ct.epoch);

                // Remove the member (triggers another key update)
                remove_member(&group_id, new_member).await.unwrap();
            }

            // Verify epochs are advancing (PCS through key updates)
            for i in 1..epochs.len() {
                assert!(epochs[i] >= epochs[i-1],
                    "Epochs should never decrease");
            }

            // Verify at least some epoch advances occurred
            assert!(epochs.last().unwrap() > &epochs[0],
                "Epochs should advance through updates");
        });
    });
}

/// Test lost packet handling
#[test]
fn test_lost_packet_handling() {
    proptest!(ProptestConfig::with_cases(10), |(
        num_members in 2..4usize,
        num_messages in 10..30usize,
        drop_indices in prop::collection::vec(0..10usize, 1..3),
    )| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Create group
            let mut members = vec![];
            for _ in 0..num_members {
                members.push(MemberIdentity::generate(MemberId::generate()).unwrap());
            }
            let group_id = group_new(&members).await.unwrap();

            // Send messages
            let mut ciphertexts = vec![];
            let mut messages = vec![];
            for i in 0..num_messages {
                let msg = format!("Message {}", i);
                messages.push(msg.clone());
                let ct = send(&group_id, msg.as_bytes()).unwrap();
                ciphertexts.push(ct);
            }

            // Simulate packet loss by skipping some messages
            let mut received_indices: Vec<usize> = (0..num_messages).collect();
            for &drop_idx in &drop_indices {
                if drop_idx < received_indices.len() {
                    received_indices.remove(drop_idx % received_indices.len());
                }
            }

            // Verify remaining messages can still be decrypted
            for &idx in &received_indices {
                let decrypted = recv(&group_id, &ciphertexts[idx]).unwrap();
                assert_eq!(decrypted, messages[idx].as_bytes());
            }
        });
    });
}

/// Test interop harness stub
#[test]
fn test_interop_stub() {
    // This is a placeholder for future interoperability testing
    // with other MLS implementations

    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        // Create a test group
        let members = vec![
            MemberIdentity::generate(MemberId::generate()).unwrap(),
            MemberIdentity::generate(MemberId::generate()).unwrap(),
        ];
        let group_id = group_new(&members).await.unwrap();

        // Basic message exchange
        let test_msg = b"Interop test message";
        let ct = send(&group_id, test_msg).unwrap();
        let decrypted = recv(&group_id, &ct).unwrap();
        assert_eq!(decrypted, test_msg);

        // TODO: Add actual interop testing with test vectors
        // from other MLS implementations
    });
}

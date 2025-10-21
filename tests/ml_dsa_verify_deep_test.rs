// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deep investigation of ML-DSA signature verification behavior
//!
//! This test file investigates the exact behavior of saorsa-pqc's ML-DSA
//! verify method to understand why signatures were appearing to verify
//! for wrong messages.

use saorsa_pqc::api::{MlDsa, MlDsaVariant};

#[test]
fn test_mldsa_verify_returns_ok_bool() {
    // Create ML-DSA instance
    let ml_dsa = MlDsa::new(MlDsaVariant::MlDsa65);

    // Generate keypair
    let (verifying_key, signing_key) = ml_dsa
        .generate_keypair()
        .expect("keypair generation should succeed");

    // Sign a message
    let message = b"Test message";
    let signature = ml_dsa
        .sign(&signing_key, message)
        .expect("signing should succeed");

    // Test 1: Verify with correct message
    let result_correct = ml_dsa.verify(&verifying_key, message, &signature);

    println!("Verify with correct message: {:?}", result_correct);
    assert!(result_correct.is_ok(), "Verification should not error");

    let is_valid = result_correct.unwrap();
    println!("Is signature valid for correct message? {}", is_valid);
    assert!(is_valid, "Signature should be valid for correct message");

    // Test 2: Verify with WRONG message
    let wrong_message = b"Wrong message";
    let result_wrong = ml_dsa.verify(&verifying_key, wrong_message, &signature);

    println!("Verify with wrong message: {:?}", result_wrong);
    assert!(
        result_wrong.is_ok(),
        "Verification should not error even with wrong message"
    );

    let is_valid_wrong = result_wrong.unwrap();
    println!("Is signature valid for wrong message? {}", is_valid_wrong);
    assert!(
        !is_valid_wrong,
        "Signature should be INVALID for wrong message"
    );

    // Test 3: Generate another keypair and try to verify with wrong key
    let (verifying_key_2, _signing_key_2) = ml_dsa
        .generate_keypair()
        .expect("second keypair generation");

    let result_wrong_key = ml_dsa.verify(&verifying_key_2, message, &signature);

    println!("Verify with wrong key: {:?}", result_wrong_key);
    assert!(
        result_wrong_key.is_ok(),
        "Verification should not error with wrong key"
    );

    let is_valid_wrong_key = result_wrong_key.unwrap();
    println!("Is signature valid with wrong key? {}", is_valid_wrong_key);
    assert!(
        !is_valid_wrong_key,
        "Signature should be INVALID with wrong key"
    );
}

#[test]
fn test_is_ok_vs_unwrap() {
    let ml_dsa = MlDsa::new(MlDsaVariant::MlDsa65);
    let (verifying_key, signing_key) = ml_dsa.generate_keypair().unwrap();

    let message = b"Test";
    let signature = ml_dsa.sign(&signing_key, message).unwrap();

    // Correct way: unwrap the Result to get the bool
    let correct_result = ml_dsa.verify(&verifying_key, message, &signature).unwrap();
    println!("Correct way (unwrap): {}", correct_result);
    assert!(correct_result, "Should be true for valid signature");

    // WRONG way: is_ok() only checks if the Result is Ok, not the bool value
    let wrong_way = ml_dsa.verify(&verifying_key, message, &signature).is_ok();
    println!("Wrong way (is_ok): {}", wrong_way);
    // This will be true even for invalid signatures because the operation succeeded!

    // Demonstrate the bug with wrong message
    let wrong_message = b"Wrong";
    let wrong_msg_result = ml_dsa.verify(&verifying_key, wrong_message, &signature);

    println!("Wrong message - Result: {:?}", wrong_msg_result);

    // Clone to test both ways
    let wrong_msg_result_clone = wrong_msg_result.clone();

    println!("Wrong message - .is_ok(): {}", wrong_msg_result.is_ok()); // TRUE (bug!)
    println!(
        "Wrong message - .unwrap(): {}",
        wrong_msg_result_clone.unwrap()
    ); // FALSE (correct!)

    // The bug: is_ok() returns true because the operation succeeded (no error occurred)
    // But this doesn't mean the signature is valid!
    assert!(
        ml_dsa
            .verify(&verifying_key, wrong_message, &signature)
            .is_ok(),
        "Operation succeeded (no error) - THIS IS THE BUG!"
    );

    // The correct check: unwrap() gives us the bool value (false for invalid signature)
    assert!(
        !ml_dsa
            .verify(&verifying_key, wrong_message, &signature)
            .unwrap(),
        "Signature is invalid for wrong message"
    );
}

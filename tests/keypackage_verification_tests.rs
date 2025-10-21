// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! KeyPackage verification tests for both ML-DSA and SLH-DSA signatures
//!
//! Tests proper signature verification for KeyPackage using TDD approach.

use saorsa_mls::{
    member::{Credential, KeyPackage},
    CipherSuite, CipherSuiteId, KeyPair, MemberId,
};

/// Test ML-DSA KeyPackage verification (should already work)
#[test]
fn test_ml_dsa_keypackage_verification_valid() {
    let suite =
        CipherSuite::from_id(CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65)
            .expect("ML-DSA suite exists");

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(MemberId::generate(), None, &keypair, suite)
        .expect("create credential");

    let key_package = KeyPackage::new(keypair, credential).expect("create key package");

    // Should verify successfully
    assert!(
        key_package.verify().expect("verification should not error"),
        "Valid ML-DSA KeyPackage should verify"
    );
}

/// Test SLH-DSA KeyPackage verification - CURRENTLY FAILS (returns true without verification)
#[test]
fn test_slh_dsa_keypackage_verification_valid() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SLH-DSA suite exists");

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(MemberId::generate(), None, &keypair, suite)
        .expect("create credential");

    let key_package = KeyPackage::new(keypair, credential).expect("create key package");

    // Should actually verify the signature, not just return true
    assert!(
        key_package.verify().expect("verification should not error"),
        "Valid SLH-DSA KeyPackage should verify"
    );
}

/// Test that tampered SLH-DSA signature fails verification
#[test]
fn test_slh_dsa_keypackage_verification_tampered_signature() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SLH-DSA suite exists");

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(MemberId::generate(), None, &keypair, suite)
        .expect("create credential");

    let mut key_package = KeyPackage::new(keypair, credential).expect("create key package");

    // Tamper with the signature by modifying its bytes
    let tampered_sig = {
        let sig_bytes = key_package.signature.0.to_bytes();
        let mut tampered = sig_bytes.clone();
        // Flip some bits in the signature
        if let Some(byte) = tampered.get_mut(0) {
            *byte = byte.wrapping_add(1);
        }

        use saorsa_mls::crypto::Signature;
        use saorsa_pqc::api::{SlhDsaSignature, SlhDsaVariant};

        let slh_sig = SlhDsaSignature::from_bytes(SlhDsaVariant::Sha2_128f, &tampered)
            .expect("tampered bytes should parse");

        saorsa_mls::crypto::DebugSignature(Signature::SlhDsa(slh_sig))
    };

    key_package.signature = tampered_sig;

    // Tampered signature should fail verification
    let result = key_package.verify().expect("verification should not error");
    assert!(
        !result,
        "Tampered SLH-DSA signature should fail verification"
    );
}

/// Test that tampered data fails SLH-DSA verification
#[test]
fn test_slh_dsa_keypackage_verification_tampered_data() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SLH-DSA suite exists");

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(MemberId::generate(), None, &keypair, suite)
        .expect("create credential");

    let mut key_package = KeyPackage::new(keypair, credential).expect("create key package");

    // Tamper with the agreement key (part of signed data)
    key_package.agreement_key.push(0xFF);

    // Tampered data should fail verification
    let result = key_package.verify().expect("verification should not error");
    assert!(
        !result,
        "KeyPackage with tampered data should fail verification"
    );
}

/// Test ML-DSA KeyPackage with tampered data
#[test]
fn test_ml_dsa_keypackage_verification_tampered_data() {
    let suite =
        CipherSuite::from_id(CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65)
            .expect("ML-DSA suite exists");

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(MemberId::generate(), None, &keypair, suite)
        .expect("create credential");

    let mut key_package = KeyPackage::new(keypair, credential).expect("create key package");

    // Tamper with the verifying key
    if let Some(byte) = key_package.verifying_key.get_mut(0) {
        *byte = byte.wrapping_add(1);
    }

    // Should fail verification
    let result = key_package.verify().expect("verification should not error");
    assert!(
        !result,
        "ML-DSA KeyPackage with tampered data should fail verification"
    );
}

/// Test that credential verification works with unified signature
#[test]
fn test_credential_verification_with_slh_dsa() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SLH-DSA suite exists");

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(MemberId::generate(), None, &keypair, suite)
        .expect("create credential");

    // Verify credential against keypair
    assert!(
        credential.verify(&keypair),
        "Valid SLH-DSA credential should verify against its keypair"
    );
}

/// Test that wrong keypair fails credential verification
#[test]
fn test_credential_verification_wrong_keypair() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SLH-DSA suite exists");

    let keypair1 = KeyPair::generate(suite);
    let keypair2 = KeyPair::generate(suite);

    let credential = Credential::new_basic(MemberId::generate(), None, &keypair1, suite)
        .expect("create credential");

    // Verify with wrong keypair should fail
    assert!(
        !credential.verify(&keypair2),
        "Credential should not verify with wrong keypair"
    );
}

/// Test signature type safety - can't verify ML-DSA sig with SLH-DSA key
#[test]
fn test_signature_type_safety() {
    // This test verifies that our type system prevents signature confusion
    // The Signature enum ensures we can't accidentally verify wrong signature type

    let ml_dsa_suite =
        CipherSuite::from_id(CipherSuiteId::SPEC2_MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65)
            .expect("ML-DSA suite exists");

    let slh_dsa_suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192,
    )
    .expect("SLH-DSA suite exists");

    let ml_dsa_keypair = KeyPair::generate(ml_dsa_suite);
    let slh_dsa_keypair = KeyPair::generate(slh_dsa_suite);

    let message = b"test message";

    // Sign with ML-DSA
    let ml_dsa_sig = ml_dsa_keypair.sign(message).expect("sign with ML-DSA");

    // Try to verify with SLH-DSA keypair - should return false (type mismatch)
    assert!(
        !slh_dsa_keypair.verify(message, &ml_dsa_sig),
        "ML-DSA signature should not verify with SLH-DSA keypair"
    );

    // Sign with SLH-DSA
    let slh_dsa_sig = slh_dsa_keypair.sign(message).expect("sign with SLH-DSA");

    // Try to verify with ML-DSA keypair - should return false (type mismatch)
    assert!(
        !ml_dsa_keypair.verify(message, &slh_dsa_sig),
        "SLH-DSA signature should not verify with ML-DSA keypair"
    );
}

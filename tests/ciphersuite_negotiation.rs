use saorsa_mls::{
    CipherSuite, CipherSuiteId, GroupConfig, MemberId, MemberIdentity, MlsAead, MlsGroup, MlsHash,
    MlsKem, MlsSignature,
};

#[test]
fn default_suite_matches_spec_transitional_profile() {
    let suite = CipherSuite::default();
    assert_eq!(
        suite.id(),
        CipherSuiteId::MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65
    );
    assert_eq!(suite.kem(), MlsKem::MlKem768);
    assert_eq!(suite.signature(), MlsSignature::MlDsa65);
    assert_eq!(suite.aead(), MlsAead::ChaCha20Poly1305);
    assert_eq!(suite.hash(), MlsHash::Sha256);
}

#[test]
fn high_security_suite_is_registered() {
    let suite = CipherSuite::from_id(CipherSuiteId::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87)
        .expect("suite must be registered");
    assert_eq!(suite.kem(), MlsKem::MlKem1024);
    assert_eq!(suite.signature(), MlsSignature::MlDsa87);
    assert_eq!(suite.aead(), MlsAead::Aes256Gcm);
    assert_eq!(suite.hash(), MlsHash::Sha512);
}

#[tokio::test]
async fn mls_group_uses_requested_suite() {
    let cipher_suite_id = CipherSuiteId::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87;
    let config = GroupConfig::default().with_cipher_suite(cipher_suite_id);
    let suite = CipherSuite::from_id(cipher_suite_id).expect("suite must exist");

    let creator = MemberIdentity::generate_with_suite(MemberId::generate(), suite)
        .expect("identity generation should succeed");

    let group = MlsGroup::new(config.clone(), creator)
        .await
        .expect("group creation must succeed");

    assert_eq!(group.cipher_suite().id(), cipher_suite_id);
}

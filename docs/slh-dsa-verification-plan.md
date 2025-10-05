# SLH-DSA KeyPackage Verification - Implementation Plan

## Current State Analysis

### What Works ✅
- **KeyPair.verify()** - Already properly handles both ML-DSA and SLH-DSA signatures
  ```rust
  pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
      match (&self.signature_key, signature) {
          (SignatureKey::MlDsa { public, .. }, Signature::MlDsa(sig)) => {
              let ml_dsa = MlDsa::new(self.suite.ml_dsa_variant());
              ml_dsa.verify(public, message, sig).unwrap_or(false)
          }
          (SignatureKey::SlhDsa { public, .. }, Signature::SlhDsa(sig)) => {
              let slh_dsa = SlhDsa::new(self.suite.slh_dsa_variant());
              slh_dsa.verify(public, message, sig).unwrap_or(false)
          }
          _ => false,
      }
  }
  ```

### What's Broken ❌
- **KeyPackage.verify()** - Returns `true` for SLH-DSA without actual verification
  ```rust
  crate::crypto::Signature::SlhDsa(_sig) => {
      // TODO: Implement proper SLH-DSA verification
      Ok(true)  // ⚠️ SECURITY RISK - No verification!
  }
  ```

### Root Cause
The issue is in `KeyPackage.verify()` which currently:
1. Calls `verify_signature(&tbs, sig)` for ML-DSA (works)
2. Returns `true` for SLH-DSA without verification (broken)

The `verify_signature()` method only accepts `MlDsaSignature`, so it can't be used for SLH-DSA.

## Proposed Solution

### Option 1: Unified verify_signature() Method (Recommended ✅)

**Approach:** Refactor `KeyPackage.verify_signature()` to accept our unified `Signature` enum.

```rust
impl KeyPackage {
    /// Verify a signature against this key package's public key
    pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> Result<bool> {
        match signature {
            Signature::MlDsa(sig) => {
                use saorsa_pqc::api::{MlDsa, MlDsaPublicKey};

                let ml_dsa = MlDsa::new(self.cipher_suite.ml_dsa_variant());
                let public_key = MlDsaPublicKey::from_bytes(
                    self.cipher_suite.ml_dsa_variant(),
                    &self.verifying_key
                ).map_err(|e| MlsError::CryptoError(format!("Invalid ML-DSA public key: {e:?}")))?;

                ml_dsa.verify(&public_key, data, sig)
                    .map_err(|e| MlsError::CryptoError(format!("ML-DSA verification failed: {e:?}")))
            }
            Signature::SlhDsa(sig) => {
                use saorsa_pqc::api::{SlhDsa, SlhDsaPublicKey};

                let slh_dsa = SlhDsa::new(self.cipher_suite.slh_dsa_variant());
                let public_key = SlhDsaPublicKey::from_bytes(
                    self.cipher_suite.slh_dsa_variant(),
                    &self.verifying_key
                ).map_err(|e| MlsError::CryptoError(format!("Invalid SLH-DSA public key: {e:?}")))?;

                slh_dsa.verify(&public_key, data, sig)
                    .map_err(|e| MlsError::CryptoError(format!("SLH-DSA verification failed: {e:?}")))
            }
        }
    }

    /// Verify the key package is self-consistent
    pub fn verify(&self) -> Result<bool> {
        let tbs = self.to_be_signed()?;
        self.verify_signature(&tbs, &self.signature.0)
    }
}
```

**Advantages:**
- ✅ Single unified method handles both signature types
- ✅ Proper error handling with Result type
- ✅ Follows existing pattern from KeyPair.verify()
- ✅ Type-safe - can't mix signature types
- ✅ Clean and maintainable

**Migration Impact:**
- Need to update callers that use the old `verify_signature(&[u8], &MlDsaSignature)` signature
- Only 2 known callers: `MemberIdentity.verify_signature()` and tests

### Option 2: Separate Methods (Not Recommended ❌)

Keep separate methods:
- `verify_ml_dsa_signature()`
- `verify_slh_dsa_signature()`

**Why Not:**
- ❌ Code duplication
- ❌ Fragmented API surface
- ❌ Harder to maintain
- ❌ Doesn't align with unified Signature enum

### Option 3: Delegate to KeyPair (Complex ⚠️)

Have KeyPackage reconstruct a KeyPair and use its verify() method.

**Why Not:**
- ❌ Requires reconstructing secret keys (not available)
- ❌ Inefficient
- ❌ Architectural violation

## Implementation Plan

### Phase 1: Refactor verify_signature() ✅
1. Update `KeyPackage.verify_signature()` to accept `&Signature` instead of `&MlDsaSignature`
2. Implement SLH-DSA verification branch
3. Update `KeyPackage.verify()` to use new signature

### Phase 2: Update Callers 🔧
1. Update `MemberIdentity.verify_signature()`:
   ```rust
   pub fn verify_signature(&self, data: &[u8], signature: &Signature) -> bool {
       self.key_package.verify_signature(data, signature).unwrap_or(false)
   }
   ```

2. Find and update any test code using `verify_signature()`

### Phase 3: Add Tests ✅
```rust
#[test]
fn test_keypackage_slh_dsa_verification() {
    let suite = CipherSuite::from_id(
        CipherSuiteId::SPEC2_MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192
    ).unwrap();

    let keypair = KeyPair::generate(suite);
    let credential = Credential::new_basic(
        MemberId::generate(),
        None,
        &keypair,
        suite
    ).unwrap();

    let key_package = KeyPackage::new(keypair.clone(), credential).unwrap();

    // Should verify successfully
    assert!(key_package.verify().unwrap());

    // Test with tampered data
    let mut bad_package = key_package.clone();
    bad_package.agreement_key.push(0xFF); // Tamper
    assert!(!bad_package.verify().unwrap());
}
```

### Phase 4: Security Audit 🔒
- [ ] Verify signature type matching (can't verify ML-DSA sig with SLH-DSA key)
- [ ] Ensure proper error propagation
- [ ] Check for timing side channels
- [ ] Validate against FIPS 205 requirements

## Security Considerations

### Critical Points 🚨
1. **Type Safety**: The match on `Signature` enum ensures we can't accidentally verify ML-DSA signature with SLH-DSA key
2. **Error Handling**: Use `Result` type to propagate verification failures properly
3. **Key Format**: Ensure `from_bytes()` validates key format before verification
4. **Timing**: Both ML-DSA and SLH-DSA should have constant-time verification

### Threat Model
- ❌ **Signature Forgery**: Attacker can't create valid signature without secret key
- ❌ **Key Confusion**: Type system prevents using wrong key type
- ❌ **Downgrade Attack**: Cipher suite is bound in signed data
- ✅ **Implementation Bugs**: Proper testing will catch verification logic errors

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_dsa_keypackage_verification() { /* ... */ }

    #[test]
    fn test_slh_dsa_keypackage_verification() { /* ... */ }

    #[test]
    fn test_signature_type_mismatch() {
        // Try to verify ML-DSA sig with SLH-DSA key - should fail
    }

    #[test]
    fn test_tampered_signature() {
        // Modify signature bytes - should fail verification
    }

    #[test]
    fn test_tampered_data() {
        // Modify signed data - should fail verification
    }
}
```

### Integration Tests
- Test KeyPackage verification in full MLS group operations
- Test with both ML-DSA and SLH-DSA suites
- Test credential verification flow

## Timeline Estimate

- **Phase 1 (Refactor)**: 1-2 hours
- **Phase 2 (Update callers)**: 1 hour
- **Phase 3 (Tests)**: 2 hours
- **Phase 4 (Security audit)**: 1 hour

**Total**: ~5-6 hours

## Dependencies

### Required from saorsa-pqc
- ✅ `SlhDsa::new(variant)` - Available
- ✅ `SlhDsa::verify(public_key, data, signature)` - Available
- ✅ `SlhDsaPublicKey::from_bytes(variant, bytes)` - Available
- ✅ `SlhDsaVariant::Sha2_128f` - Available (using this instead of 192s)

All required APIs are available in saorsa-pqc v0.3.14.

## Migration Notes

### Breaking Changes
- `KeyPackage.verify_signature()` signature changes from `(&[u8], &MlDsaSignature)` to `(&[u8], &Signature)`
- `MemberIdentity.verify_signature()` signature changes similarly

### Backward Compatibility
The unified `Signature` enum already supports ML-DSA, so existing ML-DSA code continues to work after migration.

## Recommendation

**Implement Option 1** (Unified verify_signature method) because:
1. ✅ Architecturally clean - mirrors KeyPair.verify()
2. ✅ Type-safe - leverages Signature enum
3. ✅ Maintainable - single code path
4. ✅ Secure - proper error handling
5. ✅ Tested - easy to write comprehensive tests

The implementation is straightforward and follows established patterns in the codebase.

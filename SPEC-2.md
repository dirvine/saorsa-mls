# Saorsa MLS — PQC Ciphersuite SPEC (PQC‑only)

Version: 0.2  
Status: Draft for implementation  
Scope: Use MLS with PQ KEM and signatures from `saorsa-pqc`. **No classical and no hybrid suites.**

---

## 1. Objectives

- KEM: **ML‑KEM** (Kyber) for HPKE within MLS.  
- Signatures: **ML‑DSA** (Dilithium). Optionally **SLH‑DSA**.  
- Exporter used by presence and private Saorsa Sites.

---

## 2. Ciphersuite registry (private IDs)

```
0x0B01: MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65
0x0B02: MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87
0x0B03: MLS_192_MLKEM1024_CHACHA20POLY1305_SHA384_SLHDSA192   // optional SLH-DSA suite
```

All suites use **ChaCha20-Poly1305** AEAD and are **PQC‑only**. No hybrid. No classical. No AES-GCM.

---

## 3. Protocol use

- Semantics follow MLS. TreeKEM unchanged.  
- Rekey on membership change and at least every 24 h or 10k messages.  
- Use exporter for presence beacons and private Saorsa Sites encryption keys.

---

## 4. Identity and credentials

- Credentials carry **ML‑DSA** public keys; optionally SLH‑DSA.  
- Credential chains and group credentials are PQC‑signed.

---

## 5. HPKE details

- HPKE KEM is **ML‑KEM**.  
- KDF and AEAD per RFC 9180 interface.  
- No DHKEM; no hybrid combiner.

---

## 6. APIs

```rust
pub enum MlsKem { MlKem768, MlKem1024 }
pub enum MlsSig { MlDsa65, MlDsa87, SlhDsa192 }

pub struct CipherSuite { pub kem: MlsKem, pub sig: MlsSig, pub aead: Aead, pub hash: Hash }

pub fn new_group_with_suite(s: CipherSuite) -> Result<Group, Error>;
pub fn exporter(label: &str, context: &[u8], len: usize) -> Vec<u8>;
```

---

## 7. Defaults

- `MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65` (0x0B01) as default.
- `MLS_256_MLKEM1024_CHACHA20POLY1305_SHA512_MLDSA87` (0x0B02) for high‑security rooms.

---

## 8. Downgrade and policy

- Pin suite at group creation.  
- Reject any non‑PQC suite.  
- Log ciphersuite negotiation for audit.

---

## 9. Test vectors and validation

- Verify ML‑KEM and ML‑DSA against `saorsa-pqc` KATs.  
- Publish MLS transcripts (join/add/remove) for each suite.

---

## 10. Dependencies

- `saorsa-pqc` for ML‑KEM/ML‑DSA (and SLH‑DSA if enabled).  
- Consumed by `saorsa-gossip` for presence and by Saorsa Sites for private content.

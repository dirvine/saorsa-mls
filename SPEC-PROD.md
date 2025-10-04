Saorsa MLS — PQC Ciphersuite SPEC

Version: 0.1
Status: Draft
Scope: Use MLS with PQ KEM and signatures from saorsa-pqc, plus optional hybrid modes.

1. Objectives
	•	KEM: ML-KEM for HPKE within MLS.
	•	Signatures: ML-DSA. SLH-DSA optional.
	•	Optional hybrids for transition.

2. Ciphersuite registry

Private ids until IANA assignment:
0x0A01: MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65
0x0A02: MLS_128_HYBRID_X25519+MLKEM768_AES128GCM_SHA256_MLDSA65
0x0A03: MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87
0x0A04: MLS_128_MLKEM768_CHACHA20POLY1305_SHA256_MLDSA65
	•	Hybrids combine DHKEM(X25519) with ML-KEM via a KEM combiner.
	•	AEAD and hash per RFC 9180 interfaces.

3. Protocol use
	•	Semantics follow MLS RFC 9420. TreeKEM unchanged.
	•	Use exporter for per-epoch salts and presence tag derivations.
	•	Rekey on membership change and at least every 24 h or 10k messages.

4. Identity and credentials
	•	Default credential carries ML-DSA public key.
	•	Optional dual-stack credential includes a classical key for hybrid interop.
	•	Chain may be ML-DSA or SLH-DSA signed.

5. HPKE details
	•	Implement HPKE with ML-KEM KEM ids and hybrid ids as per current drafts.
	•	For hybrids, derive secrets with the KEM combiner before KDF.

6. APIs
pub enum MlsKem { MlKem512, MlKem768, MlKem1024, HybridX25519MlKem768 }
pub enum MlsSig { MlDsa44, MlDsa65, MlDsa87, SlhDsa128, SlhDsa192, SlhDsa256 }

pub struct CipherSuite { pub kem: MlsKem, pub sig: MlsSig, pub aead: Aead, pub hash: Hash }

pub fn new_group_with_suite(s: CipherSuite) -> Result<Group, Error>;
pub fn exporter(label: &str, context: &[u8], len: usize) -> Vec<u8>;
7. Defaults
	•	MLS_128_MLKEM768_AES128GCM_SHA256_MLDSA65 as default.
	•	MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 for high-security rooms.

8. Downgrade and policy
	•	Pin ciphersuite at group creation.
	•	Reject non-PQC suites unless hybrid interop is enabled.
	•	Log negotiation artefacts.

9. Test vectors and validation
	•	Verify ML-KEM and ML-DSA against FIPS 203 and 204 known-answer tests.
	•	Publish MLS transcripts using these suites.

10. Dependencies
	•	saorsa-pqc for ML-KEM and ML-DSA.
	•	QUIC transport via ant-quic.
	•	Consumes exporter secrets for presence in saorsa-gossip.

11. References
	•	RFC 9420 MLS.
	•	RFC 9180 HPKE.
	•	FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA.
	•	Drafts for HPKE PQ and hybrid KEMs.

# Saorsa MLS

[![Crates.io](https://img.shields.io/crates/v/saorsa-mls.svg)](https://crates.io/crates/saorsa-mls)
[![Documentation](https://docs.rs/saorsa-mls/badge.svg)](https://docs.rs/saorsa-mls)
[![CI](https://github.com/dirvine/saorsa-mls-foundation/workflows/CI/badge.svg)](https://github.com/dirvine/saorsa-mls-foundation/actions)

Experimental Message Layer Security (MLS)-inspired library for P2P secure group communication.

## Status and scope

This crate is an early-stage, experimental exploration of MLS-like group messaging. It is not a production-ready implementation of RFC 9420, and it is not wire compatible with the IETF MLS ecosystem.

Do not use this crate to protect sensitive data in production systems.

## Features (current)

- **MLS-inspired design**: draws from RFC 9420 concepts (not compliant)
- **Group Management**: Create, join, and manage secure group communication
- **Forward Secrecy**: Cryptographic forward secrecy for all group messages
- **Tree-Based Key Exchange**: Efficient key management using TreeKEM
- **Asynchronous Architecture**: Built on Tokio for high-performance async operations
- **Memory Safe**: Written in Rust with zero-copy optimizations where possible

## Architecture (high-level)

The MLS implementation provides secure group messaging with the following components:

### Core Components

- **Group Management**: Creation and membership management of secure groups
- **Key Derivation**: HKDF-based key derivation for forward secrecy
- **Message Encryption**: ChaCha20Poly1305 AEAD encryption for group messages
- **Signature Verification**: Ed25519 signatures for authentication
- **TreeKEM**: Efficient group key agreement protocol

### Security features (current)

- **Forward Secrecy**: Keys are constantly rotated to ensure past messages remain secure
- **Post-Compromise Security**: Recovery from member key compromise
- **Authentication**: Strong cryptographic authentication of all group members
- **Integrity**: Message integrity protection with authenticated encryption

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-mls = "0.1.0"
```

### Basic example

```rust
use saorsa_mls::{MlsGroup, MemberIdentity, GroupConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a new group
    let config = GroupConfig::default();
    let creator = MemberIdentity::generate();
    let mut group = MlsGroup::new(config, creator).await?;

    // Add members to the group
    let member1 = MemberIdentity::generate();
    let member2 = MemberIdentity::generate();

    group.add_member(&member1).await?;
    group.add_member(&member2).await?;

    // Send a message to the group
    let plaintext = b"Hello, experimental MLS!";
    let encrypted = group.encrypt_message(plaintext).await?;

    // Decrypt the message
    let decrypted = group.decrypt_message(&encrypted).await?;
    assert_eq!(plaintext, &decrypted[..]);

    Ok(())
}
```

### Advanced notes

- The only available ciphersuite today is `CipherSuite::Ed25519ChaCha20Poly1305Blake3`.
- Epoch changes can be triggered with `group.update_epoch().await?;`.
- The wire format uses `bincode` serialization and is not stable across versions.

## Protocol details (work-in-progress)

### Ciphersuite

Currently:
- `Ed25519 + X25519 (intended) + ChaCha20-Poly1305 + BLAKE3`

### Key derivation

- **HKDF-SHA256**: KDF for deriving per-epoch secrets.
- **X25519**: Intended for ECDH key agreement (implementation is currently simplified; see Security section).
- **Ed25519**: Used for signing.

### Message Format

All MLS messages follow RFC 9420 format:
- **Application Messages**: Encrypted group content
- **Proposal Messages**: Group membership changes
- **Commit Messages**: Finalize pending proposals

## Performance

The implementation is optimized for:
- **Low Latency**: Minimal cryptographic overhead
- **High Throughput**: Efficient batch operations
- **Memory Efficiency**: Zero-copy operations where possible
- **Async Operations**: Non-blocking I/O for network operations

## Security considerations

This crate is not yet production-ready. Important limitations include:
- Key agreement and TreeKEM are simplified; shared secret derivation is not equivalent to X25519 ECDH.
- Signatures and credential handling are simplified in places; some signatures are placeholders in tests/examples.
- Nonce uniqueness relies on randomness; there is no reuse detection.
- Secrets are stored in memory as `Vec<u8>` without zeroization at drop.
- Serialization uses `bincode` without strict length limits or versioning.

Until these are addressed, treat this crate as a prototype for experimentation only.

## Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks (optional):

```bash
cargo bench
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## License

This project is dual-licensed under:
- GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
- Commercial License

For AGPL-3.0 license details, see [LICENSE-AGPL-3.0](LICENSE-AGPL-3.0).
For commercial licensing, contact: saorsalabs@gmail.com

## Security

For security issues, please contact: saorsalabs@gmail.com

Do not report security vulnerabilities through public GitHub issues.
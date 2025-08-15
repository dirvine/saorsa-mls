# Saorsa MLS

[![Crates.io](https://img.shields.io/crates/v/saorsa-mls.svg)](https://crates.io/crates/saorsa-mls)
[![Documentation](https://docs.rs/saorsa-mls/badge.svg)](https://docs.rs/saorsa-mls)
[![CI](https://github.com/dirvine/saorsa-mls-foundation/workflows/CI/badge.svg)](https://github.com/dirvine/saorsa-mls-foundation/actions)

Message Layer Security (MLS) protocol implementation for P2P secure group communication.

## Features

- **MLS Protocol Implementation**: RFC 9420 compliant implementation
- **Group Management**: Create, join, and manage secure group communication
- **Forward Secrecy**: Cryptographic forward secrecy for all group messages
- **Tree-Based Key Exchange**: Efficient key management using TreeKEM
- **Asynchronous Architecture**: Built on Tokio for high-performance async operations
- **Memory Safe**: Written in Rust with zero-copy optimizations where possible

## Architecture

The MLS implementation provides secure group messaging with the following components:

### Core Components

- **Group Management**: Creation and membership management of secure groups
- **Key Derivation**: HKDF-based key derivation for forward secrecy
- **Message Encryption**: ChaCha20Poly1305 AEAD encryption for group messages
- **Signature Verification**: Ed25519 signatures for authentication
- **TreeKEM**: Efficient group key agreement protocol

### Security Features

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

### Basic Example

```rust
use saorsa_mls::{Group, Member, MlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new group
    let config = MlsConfig::default();
    let creator = Member::new("creator".to_string()).await?;
    let mut group = Group::new(creator, config).await?;

    // Add members to the group
    let member1 = Member::new("member1".to_string()).await?;
    let member2 = Member::new("member2".to_string()).await?;
    
    group.add_member(member1).await?;
    group.add_member(member2).await?;

    // Send a secure message to the group
    let message = b"Hello, secure group!";
    let encrypted = group.encrypt_message(message).await?;
    
    // All group members can decrypt the message
    let decrypted = group.decrypt_message(&encrypted).await?;
    assert_eq!(message, &decrypted[..]);

    Ok(())
}
```

### Advanced Usage

```rust
use saorsa_mls::{Group, Member, MlsConfig, CiphersuiteName};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create group with custom configuration
    let config = MlsConfig::builder()
        .ciphersuite(CiphersuiteName::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        .max_group_size(100)
        .key_rotation_interval(Duration::from_secs(3600))
        .build();

    let creator = Member::new("creator".to_string()).await?;
    let mut group = Group::new(creator, config).await?;

    // Handle group operations
    group.on_member_added(|member_id| {
        println!("Member {} joined the group", member_id);
    });

    group.on_member_removed(|member_id| {
        println!("Member {} left the group", member_id);
    });

    // Periodic key rotation for forward secrecy
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            if let Err(e) = group.rotate_keys().await {
                eprintln!("Key rotation failed: {}", e);
            }
        }
    });

    Ok(())
}
```

## Protocol Details

### Ciphersuites

Supported MLS ciphersuites:
- `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519` (default)
- Additional ciphersuites available for different security requirements

### Key Derivation

- **HKDF-SHA256**: Key derivation function for all cryptographic operations
- **X25519**: Elliptic curve Diffie-Hellman for key agreement
- **Ed25519**: Digital signatures for authentication

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

## Security Considerations

- **Forward Secrecy**: Automatic key rotation ensures past message security
- **Post-Compromise Security**: Recovery mechanisms for compromised members
- **Side-Channel Resistance**: Constant-time cryptographic operations
- **Memory Safety**: Rust's memory safety prevents common vulnerabilities

## Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks:

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
# Saorsa MLS Project Overview

## Purpose
An experimental Message Layer Security (MLS)-inspired library for P2P secure group communication, implementing forward secrecy and post-compromise security.

## Tech Stack
- **Language**: Rust (edition 2024)
- **Async Runtime**: Tokio
- **Current Crypto**: Ed25519, X25519, ChaCha20Poly1305, BLAKE3
- **Target Crypto**: saorsa-pqc library (ML-KEM, ML-DSA, SLH-DSA)

## Project Structure
```
saorsa-mls/
├── src/
│   ├── lib.rs          # Library exports and documentation
│   ├── crypto.rs       # Cryptographic primitives (to be migrated)
│   ├── group.rs        # Group management and messaging
│   ├── member.rs       # Member identity and credentials
│   └── protocol.rs     # Protocol message definitions
├── Cargo.toml          # Dependencies
└── README.md           # Documentation
```

## Key Components
- **CipherSuite**: Defines cryptographic algorithms used
- **KeyPair**: Manages signing and key agreement keys
- **AeadCipher**: Handles authenticated encryption
- **MemberIdentity**: Member credentials and key packages
- **Group**: Manages group state and secure messaging
# SwiftSSH

A modular, educational SSH-2 implementation in Rust.

## Architecture

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│    Client     │────▶│   Transport   │────▶│    Crypto    │
│  (CLI/TUI)   │     │ (TCP + Packet)│     │ (AES/HMAC)   │
└──────────────┘     └──────┬────────┘     └──────────────┘
                            │
                 ┌──────────┼──────────┐
                 ▼          ▼          ▼
           ┌──────────┐ ┌────────┐ ┌────────┐
           │   Auth   │ │  Conn  │ │  SFTP  │
           │ (pw/key) │ │ (chan) │ │ (file) │
           └──────────┘ └────────┘ └────────┘
```

## Modules

| Module | Description | RFC |
|--------|-------------|-----|
| `packet` | SSH-2 binary packet serialization/deserialization, wire types | RFC 4253 §6 |
| `transport` | Version exchange, key exchange (Curve25519), encrypted packet I/O | RFC 4253 |
| `crypto` | AES-256-CTR encryption, HMAC-SHA256, session key derivation | RFC 4253 §7.2 |
| `auth` | Password and public-key authentication | RFC 4252 |
| `connection` | Multiplexed SSH channels, exec/shell/pty requests | RFC 4254 |
| `sftp` | SFTP file transfer subsystem (open, read, write, mkdir, etc.) | draft-ietf-secsh-filexfer |
| `session` | Per-connection state, sequence numbers, key management | — |
| `error` | Unified error types | — |

## Building

```bash
cargo build
```

## Running

### Start the server

```bash
# Listens on 0.0.0.0:2222 by default
# Default users: admin/admin, user/password
cargo run --bin swiftssh-server

# With debug logging
RUST_LOG=debug cargo run --bin swiftssh-server
```

### Connect with the client

```bash
# Execute a remote command
cargo run --bin swiftssh-client -- --user admin --password admin --command "ls -la"

# Interactive shell
cargo run --bin swiftssh-client -- --user admin --password admin --interactive

# Custom host/port
cargo run --bin swiftssh-client -- --host 192.168.1.100 --port 2222 --user admin --password admin -c "whoami"
```

## Testing

```bash
# Run all 24 unit tests
cargo test

# Run tests for a specific module
cargo test packet::
cargo test crypto::
cargo test auth::
cargo test connection::
cargo test sftp::
cargo test transport::
```

## Project Structure

```
src/
├── lib.rs              # Library root — re-exports all modules
├── bin/
│   ├── client.rs       # CLI client binary
│   └── server.rs       # Server binary
├── packet/
│   ├── mod.rs          # Module exports
│   ├── codec.rs        # Packet serialize/deserialize, SshBuf wire helpers
│   └── types.rs        # Message types, constants, disconnect codes
├── transport/
│   ├── mod.rs
│   ├── io.rs           # Async packet send/recv, version string exchange
│   └── kex.rs          # Curve25519 key exchange (client + server sides)
├── crypto/
│   └── mod.rs          # AES-256-CTR, HMAC-SHA256, key derivation
├── auth/
│   └── mod.rs          # Password/publickey auth, user database
├── connection/
│   └── mod.rs          # Channel manager, channel packets, exec/shell/pty
├── sftp/
│   └── mod.rs          # SFTP protocol, file handler with chroot protection
├── session/
│   └── mod.rs          # Session state, key storage, sequence numbers
└── error/
    └── mod.rs          # SshError enum, SshResult type alias
```

## Protocol Flow

```
Client                          Server
  │                               │
  │──── Version String ──────────▶│  SSH-2.0-SwiftSSH_0.1
  │◀──── Version String ──────────│
  │                               │
  │──── SSH_MSG_KEXINIT ─────────▶│  Algorithm negotiation
  │◀──── SSH_MSG_KEXINIT ─────────│
  │                               │
  │──── KEX_ECDH_INIT ──────────▶│  Client ephemeral pubkey
  │◀──── KEX_ECDH_REPLY ─────────│  Server pubkey + signature
  │                               │
  │──── SSH_MSG_NEWKEYS ─────────▶│  Switch to encrypted mode
  │◀──── SSH_MSG_NEWKEYS ─────────│
  │                               │
  │═══ Encrypted from here ═══════│
  │                               │
  │──── SERVICE_REQUEST ─────────▶│  "ssh-userauth"
  │◀──── SERVICE_ACCEPT ──────────│
  │                               │
  │──── USERAUTH_REQUEST ────────▶│  password / publickey
  │◀──── USERAUTH_SUCCESS ────────│
  │                               │
  │──── CHANNEL_OPEN ────────────▶│  "session"
  │◀──── CHANNEL_OPEN_CONFIRM ────│
  │                               │
  │──── CHANNEL_REQUEST ─────────▶│  "exec" / "shell" / "subsystem"
  │◀──── CHANNEL_DATA ────────────│  Command output
  │◀──── CHANNEL_EOF ─────────────│
  │◀──── CHANNEL_CLOSE ───────────│
  │──── DISCONNECT ──────────────▶│
```

## Features

- **Fully async** — Built on Tokio with non-blocking I/O
- **Encrypted** — AES-256-CTR encryption with HMAC-SHA256 integrity after key exchange
- **Curve25519 key exchange** — Modern elliptic-curve Diffie-Hellman
- **Password & public key auth** — Pluggable user database
- **Channel multiplexing** — Multiple concurrent sessions per connection
- **SFTP subsystem** — File read/write/list/mkdir/rm with chroot isolation
- **Remote command execution** — Run commands and stream output back
- **Educational** — Clear module boundaries following RFC structure

## Tech Stack

- **Language:** Rust (2021 edition)
- **Async Runtime:** Tokio
- **Cryptography:** RustCrypto (aes, hmac, sha2, x25519-dalek)
- **CLI:** clap + crossterm
- **Logging:** tracing + tracing-subscriber
- **Error Handling:** thiserror + anyhow

## License

MIT

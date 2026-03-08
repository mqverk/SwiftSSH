# SwiftSSH

SwiftSSH is a modular, educational SSH-2 implementation written in Rust. It provides a lightweight, readable reference implementation of core SSH concepts: the transport layer (version exchange, key exchange, encryption/MAC), user authentication, multiplexed channels for remote command execution, and an SFTP subsystem.

This project is intended for learning, experimentation, and extension — not for production use.

---

## Key Goals

- Education: clear module separation and RFC-aligned code paths.
- Completeness: client and server binaries, SFTP support, and unit tests.
- Modern crypto: Curve25519 key exchange, AES-256-CTR, HMAC-SHA256.
- Async-first: built on Tokio for non-blocking networking.

---

## Features

- Fully async transport layer with version and key exchange (RFC 4253).
- Curve25519 (X25519) ephemeral key exchange and SHA-256 exchange hash.
- AES-256-CTR encryption and HMAC-SHA256 integrity for packet traffic.
- Password and public-key authentication (RFC 4252) with a simple server-side user database.
- Multiplexed SSH channels (RFC 4254): exec, shell, pty-req, subsystem (SFTP) support.
- SFTP subsystem (subset) with open/read/write/readdir/stat/mkdir/rmdir/remove and chroot-style path protection.
- Clear packet codec and wire-type helpers for learning packet formats.
- Unit tests for packet handling, crypto helpers, kex, auth parsing, channels, and SFTP.

---

## Project layout

See `src/` for the full code. High-level modules:

- `packet/` — packet codec (serialize/deserialize) and wire helpers (`SshBuf`).
- `transport/` — version exchange, KEX, async packet I/O.
- `crypto/` — AES CTR, HMAC, RFC-style key derivation helpers.
- `auth/` — parsing/auth helpers and a simple `UserDatabase` for the server.
- `connection/` — channel management, windowing, channel packet builders/parsers.
- `sftp/` — SFTP packet helpers and a server-side handler for file ops.
- `session/` — per-connection key and sequence-state storage.
- `error/` — shared `SshError` and `SshResult` types.
- `src/bin/` — two binaries: `swiftssh-server` and `swiftssh-client`.

---

## Quickstart

Prerequisites

- Rust toolchain (stable) and `cargo`.

Build

```bash
cargo build --release
```

Run the server (defaults)

```bash
# Default: listen on 0.0.0.0:2222
cargo run --bin swiftssh-server --release
```

Default server notes

- Default SFTP root: `/tmp/swiftssh` (server will create it if missing).
- Default users (for the example server): `admin`/`admin` and `user`/`password`.

Run the client (example)

```bash
# Execute a remote command
cargo run --bin swiftssh-client -- --user admin --password admin --command "whoami"

# Interactive shell mode
cargo run --bin swiftssh-client -- --user admin --password admin --interactive
```

---

## SFTP

The SFTP subsystem runs over an SSH channel using a simplified v3 implementation. Basic operations supported include `open`, `read`, `write`, `readdir`, `stat`, `mkdir`, `rmdir`, and `remove`. The server enforces a path restriction rooted at the configured SFTP root to avoid traversal outside the allowed tree.

---

## Testing

Run unit tests:

```bash
cargo test
```

The repository includes tests for packet serialization round-trips, kex, crypto helpers, auth parsing, channel lifecycle, and SFTP behaviors.

---

## Security & Limitations

This code is educational and deliberately simplified in places:

- Host key handling and signature verification are simplified placeholders — do _not_ rely on them for production-level host authenticity.
- There is no built-in key storage, agent integration, or secure secrets management.
- Performance and hardened edge-cases are not fully implemented.

Do not expose this server to untrusted networks without auditing and upgrading cryptographic checks and host-key handling.

---

## Development notes

- Format: `cargo fmt` (if formatting is desired, add `rustfmt`).
- Linting: `cargo clippy`.
- Tests: `cargo test`.

If you plan to extend the project, focus on isolating cryptographic primitives from protocol logic and add thorough tests for any new code paths.

---

## Contributing

Contributions are welcome. Open an issue to discuss design changes, then submit a PR with tests and a clear commit message.

---

## License

MIT

---

If you want, I can also:

- Add a short `docs/` folder with RFC references and diagrams.
- Create CI workflows (GitHub Actions) to run `cargo test` and `cargo fmt` on push/PR.
- Add a minimal `examples/` directory with automated server/client run scripts.

Tell me which of the above you'd like next.

//! # SwiftSSH
//!
//! A modular, educational SSH-2 implementation in Rust.
//!
//! ## Modules
//!
//! - [`packet`] — SSH-2 binary packet serialization/deserialization (RFC 4253 §6)
//! - [`transport`] — Transport layer: version exchange, key exchange, packet I/O
//! - [`crypto`] — AES-256-CTR encryption, HMAC-SHA256, session key derivation
//! - [`auth`] — User authentication: password and public key (RFC 4252)
//! - [`connection`] — Multiplexed SSH channels (RFC 4254)
//! - [`sftp`] — SFTP file transfer subsystem
//! - [`session`] — Per-connection session state and key management
//! - [`error`] — Unified error types
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────┐     ┌───────────┐     ┌──────────────┐
//! │  Client   │────▶│ Transport │────▶│   Crypto     │
//! │  (CLI)    │     │ (TCP+Pkt) │     │ (AES/HMAC)   │
//! └──────────┘     └─────┬─────┘     └──────────────┘
//!                        │
//!              ┌─────────┼─────────┐
//!              ▼         ▼         ▼
//!        ┌─────────┐ ┌──────┐ ┌──────┐
//!        │  Auth   │ │ Conn │ │ SFTP │
//!        │(pw/key) │ │(chan) │ │(file)│
//!        └─────────┘ └──────┘ └──────┘
//! ```

pub mod auth;
pub mod connection;
pub mod crypto;
pub mod error;
pub mod packet;
pub mod session;
pub mod sftp;
pub mod transport;

/// SSH-2 key exchange using Curve25519 (similar to curve25519-sha256).
///
/// Per RFC 8731 / draft-ietf-curdle-ssh-curves:
/// 1. Client generates ephemeral X25519 keypair, sends public key in SSH_MSG_KEX_ECDH_INIT
/// 2. Server generates ephemeral X25519 keypair, computes shared secret
/// 3. Server signs exchange hash with host key, sends reply in SSH_MSG_KEX_ECDH_REPLY
/// 4. Both sides derive session keys from shared secret + exchange hash
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::error::{SshError, SshResult};
use crate::packet::SshBuf;

/// Supported key exchange algorithms.
pub const KEX_ALGORITHMS: &[&str] = &["curve25519-sha256"];

/// Supported host key algorithms.
pub const HOST_KEY_ALGORITHMS: &[&str] = &["ssh-ed25519", "rsa-sha2-256"];

/// Supported encryption algorithms.
pub const ENCRYPTION_ALGORITHMS: &[&str] = &["aes256-ctr", "aes128-ctr"];

/// Supported MAC algorithms.
pub const MAC_ALGORITHMS: &[&str] = &["hmac-sha2-256"];

/// Supported compression algorithms.
pub const COMPRESSION_ALGORITHMS: &[&str] = &["none"];

/// Result of Diffie-Hellman key exchange on one side.
pub struct KexResult {
    /// The shared secret K (raw bytes, not yet mpint-encoded).
    pub shared_secret: Vec<u8>,
    /// The exchange hash H = SHA-256(...).
    pub exchange_hash: Vec<u8>,
}

/// Client-side key exchange state.
pub struct KexClient {
    secret: Option<EphemeralSecret>,
    pub client_ephemeral_pub: [u8; 32],
}

impl KexClient {
    /// Generate an ephemeral keypair for key exchange.
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            client_ephemeral_pub: *public.as_bytes(),
        }
    }

    /// Complete key exchange given the server's ephemeral public key and exchange hash inputs.
    ///
    /// Computes the shared secret and exchange hash.
    pub fn complete(
        &mut self,
        server_ephemeral_pub: &[u8; 32],
        client_version: &str,
        server_version: &str,
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        server_host_key_blob: &[u8],
    ) -> SshResult<KexResult> {
        let secret = self
            .secret
            .take()
            .ok_or_else(|| SshError::KeyExchange("Key exchange already completed".into()))?;

        let server_pub = PublicKey::from(*server_ephemeral_pub);
        let shared_secret = secret.diffie_hellman(&server_pub);
        let shared_bytes = shared_secret.as_bytes().to_vec();

        let exchange_hash = compute_exchange_hash(
            client_version,
            server_version,
            client_kexinit,
            server_kexinit,
            server_host_key_blob,
            &self.client_ephemeral_pub,
            server_ephemeral_pub,
            &shared_bytes,
        );

        Ok(KexResult {
            shared_secret: shared_bytes,
            exchange_hash,
        })
    }
}

/// Server-side key exchange state.
pub struct KexServer {
    secret: Option<EphemeralSecret>,
    pub server_ephemeral_pub: [u8; 32],
}

impl KexServer {
    pub fn new() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self {
            secret: Some(secret),
            server_ephemeral_pub: *public.as_bytes(),
        }
    }

    /// Complete key exchange given the client's ephemeral public key.
    pub fn complete(
        &mut self,
        client_ephemeral_pub: &[u8; 32],
        client_version: &str,
        server_version: &str,
        client_kexinit: &[u8],
        server_kexinit: &[u8],
        server_host_key_blob: &[u8],
    ) -> SshResult<KexResult> {
        let secret = self
            .secret
            .take()
            .ok_or_else(|| SshError::KeyExchange("Key exchange already completed".into()))?;

        let client_pub = PublicKey::from(*client_ephemeral_pub);
        let shared_secret = secret.diffie_hellman(&client_pub);
        let shared_bytes = shared_secret.as_bytes().to_vec();

        let exchange_hash = compute_exchange_hash(
            client_version,
            server_version,
            client_kexinit,
            server_kexinit,
            server_host_key_blob,
            client_ephemeral_pub,
            &self.server_ephemeral_pub,
            &shared_bytes,
        );

        Ok(KexResult {
            shared_secret: shared_bytes,
            exchange_hash,
        })
    }
}

/// Compute the exchange hash H per RFC 4253 §8 / RFC 8731:
///
/// ```text
/// H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
/// ```
///
/// Where:
/// - V_C, V_S = client/server version strings (as SSH strings)
/// - I_C, I_S = client/server SSH_MSG_KEXINIT payloads (as SSH strings)
/// - K_S = server host key blob (as SSH string)
/// - e = client ephemeral public key (as SSH string)
/// - f = server ephemeral public key (as SSH string)
/// - K = shared secret (as mpint)
fn compute_exchange_hash(
    client_version: &str,
    server_version: &str,
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    server_host_key_blob: &[u8],
    client_ephemeral_pub: &[u8; 32],
    server_ephemeral_pub: &[u8; 32],
    shared_secret: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1024);

    SshBuf::write_utf8(&mut buf, client_version);
    SshBuf::write_utf8(&mut buf, server_version);
    SshBuf::write_string(&mut buf, client_kexinit);
    SshBuf::write_string(&mut buf, server_kexinit);
    SshBuf::write_string(&mut buf, server_host_key_blob);
    SshBuf::write_string(&mut buf, client_ephemeral_pub);
    SshBuf::write_string(&mut buf, server_ephemeral_pub);
    SshBuf::write_mpint(&mut buf, shared_secret);

    let hash = Sha256::digest(&buf);
    hash.to_vec()
}

/// Build an SSH_MSG_KEXINIT payload (RFC 4253 §7.1).
pub fn build_kexinit_payload() -> Vec<u8> {
    let mut payload = Vec::new();

    // 16 bytes cookie (random)
    let mut cookie = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut cookie);
    payload.extend_from_slice(&cookie);

    // Algorithm lists
    SshBuf::write_name_list(&mut payload, KEX_ALGORITHMS);
    SshBuf::write_name_list(&mut payload, HOST_KEY_ALGORITHMS);
    SshBuf::write_name_list(&mut payload, ENCRYPTION_ALGORITHMS); // client->server
    SshBuf::write_name_list(&mut payload, ENCRYPTION_ALGORITHMS); // server->client
    SshBuf::write_name_list(&mut payload, MAC_ALGORITHMS); // client->server
    SshBuf::write_name_list(&mut payload, MAC_ALGORITHMS); // server->client
    SshBuf::write_name_list(&mut payload, COMPRESSION_ALGORITHMS); // client->server
    SshBuf::write_name_list(&mut payload, COMPRESSION_ALGORITHMS); // server->client
    SshBuf::write_name_list(&mut payload, &[]); // languages client->server
    SshBuf::write_name_list(&mut payload, &[]); // languages server->client
    SshBuf::write_bool(&mut payload, false); // first_kex_packet_follows
    SshBuf::write_u32(&mut payload, 0); // reserved

    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kex_exchange() {
        let mut client = KexClient::new();
        let mut server = KexServer::new();

        let client_version = "SSH-2.0-SwiftSSH_client";
        let server_version = "SSH-2.0-SwiftSSH_server";
        let client_kexinit = build_kexinit_payload();
        let server_kexinit = build_kexinit_payload();
        let host_key_blob = b"fake-host-key";

        let client_pub = client.client_ephemeral_pub;
        let server_pub = server.server_ephemeral_pub;

        let server_result = server
            .complete(
                &client_pub,
                client_version,
                server_version,
                &client_kexinit,
                &server_kexinit,
                host_key_blob,
            )
            .unwrap();

        let client_result = client
            .complete(
                &server_pub,
                client_version,
                server_version,
                &client_kexinit,
                &server_kexinit,
                host_key_blob,
            )
            .unwrap();

        assert_eq!(client_result.shared_secret, server_result.shared_secret);
        assert_eq!(client_result.exchange_hash, server_result.exchange_hash);
    }

    #[test]
    fn test_kexinit_payload_not_empty() {
        let payload = build_kexinit_payload();
        assert!(payload.len() > 16); // at least the cookie
    }
}

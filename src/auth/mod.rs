/// SSH-2 User Authentication (RFC 4252).
///
/// Supports:
/// - Password authentication
/// - Public key authentication (signature verification)
use std::collections::HashMap;
use std::io::Cursor;

use crate::error::{SshError, SshResult};
use crate::packet::{MessageType, SshBuf, SshPacket};

/// Represents a user credential for authentication.
#[derive(Debug, Clone)]
pub enum Credential {
    Password(String),
    PublicKey {
        algorithm: String,
        key_blob: Vec<u8>,
        signature: Option<Vec<u8>>,
    },
}

/// Server-side user database (for the educational server).
#[derive(Debug, Clone)]
pub struct UserDatabase {
    /// username -> password
    passwords: HashMap<String, String>,
    /// username -> list of authorized public key blobs
    public_keys: HashMap<String, Vec<Vec<u8>>>,
}

impl UserDatabase {
    pub fn new() -> Self {
        Self {
            passwords: HashMap::new(),
            public_keys: HashMap::new(),
        }
    }

    /// Add a user with password authentication.
    pub fn add_password_user(&mut self, username: &str, password: &str) {
        self.passwords
            .insert(username.to_string(), password.to_string());
    }

    /// Add an authorized public key for a user.
    pub fn add_public_key(&mut self, username: &str, key_blob: Vec<u8>) {
        self.public_keys
            .entry(username.to_string())
            .or_default()
            .push(key_blob);
    }

    /// Verify password for a user.
    pub fn verify_password(&self, username: &str, password: &str) -> bool {
        self.passwords
            .get(username)
            .map(|p| p == password)
            .unwrap_or(false)
    }

    /// Check if a public key is authorized for a user.
    pub fn is_key_authorized(&self, username: &str, key_blob: &[u8]) -> bool {
        self.public_keys
            .get(username)
            .map(|keys| keys.iter().any(|k| k == key_blob))
            .unwrap_or(false)
    }
}

impl Default for UserDatabase {
    fn default() -> Self {
        Self::new()
    }
}

/// Build an SSH_MSG_USERAUTH_REQUEST for password authentication.
pub fn build_password_auth_request(
    username: &str,
    service: &str,
    password: &str,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_utf8(&mut payload, username);
    SshBuf::write_utf8(&mut payload, service);
    SshBuf::write_utf8(&mut payload, "password");
    SshBuf::write_bool(&mut payload, false); // no new password
    SshBuf::write_utf8(&mut payload, password);

    SshPacket::new(MessageType::UserAuthRequest, payload)
}

/// Build an SSH_MSG_USERAUTH_REQUEST for public key authentication.
pub fn build_pubkey_auth_request(
    username: &str,
    service: &str,
    algorithm: &str,
    key_blob: &[u8],
    signature: Option<&[u8]>,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_utf8(&mut payload, username);
    SshBuf::write_utf8(&mut payload, service);
    SshBuf::write_utf8(&mut payload, "publickey");
    SshBuf::write_bool(&mut payload, signature.is_some());
    SshBuf::write_utf8(&mut payload, algorithm);
    SshBuf::write_string(&mut payload, key_blob);

    if let Some(sig) = signature {
        SshBuf::write_string(&mut payload, sig);
    }

    SshPacket::new(MessageType::UserAuthRequest, payload)
}

/// Build an SSH_MSG_USERAUTH_FAILURE response.
pub fn build_auth_failure(methods: &[&str], partial_success: bool) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_name_list(&mut payload, methods);
    SshBuf::write_bool(&mut payload, partial_success);

    SshPacket::new(MessageType::UserAuthFailure, payload)
}

/// Build an SSH_MSG_USERAUTH_SUCCESS response.
pub fn build_auth_success() -> SshPacket {
    SshPacket::new(MessageType::UserAuthSuccess, Vec::new())
}

/// Build an SSH_MSG_SERVICE_REQUEST.
pub fn build_service_request(service_name: &str) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_utf8(&mut payload, service_name);
    SshPacket::new(MessageType::ServiceRequest, payload)
}

/// Build an SSH_MSG_SERVICE_ACCEPT.
pub fn build_service_accept(service_name: &str) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_utf8(&mut payload, service_name);
    SshPacket::new(MessageType::ServiceAccept, payload)
}

/// Parse an SSH_MSG_USERAUTH_REQUEST payload.
pub struct AuthRequest {
    pub username: String,
    pub service: String,
    pub method: String,
    pub credential: Credential,
}

impl AuthRequest {
    pub fn parse(payload: &[u8]) -> SshResult<Self> {
        let mut cursor = Cursor::new(payload);
        let username = SshBuf::read_utf8(&mut cursor)?;
        let service = SshBuf::read_utf8(&mut cursor)?;
        let method = SshBuf::read_utf8(&mut cursor)?;

        let credential = match method.as_str() {
            "password" => {
                let _change = SshBuf::read_bool(&mut cursor)?;
                let password = SshBuf::read_utf8(&mut cursor)?;
                Credential::Password(password)
            }
            "publickey" => {
                let has_sig = SshBuf::read_bool(&mut cursor)?;
                let algorithm = SshBuf::read_utf8(&mut cursor)?;
                let key_blob = SshBuf::read_string(&mut cursor)?;
                let signature = if has_sig {
                    Some(SshBuf::read_string(&mut cursor)?)
                } else {
                    None
                };
                Credential::PublicKey {
                    algorithm,
                    key_blob,
                    signature,
                }
            }
            other => {
                return Err(SshError::AuthFailed(format!(
                    "Unsupported auth method: {}",
                    other
                )));
            }
        };

        Ok(Self {
            username,
            service,
            method,
            credential,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_database() {
        let mut db = UserDatabase::new();
        db.add_password_user("alice", "secret123");
        db.add_public_key("bob", vec![1, 2, 3, 4]);

        assert!(db.verify_password("alice", "secret123"));
        assert!(!db.verify_password("alice", "wrong"));
        assert!(!db.verify_password("nobody", "secret123"));

        assert!(db.is_key_authorized("bob", &[1, 2, 3, 4]));
        assert!(!db.is_key_authorized("bob", &[5, 6, 7, 8]));
        assert!(!db.is_key_authorized("alice", &[1, 2, 3, 4]));
    }

    #[test]
    fn test_password_auth_roundtrip() {
        let pkt = build_password_auth_request("alice", "ssh-connection", "mypass");
        let req = AuthRequest::parse(&pkt.payload).unwrap();
        assert_eq!(req.username, "alice");
        assert_eq!(req.service, "ssh-connection");
        assert_eq!(req.method, "password");
        match req.credential {
            Credential::Password(p) => assert_eq!(p, "mypass"),
            _ => panic!("Expected password credential"),
        }
    }

    #[test]
    fn test_pubkey_auth_roundtrip() {
        let key_blob = vec![10, 20, 30];
        let sig = vec![40, 50, 60];
        let pkt = build_pubkey_auth_request(
            "bob",
            "ssh-connection",
            "ssh-ed25519",
            &key_blob,
            Some(&sig),
        );
        let req = AuthRequest::parse(&pkt.payload).unwrap();
        assert_eq!(req.username, "bob");
        assert_eq!(req.method, "publickey");
        match req.credential {
            Credential::PublicKey {
                algorithm,
                key_blob: kb,
                signature: s,
            } => {
                assert_eq!(algorithm, "ssh-ed25519");
                assert_eq!(kb, key_blob);
                assert_eq!(s, Some(sig));
            }
            _ => panic!("Expected public key credential"),
        }
    }
}

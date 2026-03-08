/// SSH session state tracking.
use crate::crypto::CipherPair;

/// The state of an SSH session through its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Initial TCP connection, exchanging version strings.
    VersionExchange,
    /// Key exchange in progress.
    KeyExchange,
    /// Keys established, waiting for service request.
    Authenticated,
    /// Interactive session active.
    Active,
    /// Disconnecting or disconnected.
    Disconnected,
}

/// Tracks per-session data including keys and sequence numbers.
pub struct SessionKeys {
    /// Sequence number for outgoing packets (wraps at u32::MAX).
    pub send_seq: u32,
    /// Sequence number for incoming packets.
    pub recv_seq: u32,
    /// Session identifier (exchange hash from first key exchange).
    pub session_id: Option<Vec<u8>>,
    /// Current cipher pair (None before key exchange completes).
    pub ciphers: Option<CipherPair>,
    /// HMAC key for outgoing packets.
    pub send_mac_key: Option<Vec<u8>>,
    /// HMAC key for incoming packets.
    pub recv_mac_key: Option<Vec<u8>>,
}

impl SessionKeys {
    pub fn new() -> Self {
        Self {
            send_seq: 0,
            recv_seq: 0,
            session_id: None,
            ciphers: None,
            send_mac_key: None,
            recv_mac_key: None,
        }
    }

    /// Advance send sequence number.
    pub fn next_send_seq(&mut self) -> u32 {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        seq
    }

    /// Advance receive sequence number.
    pub fn next_recv_seq(&mut self) -> u32 {
        let seq = self.recv_seq;
        self.recv_seq = self.recv_seq.wrapping_add(1);
        seq
    }

    /// Returns true if encryption is active.
    pub fn is_encrypted(&self) -> bool {
        self.ciphers.is_some()
    }
}

impl Default for SessionKeys {
    fn default() -> Self {
        Self::new()
    }
}

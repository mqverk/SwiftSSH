use thiserror::Error;

/// Central error type for SwiftSSH operations.
#[derive(Debug, Error)]
pub enum SshError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Key exchange failed: {0}")]
    KeyExchange(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Channel error: {0}")]
    Channel(String),

    #[error("SFTP error: {0}")]
    Sftp(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    #[error("Decryption error: {0}")]
    Decryption(String),

    #[error("MAC verification failed")]
    MacMismatch,

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),

    #[error("Unexpected message type: {0}")]
    UnexpectedMessage(u8),

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Timeout")]
    Timeout,

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
}

pub type SshResult<T> = Result<T, SshError>;

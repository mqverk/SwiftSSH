/// SSH-2 Message type identifiers (RFC 4253, 4252, 4254).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    // Transport layer (RFC 4253)
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,

    // Key exchange (RFC 4253)
    KexInit = 20,
    NewKeys = 21,
    KexEcdhInit = 30,
    KexEcdhReply = 31,

    // User authentication (RFC 4252)
    UserAuthRequest = 50,
    UserAuthFailure = 51,
    UserAuthSuccess = 52,
    UserAuthBanner = 53,

    // Connection protocol (RFC 4254)
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(Self::Disconnect),
            2 => Some(Self::Ignore),
            3 => Some(Self::Unimplemented),
            4 => Some(Self::Debug),
            5 => Some(Self::ServiceRequest),
            6 => Some(Self::ServiceAccept),
            20 => Some(Self::KexInit),
            21 => Some(Self::NewKeys),
            30 => Some(Self::KexEcdhInit),
            31 => Some(Self::KexEcdhReply),
            50 => Some(Self::UserAuthRequest),
            51 => Some(Self::UserAuthFailure),
            52 => Some(Self::UserAuthSuccess),
            53 => Some(Self::UserAuthBanner),
            80 => Some(Self::GlobalRequest),
            81 => Some(Self::RequestSuccess),
            82 => Some(Self::RequestFailure),
            90 => Some(Self::ChannelOpen),
            91 => Some(Self::ChannelOpenConfirmation),
            92 => Some(Self::ChannelOpenFailure),
            93 => Some(Self::ChannelWindowAdjust),
            94 => Some(Self::ChannelData),
            95 => Some(Self::ChannelExtendedData),
            96 => Some(Self::ChannelEof),
            97 => Some(Self::ChannelClose),
            98 => Some(Self::ChannelRequest),
            99 => Some(Self::ChannelSuccess),
            100 => Some(Self::ChannelFailure),
            _ => None,
        }
    }
}

/// SSH-2 disconnect reason codes (RFC 4253 §11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DisconnectReason {
    HostNotAllowed = 1,
    ProtocolError = 2,
    KeyExchangeFailed = 3,
    Reserved = 4,
    MacError = 5,
    CompressionError = 6,
    ServiceNotAvailable = 7,
    ProtocolVersionNotSupported = 8,
    HostKeyNotVerifiable = 9,
    ConnectionLost = 10,
    ByApplication = 11,
    TooManyConnections = 12,
    AuthCancelledByUser = 13,
    NoMoreAuthMethodsAvailable = 14,
    IllegalUserName = 15,
}

/// SSH version identification string.
pub const SSH_VERSION_STRING: &str = "SSH-2.0-SwiftSSH_0.1";

/// Maximum packet size per RFC 4253 §6.1.
pub const MAX_PACKET_SIZE: usize = 35000;

/// Minimum packet size (padding requirements).
pub const MIN_PADDING: usize = 4;

/// Maximum padding.
pub const MAX_PADDING: usize = 255;

/// Block size for AES-256-CTR.
pub const AES_BLOCK_SIZE: usize = 16;

/// HMAC-SHA256 output size.
pub const HMAC_SHA256_SIZE: usize = 32;

/// Default window size for channels.
pub const DEFAULT_WINDOW_SIZE: u32 = 2_097_152; // 2 MiB

/// Default maximum packet size for channels.
pub const DEFAULT_MAX_PACKET_SIZE: u32 = 32768;

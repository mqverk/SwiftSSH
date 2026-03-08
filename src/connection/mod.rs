/// SSH-2 Connection Protocol — Channel multiplexing (RFC 4254).
///
/// Supports:
/// - Opening/closing channels
/// - Sending/receiving data
/// - Channel requests (exec, shell, pty-req)
/// - Window management
use std::collections::HashMap;
use std::io::Cursor;

use crate::error::{SshError, SshResult};
use crate::packet::types::*;
use crate::packet::{SshBuf, SshPacket};

/// Represents a single SSH channel.
#[derive(Debug)]
pub struct Channel {
    pub local_id: u32,
    pub remote_id: u32,
    pub channel_type: String,
    pub local_window: u32,
    pub remote_window: u32,
    pub local_max_packet: u32,
    pub remote_max_packet: u32,
    pub eof_sent: bool,
    pub eof_received: bool,
    pub closed: bool,
    /// Buffer for received data.
    pub recv_buffer: Vec<u8>,
}

impl Channel {
    pub fn new(local_id: u32, channel_type: &str) -> Self {
        Self {
            local_id,
            remote_id: 0,
            channel_type: channel_type.to_string(),
            local_window: DEFAULT_WINDOW_SIZE,
            remote_window: 0,
            local_max_packet: DEFAULT_MAX_PACKET_SIZE,
            remote_max_packet: 0,
            eof_sent: false,
            eof_received: false,
            closed: false,
            recv_buffer: Vec::new(),
        }
    }
}

/// Manages multiple SSH channels for a connection.
pub struct ChannelManager {
    channels: HashMap<u32, Channel>,
    next_id: u32,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
            next_id: 0,
        }
    }

    /// Open a new local channel and return its ID.
    pub fn open_channel(&mut self, channel_type: &str) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        let channel = Channel::new(id, channel_type);
        self.channels.insert(id, channel);
        id
    }

    /// Set remote channel parameters after receiving CHANNEL_OPEN_CONFIRMATION.
    pub fn confirm_channel(
        &mut self,
        local_id: u32,
        remote_id: u32,
        remote_window: u32,
        remote_max_packet: u32,
    ) -> SshResult<()> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or_else(|| SshError::Channel(format!("Unknown channel {}", local_id)))?;
        ch.remote_id = remote_id;
        ch.remote_window = remote_window;
        ch.remote_max_packet = remote_max_packet;
        Ok(())
    }

    /// Register a channel opened by the remote side.
    pub fn accept_channel(
        &mut self,
        remote_id: u32,
        channel_type: &str,
        remote_window: u32,
        remote_max_packet: u32,
    ) -> u32 {
        let local_id = self.next_id;
        self.next_id += 1;
        let mut channel = Channel::new(local_id, channel_type);
        channel.remote_id = remote_id;
        channel.remote_window = remote_window;
        channel.remote_max_packet = remote_max_packet;
        self.channels.insert(local_id, channel);
        local_id
    }

    /// Get a reference to a channel by local ID.
    pub fn get(&self, local_id: u32) -> Option<&Channel> {
        self.channels.get(&local_id)
    }

    /// Get a mutable reference to a channel by local ID.
    pub fn get_mut(&mut self, local_id: u32) -> Option<&mut Channel> {
        self.channels.get_mut(&local_id)
    }

    /// Find a channel by its remote ID.
    pub fn find_by_remote_id(&self, remote_id: u32) -> Option<&Channel> {
        self.channels.values().find(|ch| ch.remote_id == remote_id)
    }

    /// Find a channel by its remote ID (mutable).
    pub fn find_by_remote_id_mut(&mut self, remote_id: u32) -> Option<&mut Channel> {
        self.channels
            .values_mut()
            .find(|ch| ch.remote_id == remote_id)
    }

    /// Remove a channel.
    pub fn remove_channel(&mut self, local_id: u32) -> Option<Channel> {
        self.channels.remove(&local_id)
    }

    /// Push received data into a channel's buffer, consuming window.
    pub fn receive_data(&mut self, local_id: u32, data: &[u8]) -> SshResult<()> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or_else(|| SshError::Channel(format!("Unknown channel {}", local_id)))?;

        if data.len() as u32 > ch.local_window {
            return Err(SshError::Channel("Window overflow".into()));
        }

        ch.local_window -= data.len() as u32;
        ch.recv_buffer.extend_from_slice(data);
        Ok(())
    }

    /// Consume `amount` of window on the remote side (we sent data).
    pub fn consume_remote_window(&mut self, local_id: u32, amount: u32) -> SshResult<()> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or_else(|| SshError::Channel(format!("Unknown channel {}", local_id)))?;

        if amount > ch.remote_window {
            return Err(SshError::Channel("Would exceed remote window".into()));
        }
        ch.remote_window -= amount;
        Ok(())
    }

    /// Adjust (increase) the local window for a channel.
    pub fn adjust_local_window(&mut self, local_id: u32, amount: u32) -> SshResult<()> {
        let ch = self
            .channels
            .get_mut(&local_id)
            .ok_or_else(|| SshError::Channel(format!("Unknown channel {}", local_id)))?;
        ch.local_window = ch.local_window.saturating_add(amount);
        Ok(())
    }

    /// How many active (non-closed) channels exist.
    pub fn active_count(&self) -> usize {
        self.channels.values().filter(|ch| !ch.closed).count()
    }
}

impl Default for ChannelManager {
    fn default() -> Self {
        Self::new()
    }
}

// --- Packet builders ---

/// Build SSH_MSG_CHANNEL_OPEN (RFC 4254 §5.1).
pub fn build_channel_open(
    channel_type: &str,
    sender_channel: u32,
    initial_window: u32,
    max_packet: u32,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_utf8(&mut payload, channel_type);
    SshBuf::write_u32(&mut payload, sender_channel);
    SshBuf::write_u32(&mut payload, initial_window);
    SshBuf::write_u32(&mut payload, max_packet);

    SshPacket::new(MessageType::ChannelOpen, payload)
}

/// Build SSH_MSG_CHANNEL_OPEN_CONFIRMATION.
pub fn build_channel_open_confirmation(
    recipient_channel: u32,
    sender_channel: u32,
    initial_window: u32,
    max_packet: u32,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_u32(&mut payload, sender_channel);
    SshBuf::write_u32(&mut payload, initial_window);
    SshBuf::write_u32(&mut payload, max_packet);

    SshPacket::new(MessageType::ChannelOpenConfirmation, payload)
}

/// Build SSH_MSG_CHANNEL_OPEN_FAILURE.
pub fn build_channel_open_failure(
    recipient_channel: u32,
    reason_code: u32,
    description: &str,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_u32(&mut payload, reason_code);
    SshBuf::write_utf8(&mut payload, description);
    SshBuf::write_utf8(&mut payload, "en"); // language tag

    SshPacket::new(MessageType::ChannelOpenFailure, payload)
}

/// Build SSH_MSG_CHANNEL_DATA.
pub fn build_channel_data(recipient_channel: u32, data: &[u8]) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_string(&mut payload, data);

    SshPacket::new(MessageType::ChannelData, payload)
}

/// Build SSH_MSG_CHANNEL_WINDOW_ADJUST.
pub fn build_window_adjust(recipient_channel: u32, bytes_to_add: u32) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_u32(&mut payload, bytes_to_add);

    SshPacket::new(MessageType::ChannelWindowAdjust, payload)
}

/// Build SSH_MSG_CHANNEL_EOF.
pub fn build_channel_eof(recipient_channel: u32) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);

    SshPacket::new(MessageType::ChannelEof, payload)
}

/// Build SSH_MSG_CHANNEL_CLOSE.
pub fn build_channel_close(recipient_channel: u32) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);

    SshPacket::new(MessageType::ChannelClose, payload)
}

/// Build SSH_MSG_CHANNEL_REQUEST for "exec" (RFC 4254 §6.5).
pub fn build_exec_request(
    recipient_channel: u32,
    command: &str,
    want_reply: bool,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_utf8(&mut payload, "exec");
    SshBuf::write_bool(&mut payload, want_reply);
    SshBuf::write_utf8(&mut payload, command);

    SshPacket::new(MessageType::ChannelRequest, payload)
}

/// Build SSH_MSG_CHANNEL_REQUEST for "shell" (RFC 4254 §6.5).
pub fn build_shell_request(recipient_channel: u32, want_reply: bool) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_utf8(&mut payload, "shell");
    SshBuf::write_bool(&mut payload, want_reply);

    SshPacket::new(MessageType::ChannelRequest, payload)
}

/// Build SSH_MSG_CHANNEL_REQUEST for "pty-req" (RFC 4254 §6.2).
pub fn build_pty_request(
    recipient_channel: u32,
    term: &str,
    width_cols: u32,
    height_rows: u32,
    width_px: u32,
    height_px: u32,
    want_reply: bool,
) -> SshPacket {
    let mut payload = Vec::new();
    SshBuf::write_u32(&mut payload, recipient_channel);
    SshBuf::write_utf8(&mut payload, "pty-req");
    SshBuf::write_bool(&mut payload, want_reply);
    SshBuf::write_utf8(&mut payload, term);
    SshBuf::write_u32(&mut payload, width_cols);
    SshBuf::write_u32(&mut payload, height_rows);
    SshBuf::write_u32(&mut payload, width_px);
    SshBuf::write_u32(&mut payload, height_px);
    // Empty encoded terminal modes
    SshBuf::write_string(&mut payload, &[0]); // TTY_OP_END

    SshPacket::new(MessageType::ChannelRequest, payload)
}

/// Parse a CHANNEL_OPEN packet payload.
pub struct ChannelOpenMsg {
    pub channel_type: String,
    pub sender_channel: u32,
    pub initial_window: u32,
    pub max_packet: u32,
}

impl ChannelOpenMsg {
    pub fn parse(payload: &[u8]) -> SshResult<Self> {
        let mut cursor = Cursor::new(payload);
        let channel_type = SshBuf::read_utf8(&mut cursor)?;
        let sender_channel = SshBuf::read_u32(&mut cursor)?;
        let initial_window = SshBuf::read_u32(&mut cursor)?;
        let max_packet = SshBuf::read_u32(&mut cursor)?;

        Ok(Self {
            channel_type,
            sender_channel,
            initial_window,
            max_packet,
        })
    }
}

/// Parse a CHANNEL_DATA packet payload.
pub struct ChannelDataMsg {
    pub recipient_channel: u32,
    pub data: Vec<u8>,
}

impl ChannelDataMsg {
    pub fn parse(payload: &[u8]) -> SshResult<Self> {
        let mut cursor = Cursor::new(payload);
        let recipient_channel = SshBuf::read_u32(&mut cursor)?;
        let data = SshBuf::read_string(&mut cursor)?;

        Ok(Self {
            recipient_channel,
            data,
        })
    }
}

/// Parse a CHANNEL_REQUEST packet payload.
pub struct ChannelRequestMsg {
    pub recipient_channel: u32,
    pub request_type: String,
    pub want_reply: bool,
    /// The remaining type-specific data.
    pub data: Vec<u8>,
}

impl ChannelRequestMsg {
    pub fn parse(payload: &[u8]) -> SshResult<Self> {
        let mut cursor = Cursor::new(payload);
        let recipient_channel = SshBuf::read_u32(&mut cursor)?;
        let request_type = SshBuf::read_utf8(&mut cursor)?;
        let want_reply = SshBuf::read_bool(&mut cursor)?;

        let pos = cursor.position() as usize;
        let data = payload[pos..].to_vec();

        Ok(Self {
            recipient_channel,
            request_type,
            want_reply,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_manager_lifecycle() {
        let mut mgr = ChannelManager::new();

        let ch_id = mgr.open_channel("session");
        assert_eq!(ch_id, 0);
        assert_eq!(mgr.active_count(), 1);

        mgr.confirm_channel(ch_id, 42, 65536, 32768).unwrap();
        let ch = mgr.get(ch_id).unwrap();
        assert_eq!(ch.remote_id, 42);
        assert_eq!(ch.remote_window, 65536);

        mgr.receive_data(ch_id, &[1, 2, 3]).unwrap();
        assert_eq!(mgr.get(ch_id).unwrap().recv_buffer, vec![1, 2, 3]);

        let removed = mgr.remove_channel(ch_id);
        assert!(removed.is_some());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_channel_open_roundtrip() {
        let pkt = build_channel_open("session", 0, DEFAULT_WINDOW_SIZE, DEFAULT_MAX_PACKET_SIZE);
        let msg = ChannelOpenMsg::parse(&pkt.payload).unwrap();
        assert_eq!(msg.channel_type, "session");
        assert_eq!(msg.sender_channel, 0);
        assert_eq!(msg.initial_window, DEFAULT_WINDOW_SIZE);
    }

    #[test]
    fn test_channel_data_roundtrip() {
        let pkt = build_channel_data(7, b"hello world");
        let msg = ChannelDataMsg::parse(&pkt.payload).unwrap();
        assert_eq!(msg.recipient_channel, 7);
        assert_eq!(msg.data, b"hello world");
    }

    #[test]
    fn test_exec_request_roundtrip() {
        let pkt = build_exec_request(3, "ls -la", true);
        let msg = ChannelRequestMsg::parse(&pkt.payload).unwrap();
        assert_eq!(msg.recipient_channel, 3);
        assert_eq!(msg.request_type, "exec");
        assert!(msg.want_reply);
    }

    #[test]
    fn test_window_overflow_rejected() {
        let mut mgr = ChannelManager::new();
        let ch_id = mgr.open_channel("session");
        // Try to receive more data than the window allows
        let window = mgr.get(ch_id).unwrap().local_window;
        let result = mgr.receive_data(ch_id, &vec![0u8; window as usize + 1]);
        assert!(result.is_err());
    }
}

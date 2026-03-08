/// SSH-2 packet serialization and deserialization (RFC 4253 §6).
///
/// Binary Packet Protocol format:
/// ```text
///   uint32    packet_length     (excluding MAC and itself)
///   byte      padding_length
///   byte[n1]  payload           (n1 = packet_length - padding_length - 1)
///   byte[n2]  random_padding    (n2 = padding_length)
///   byte[m]   mac               (message authentication code)
/// ```
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

use crate::error::{SshError, SshResult};
use crate::packet::types::*;

/// A raw SSH packet before/after encryption.
#[derive(Debug, Clone)]
pub struct SshPacket {
    /// The message type byte (first byte of payload).
    pub msg_type: u8,
    /// The payload bytes (excluding the message type byte).
    pub payload: Vec<u8>,
}

impl SshPacket {
    /// Create a new packet with a given message type and payload.
    pub fn new(msg_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            msg_type: msg_type as u8,
            payload,
        }
    }

    /// Serialize the packet into the SSH binary format (unencrypted).
    /// Returns the full packet bytes including length, padding, but excluding MAC.
    pub fn serialize(&self, block_size: usize) -> SshResult<Vec<u8>> {
        let block_size = block_size.max(8);

        // payload = msg_type byte + payload data
        let payload_len = 1 + self.payload.len();

        // packet_length = padding_length(1) + payload + padding
        // Total must be multiple of block_size (minimum 8).
        // minimum padding is 4 bytes
        let min_packet_len = 1 + payload_len + MIN_PADDING;
        let padding_len = {
            let remainder = min_packet_len % block_size;
            if remainder == 0 {
                MIN_PADDING
            } else {
                MIN_PADDING + (block_size - remainder)
            }
        };
        let packet_length = 1 + payload_len + padding_len;

        if packet_length > MAX_PACKET_SIZE {
            return Err(SshError::InvalidPacket(format!(
                "Packet too large: {} bytes",
                packet_length
            )));
        }

        let mut buf = Vec::with_capacity(4 + packet_length);
        buf.write_u32::<BigEndian>(packet_length as u32)
            .map_err(|e| SshError::Io(e))?;
        buf.write_u8(padding_len as u8)
            .map_err(|e| SshError::Io(e))?;
        buf.write_u8(self.msg_type)
            .map_err(|e| SshError::Io(e))?;
        buf.write_all(&self.payload)
            .map_err(|e| SshError::Io(e))?;

        // Random padding
        let mut padding = vec![0u8; padding_len];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut padding);
        buf.write_all(&padding).map_err(|e| SshError::Io(e))?;

        Ok(buf)
    }

    /// Deserialize an SSH packet from raw (decrypted) bytes.
    /// The input should start with the packet_length field.
    pub fn deserialize(data: &[u8]) -> SshResult<Self> {
        if data.len() < 6 {
            return Err(SshError::InvalidPacket(
                "Packet too short".to_string(),
            ));
        }

        let mut cursor = Cursor::new(data);
        let packet_length = cursor
            .read_u32::<BigEndian>()
            .map_err(|e| SshError::Io(e))? as usize;

        if packet_length > MAX_PACKET_SIZE {
            return Err(SshError::InvalidPacket(format!(
                "Packet length too large: {}",
                packet_length
            )));
        }

        if data.len() < 4 + packet_length {
            return Err(SshError::InvalidPacket(
                "Incomplete packet data".to_string(),
            ));
        }

        let padding_length = cursor.read_u8().map_err(|e| SshError::Io(e))? as usize;

        if padding_length >= packet_length {
            return Err(SshError::InvalidPacket(
                "Invalid padding length".to_string(),
            ));
        }

        let payload_length = packet_length - 1 - padding_length;
        if payload_length == 0 {
            return Err(SshError::InvalidPacket(
                "Empty payload".to_string(),
            ));
        }

        let msg_type = cursor.read_u8().map_err(|e| SshError::Io(e))?;

        let mut payload = vec![0u8; payload_length - 1];
        cursor.read_exact(&mut payload).map_err(|e| SshError::Io(e))?;

        Ok(Self { msg_type, payload })
    }
}

/// Helpers for reading/writing SSH-2 wire types from a byte buffer.
pub struct SshBuf;

impl SshBuf {
    /// Write an SSH string (uint32 length + data).
    pub fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
        buf.write_u32::<BigEndian>(data.len() as u32).unwrap();
        buf.write_all(data).unwrap();
    }

    /// Write a UTF-8 SSH string.
    pub fn write_utf8(buf: &mut Vec<u8>, s: &str) {
        Self::write_string(buf, s.as_bytes());
    }

    /// Write a name-list (comma-separated algorithm names).
    pub fn write_name_list(buf: &mut Vec<u8>, names: &[&str]) {
        let joined = names.join(",");
        Self::write_utf8(buf, &joined);
    }

    /// Write a boolean.
    pub fn write_bool(buf: &mut Vec<u8>, val: bool) {
        buf.push(if val { 1 } else { 0 });
    }

    /// Write a uint32.
    pub fn write_u32(buf: &mut Vec<u8>, val: u32) {
        buf.write_u32::<BigEndian>(val).unwrap();
    }

    /// Write a byte.
    pub fn write_u8(buf: &mut Vec<u8>, val: u8) {
        buf.push(val);
    }

    /// Write an SSH mpint (multi-precision integer).
    pub fn write_mpint(buf: &mut Vec<u8>, val: &[u8]) {
        // Strip leading zeros, but keep one if the high bit is set
        let stripped = match val.iter().position(|&b| b != 0) {
            Some(pos) => &val[pos..],
            None => &[0],
        };
        if stripped[0] & 0x80 != 0 {
            // Prepend a zero byte
            buf.write_u32::<BigEndian>((stripped.len() + 1) as u32).unwrap();
            buf.push(0);
        } else {
            buf.write_u32::<BigEndian>(stripped.len() as u32).unwrap();
        }
        buf.write_all(stripped).unwrap();
    }

    /// Read an SSH string from a cursor. Returns the raw bytes.
    pub fn read_string(cursor: &mut Cursor<&[u8]>) -> SshResult<Vec<u8>> {
        let len = cursor
            .read_u32::<BigEndian>()
            .map_err(|_| SshError::InvalidPacket("Failed to read string length".into()))?
            as usize;
        if len > MAX_PACKET_SIZE {
            return Err(SshError::InvalidPacket("String too long".into()));
        }
        let mut data = vec![0u8; len];
        cursor
            .read_exact(&mut data)
            .map_err(|_| SshError::InvalidPacket("Truncated string".into()))?;
        Ok(data)
    }

    /// Read a UTF-8 SSH string.
    pub fn read_utf8(cursor: &mut Cursor<&[u8]>) -> SshResult<String> {
        let data = Self::read_string(cursor)?;
        String::from_utf8(data)
            .map_err(|_| SshError::InvalidPacket("Invalid UTF-8 string".into()))
    }

    /// Read a name-list.
    pub fn read_name_list(cursor: &mut Cursor<&[u8]>) -> SshResult<Vec<String>> {
        let s = Self::read_utf8(cursor)?;
        if s.is_empty() {
            Ok(Vec::new())
        } else {
            Ok(s.split(',').map(|n| n.to_string()).collect())
        }
    }

    /// Read a boolean.
    pub fn read_bool(cursor: &mut Cursor<&[u8]>) -> SshResult<bool> {
        let b = cursor
            .read_u8()
            .map_err(|_| SshError::InvalidPacket("Failed to read bool".into()))?;
        Ok(b != 0)
    }

    /// Read a uint32.
    pub fn read_u32(cursor: &mut Cursor<&[u8]>) -> SshResult<u32> {
        cursor
            .read_u32::<BigEndian>()
            .map_err(|_| SshError::InvalidPacket("Failed to read u32".into()))
    }

    /// Read an SSH mpint.
    pub fn read_mpint(cursor: &mut Cursor<&[u8]>) -> SshResult<Vec<u8>> {
        Self::read_string(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_roundtrip() {
        let pkt = SshPacket::new(MessageType::Ignore, vec![1, 2, 3, 4]);
        let serialized = pkt.serialize(8).unwrap();
        let deserialized = SshPacket::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.msg_type, MessageType::Ignore as u8);
        assert_eq!(deserialized.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_packet_alignment() {
        // Ensure serialized length is aligned to block size
        let pkt = SshPacket::new(MessageType::Debug, vec![0; 13]);
        let serialized = pkt.serialize(16).unwrap();
        // Excluding the 4-byte length field, the rest should be aligned to 16
        assert_eq!((serialized.len() - 4) % 16, 0);
    }

    #[test]
    fn test_ssh_buf_string_roundtrip() {
        let mut buf = Vec::new();
        SshBuf::write_utf8(&mut buf, "hello-ssh");
        let mut cursor = Cursor::new(buf.as_slice());
        let result = SshBuf::read_utf8(&mut cursor).unwrap();
        assert_eq!(result, "hello-ssh");
    }

    #[test]
    fn test_ssh_buf_name_list() {
        let mut buf = Vec::new();
        SshBuf::write_name_list(&mut buf, &["aes256-ctr", "aes128-ctr"]);
        let mut cursor = Cursor::new(buf.as_slice());
        let result = SshBuf::read_name_list(&mut cursor).unwrap();
        assert_eq!(result, vec!["aes256-ctr", "aes128-ctr"]);
    }

    #[test]
    fn test_ssh_buf_u32() {
        let mut buf = Vec::new();
        SshBuf::write_u32(&mut buf, 42);
        let mut cursor = Cursor::new(buf.as_slice());
        assert_eq!(SshBuf::read_u32(&mut cursor).unwrap(), 42);
    }

    #[test]
    fn test_ssh_buf_mpint() {
        // Positive integer with high bit set — must be zero-padded
        let mut buf = Vec::new();
        SshBuf::write_mpint(&mut buf, &[0x80, 0x01]);
        let mut cursor = Cursor::new(buf.as_slice());
        let result = SshBuf::read_mpint(&mut cursor).unwrap();
        assert_eq!(result, vec![0x00, 0x80, 0x01]);
    }

    #[test]
    fn test_empty_payload_rejected() {
        // Construct a minimal packet with 0 payload length (padding fills all)
        let data = vec![0, 0, 0, 4, 3, 0, 0, 0]; // packet_length=4, padding=3, then 3 pad bytes
        let result = SshPacket::deserialize(&data);
        assert!(result.is_err());
    }
}

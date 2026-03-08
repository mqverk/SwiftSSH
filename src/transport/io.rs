/// Async SSH packet I/O over TCP streams.
///
/// Handles reading/writing SSH packets with optional encryption and MAC.
use byteorder::{BigEndian, WriteBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Write a u32 in big-endian to a Vec<u8> without ambiguity.
fn write_u32_be(buf: &mut Vec<u8>, val: u32) {
    WriteBytesExt::write_u32::<BigEndian>(buf, val).unwrap();
}

use crate::crypto::{compute_hmac, verify_hmac};
use crate::error::{SshError, SshResult};
use crate::packet::types::*;
use crate::packet::SshPacket;
use crate::session::SessionKeys;

/// Send an SSH packet over the stream with optional encryption/MAC.
pub async fn send_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    packet: &SshPacket,
    keys: &mut SessionKeys,
) -> SshResult<()> {
    let block_size = if keys.is_encrypted() {
        AES_BLOCK_SIZE
    } else {
        8
    };

    let mut data = packet.serialize(block_size)?;
    let seq = keys.next_send_seq();

    // Compute MAC before encryption (encrypt-then-MAC is not standard SSH, but
    // standard SSH uses MAC-then-encrypt with sequence number prepended)
    let mac = if let Some(ref mac_key) = keys.send_mac_key {
        let mut mac_data = Vec::new();
        write_u32_be(&mut mac_data, seq);
        mac_data.extend_from_slice(&data);
        Some(compute_hmac(mac_key, &mac_data))
    } else {
        None
    };

    // Encrypt the packet data (not the MAC)
    if let Some(ref mut ciphers) = keys.ciphers {
        ciphers.encrypt.apply(&mut data);
    }

    writer.write_all(&data).await.map_err(SshError::Io)?;

    if let Some(mac) = mac {
        writer.write_all(&mac).await.map_err(SshError::Io)?;
    }

    writer.flush().await.map_err(SshError::Io)?;
    Ok(())
}

/// Receive an SSH packet from the stream with optional decryption/MAC verification.
pub async fn recv_packet<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    keys: &mut SessionKeys,
) -> SshResult<SshPacket> {
    let block_size = if keys.is_encrypted() {
        AES_BLOCK_SIZE
    } else {
        8
    };

    // Read the first block to get the packet length
    let mut first_block = vec![0u8; block_size];
    reader
        .read_exact(&mut first_block)
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                SshError::ConnectionClosed
            } else {
                SshError::Io(e)
            }
        })?;

    // Decrypt the first block to read packet_length
    if let Some(ref mut ciphers) = keys.ciphers {
        ciphers.decrypt.apply(&mut first_block);
    }

    let packet_length =
        u32::from_be_bytes([first_block[0], first_block[1], first_block[2], first_block[3]])
            as usize;

    if packet_length > MAX_PACKET_SIZE {
        return Err(SshError::InvalidPacket(format!(
            "Packet length too large: {}",
            packet_length
        )));
    }

    // Read the remaining bytes (packet_length + 4 - block_size already read)
    let total = 4 + packet_length;
    let remaining = total - block_size;

    let mut rest = vec![0u8; remaining];
    if remaining > 0 {
        reader.read_exact(&mut rest).await.map_err(SshError::Io)?;

        if let Some(ref mut ciphers) = keys.ciphers {
            ciphers.decrypt.apply(&mut rest);
        }
    }

    // Reassemble full packet data
    let mut full_data = first_block;
    full_data.extend_from_slice(&rest);

    let seq = keys.next_recv_seq();

    // Verify MAC if active
    if let Some(ref mac_key) = keys.recv_mac_key {
        let mut mac_buf = vec![0u8; HMAC_SHA256_SIZE];
        reader.read_exact(&mut mac_buf).await.map_err(SshError::Io)?;

        let mut mac_data = Vec::new();
        write_u32_be(&mut mac_data, seq);
        mac_data.extend_from_slice(&full_data);
        verify_hmac(mac_key, &mac_data, &mac_buf)?;
    }

    SshPacket::deserialize(&full_data)
}

/// Exchange version strings per RFC 4253 §4.2.
///
/// The version string is `SSH-2.0-SwiftSSH_0.1\r\n`.
pub async fn send_version_string<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    version: &str,
) -> SshResult<()> {
    let line = format!("{}\r\n", version);
    writer.write_all(line.as_bytes()).await.map_err(SshError::Io)?;
    writer.flush().await.map_err(SshError::Io)?;
    tracing::debug!("Sent version: {}", version);
    Ok(())
}

/// Read the peer's version string.
/// Returns the version without the trailing \r\n.
pub async fn recv_version_string<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> SshResult<String> {
    let mut buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        reader.read_exact(&mut byte).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                SshError::ConnectionClosed
            } else {
                SshError::Io(e)
            }
        })?;

        buf.push(byte[0]);

        if buf.len() > 255 {
            return Err(SshError::Protocol("Version string too long".into()));
        }

        if buf.ends_with(b"\r\n") {
            break;
        }
    }

    // Remove trailing \r\n
    buf.truncate(buf.len() - 2);

    let version = String::from_utf8(buf)
        .map_err(|_| SshError::Protocol("Invalid UTF-8 in version string".into()))?;

    if !version.starts_with("SSH-2.0-") {
        return Err(SshError::Protocol(format!(
            "Unsupported protocol version: {}",
            version
        )));
    }

    tracing::debug!("Received version: {}", version);
    Ok(version)
}

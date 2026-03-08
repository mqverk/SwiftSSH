/// SwiftSSH Server — handles incoming SSH-2 connections.
///
/// Flow per connection:
/// 1. Version exchange (RFC 4253 §4.2)
/// 2. Key exchange (curve25519-sha256)
/// 3. Service request → "ssh-userauth"
/// 4. User authentication (password or publickey)
/// 5. Channel open → exec / shell / SFTP subsystem
/// 6. Data exchange → channel close → disconnect
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use swiftssh::auth::{
    AuthRequest, Credential, UserDatabase,
    build_auth_failure, build_auth_success, build_service_accept,
};
use swiftssh::connection::{
    self, ChannelDataMsg, ChannelManager, ChannelOpenMsg, ChannelRequestMsg,
};
use swiftssh::crypto::{self, CipherPair};
use swiftssh::error::{SshError, SshResult};
use swiftssh::packet::types::*;
use swiftssh::packet::{SshBuf, SshPacket};
use swiftssh::session::SessionKeys;
use swiftssh::sftp::{SftpHandler, SftpPacket};
use swiftssh::transport::{
    KexServer, build_kexinit_payload,
    recv_packet, recv_version_string, send_packet, send_version_string,
};

/// Server configuration.
#[derive(Clone)]
pub struct ServerConfig {
    pub bind_addr: String,
    pub port: u16,
    pub sftp_root: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: 2222,
            sftp_root: PathBuf::from("/tmp/swiftssh"),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = ServerConfig::default();

    // Ensure SFTP root exists
    std::fs::create_dir_all(&config.sftp_root)?;

    // Set up user database
    let mut user_db = UserDatabase::new();
    user_db.add_password_user("admin", "admin");
    user_db.add_password_user("user", "password");
    let user_db = Arc::new(user_db);

    let addr = format!("{}:{}", config.bind_addr, config.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("SwiftSSH server listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        tracing::info!("New connection from {}", peer_addr);

        let user_db = user_db.clone();
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, user_db, config).await {
                tracing::error!("Connection error from {}: {}", peer_addr, e);
            }
            tracing::info!("Connection closed: {}", peer_addr);
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    user_db: Arc<UserDatabase>,
    config: ServerConfig,
) -> SshResult<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);
    let mut keys = SessionKeys::new();
    let mut channels = ChannelManager::new();

    let server_version = SSH_VERSION_STRING;

    // 1. Version exchange
    send_version_string(&mut writer, server_version).await?;
    let client_version = recv_version_string(&mut reader).await?;
    tracing::info!("Client version: {}", client_version);

    // 2. Key exchange
    let server_kexinit_payload = build_kexinit_payload();
    let server_kexinit_packet = SshPacket::new(MessageType::KexInit, server_kexinit_payload.clone());
    send_packet(&mut writer, &server_kexinit_packet, &mut keys).await?;

    // Receive client's KEXINIT
    let client_kexinit_pkt = recv_packet(&mut reader, &mut keys).await?;
    if client_kexinit_pkt.msg_type != MessageType::KexInit as u8 {
        return Err(SshError::Protocol("Expected KEXINIT".into()));
    }
    let client_kexinit_payload = client_kexinit_pkt.payload.clone();

    // Receive client's KEX_ECDH_INIT
    let kex_init_pkt = recv_packet(&mut reader, &mut keys).await?;
    if kex_init_pkt.msg_type != MessageType::KexEcdhInit as u8 {
        return Err(SshError::Protocol("Expected KEX_ECDH_INIT".into()));
    }
    let mut cursor = Cursor::new(kex_init_pkt.payload.as_slice());
    let client_ephemeral_pub_bytes = SshBuf::read_string(&mut cursor)?;
    if client_ephemeral_pub_bytes.len() != 32 {
        return Err(SshError::KeyExchange("Invalid client public key length".into()));
    }
    let mut client_ephemeral_pub = [0u8; 32];
    client_ephemeral_pub.copy_from_slice(&client_ephemeral_pub_bytes);

    // Server performs key exchange
    let mut kex = KexServer::new();
    let server_ephemeral_pub = kex.server_ephemeral_pub;

    // For educational purposes, use a simple host key blob
    let host_key_blob = b"swiftssh-server-host-key";

    // Complete the KEXINIT payload needs to include msg type
    let mut full_client_kexinit = vec![MessageType::KexInit as u8];
    full_client_kexinit.extend_from_slice(&client_kexinit_payload);
    let mut full_server_kexinit = vec![MessageType::KexInit as u8];
    full_server_kexinit.extend_from_slice(&server_kexinit_payload);

    let kex_result = kex.complete(
        &client_ephemeral_pub,
        &client_version,
        server_version,
        &full_client_kexinit,
        &full_server_kexinit,
        host_key_blob,
    )?;

    // Send KEX_ECDH_REPLY
    let mut reply_payload = Vec::new();
    SshBuf::write_string(&mut reply_payload, host_key_blob); // K_S (host key)
    SshBuf::write_string(&mut reply_payload, &server_ephemeral_pub); // f (server ephemeral pub)
    // Signature over exchange hash (simplified — real impl would use Ed25519/RSA)
    let signature = crypto::compute_hmac(b"host-key-secret", &kex_result.exchange_hash);
    SshBuf::write_string(&mut reply_payload, &signature); // sig(H)

    let reply_pkt = SshPacket::new(MessageType::KexEcdhReply, reply_payload);
    send_packet(&mut writer, &reply_pkt, &mut keys).await?;

    // Send NEWKEYS
    let newkeys_pkt = SshPacket::new(MessageType::NewKeys, Vec::new());
    send_packet(&mut writer, &newkeys_pkt, &mut keys).await?;

    // Receive client's NEWKEYS
    let client_newkeys = recv_packet(&mut reader, &mut keys).await?;
    if client_newkeys.msg_type != MessageType::NewKeys as u8 {
        return Err(SshError::Protocol("Expected NEWKEYS".into()));
    }

    // Derive session keys
    let session_id = kex_result.exchange_hash.clone();

    // IV client->server (A), IV server->client (B)
    // Enc key client->server (C), Enc key server->client (D)
    // MAC key client->server (E), MAC key server->client (F)
    let iv_cs = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'A', &session_id, 16);
    let iv_sc = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'B', &session_id, 16);
    let enc_key_cs = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'C', &session_id, 32);
    let enc_key_sc = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'D', &session_id, 32);
    let mac_key_cs = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'E', &session_id, 32);
    let mac_key_sc = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'F', &session_id, 32);

    // Server decrypts with client->server keys, encrypts with server->client keys
    let cipher_pair = CipherPair::new(&enc_key_sc, &iv_sc, &enc_key_cs, &iv_cs)?;

    keys.session_id = Some(session_id);
    keys.ciphers = Some(cipher_pair);
    keys.send_mac_key = Some(mac_key_sc);
    keys.recv_mac_key = Some(mac_key_cs);

    tracing::info!("Key exchange complete, encryption active");

    // 3. Service request
    let service_req = recv_packet(&mut reader, &mut keys).await?;
    if service_req.msg_type != MessageType::ServiceRequest as u8 {
        return Err(SshError::Protocol("Expected SERVICE_REQUEST".into()));
    }
    let mut cursor = Cursor::new(service_req.payload.as_slice());
    let service_name = SshBuf::read_utf8(&mut cursor)?;
    tracing::info!("Service requested: {}", service_name);

    let accept_pkt = build_service_accept(&service_name);
    send_packet(&mut writer, &accept_pkt, &mut keys).await?;

    // 4. User authentication
    let mut authenticated = false;
    while !authenticated {
        let auth_pkt = recv_packet(&mut reader, &mut keys).await?;
        if auth_pkt.msg_type != MessageType::UserAuthRequest as u8 {
            return Err(SshError::Protocol("Expected USERAUTH_REQUEST".into()));
        }

        let auth_req = AuthRequest::parse(&auth_pkt.payload)?;
        tracing::info!(
            "Auth attempt: user={}, method={}",
            auth_req.username,
            auth_req.method
        );

        match auth_req.credential {
            Credential::Password(ref password) => {
                if user_db.verify_password(&auth_req.username, password) {
                    let success = build_auth_success();
                    send_packet(&mut writer, &success, &mut keys).await?;
                    authenticated = true;
                    tracing::info!("User '{}' authenticated (password)", auth_req.username);
                } else {
                    let failure = build_auth_failure(&["password", "publickey"], false);
                    send_packet(&mut writer, &failure, &mut keys).await?;
                    tracing::warn!("Auth failed for user '{}'", auth_req.username);
                }
            }
            Credential::PublicKey { ref key_blob, .. } => {
                if user_db.is_key_authorized(&auth_req.username, key_blob) {
                    let success = build_auth_success();
                    send_packet(&mut writer, &success, &mut keys).await?;
                    authenticated = true;
                    tracing::info!("User '{}' authenticated (publickey)", auth_req.username);
                } else {
                    let failure = build_auth_failure(&["password", "publickey"], false);
                    send_packet(&mut writer, &failure, &mut keys).await?;
                }
            }
        }
    }

    // 5. Channel handling loop
    let sftp_handler = Arc::new(Mutex::new(SftpHandler::new(config.sftp_root)));

    loop {
        let pkt = match recv_packet(&mut reader, &mut keys).await {
            Ok(p) => p,
            Err(SshError::ConnectionClosed) => {
                tracing::info!("Client disconnected");
                break;
            }
            Err(e) => return Err(e),
        };

        let msg_type = MessageType::from_u8(pkt.msg_type);
        tracing::debug!("Received message type: {:?}", msg_type);

        match msg_type {
            Some(MessageType::ChannelOpen) => {
                let msg = ChannelOpenMsg::parse(&pkt.payload)?;
                tracing::info!("Channel open: type={}, id={}", msg.channel_type, msg.sender_channel);

                let local_id = channels.accept_channel(
                    msg.sender_channel,
                    &msg.channel_type,
                    msg.initial_window,
                    msg.max_packet,
                );

                let confirm = connection::build_channel_open_confirmation(
                    msg.sender_channel,
                    local_id,
                    DEFAULT_WINDOW_SIZE,
                    DEFAULT_MAX_PACKET_SIZE,
                );
                send_packet(&mut writer, &confirm, &mut keys).await?;
            }

            Some(MessageType::ChannelRequest) => {
                let msg = ChannelRequestMsg::parse(&pkt.payload)?;
                tracing::info!(
                    "Channel request: type={}, channel={}",
                    msg.request_type,
                    msg.recipient_channel
                );

                match msg.request_type.as_str() {
                    "exec" => {
                        let mut data_cursor = Cursor::new(msg.data.as_slice());
                        let command = SshBuf::read_utf8(&mut data_cursor)?;
                        tracing::info!("Exec: {}", command);

                        // Execute command
                        let output = execute_command(&command).await;

                        // Find the channel's remote_id
                        let ch = channels
                            .find_by_remote_id(msg.recipient_channel)
                            .ok_or_else(|| {
                                SshError::Channel("Unknown channel".into())
                            })?;
                        let remote_id = ch.remote_id;

                        // Send success if wanted
                        if msg.want_reply {
                            let success = SshPacket::new(MessageType::ChannelSuccess, {
                                let mut p = Vec::new();
                                SshBuf::write_u32(&mut p, remote_id);
                                p
                            });
                            send_packet(&mut writer, &success, &mut keys).await?;
                        }

                        // Send output data
                        let data_pkt = connection::build_channel_data(remote_id, output.as_bytes());
                        send_packet(&mut writer, &data_pkt, &mut keys).await?;

                        // Send EOF and close
                        let eof = connection::build_channel_eof(remote_id);
                        send_packet(&mut writer, &eof, &mut keys).await?;

                        let close = connection::build_channel_close(remote_id);
                        send_packet(&mut writer, &close, &mut keys).await?;
                    }
                    "shell" => {
                        if msg.want_reply {
                            let ch = channels.find_by_remote_id(msg.recipient_channel)
                                .ok_or_else(|| SshError::Channel("Unknown channel".into()))?;
                            let remote_id = ch.remote_id;
                            let success = SshPacket::new(MessageType::ChannelSuccess, {
                                let mut p = Vec::new();
                                SshBuf::write_u32(&mut p, remote_id);
                                p
                            });
                            send_packet(&mut writer, &success, &mut keys).await?;
                        }
                        tracing::info!("Shell requested (interactive mode placeholder)");
                    }
                    "subsystem" => {
                        let mut data_cursor = Cursor::new(msg.data.as_slice());
                        let subsystem = SshBuf::read_utf8(&mut data_cursor)?;
                        tracing::info!("Subsystem requested: {}", subsystem);

                        if subsystem == "sftp" {
                            if msg.want_reply {
                                let ch = channels.find_by_remote_id(msg.recipient_channel)
                                    .ok_or_else(|| SshError::Channel("Unknown channel".into()))?;
                                let remote_id = ch.remote_id;
                                let success = SshPacket::new(MessageType::ChannelSuccess, {
                                    let mut p = Vec::new();
                                    SshBuf::write_u32(&mut p, remote_id);
                                    p
                                });
                                send_packet(&mut writer, &success, &mut keys).await?;
                            }
                        } else if msg.want_reply {
                            let ch = channels.find_by_remote_id(msg.recipient_channel)
                                .ok_or_else(|| SshError::Channel("Unknown channel".into()))?;
                            let remote_id = ch.remote_id;
                            let failure = SshPacket::new(MessageType::ChannelFailure, {
                                let mut p = Vec::new();
                                SshBuf::write_u32(&mut p, remote_id);
                                p
                            });
                            send_packet(&mut writer, &failure, &mut keys).await?;
                        }
                    }
                    "pty-req" => {
                        tracing::info!("PTY request (accepted)");
                        if msg.want_reply {
                            let ch = channels.find_by_remote_id(msg.recipient_channel)
                                .ok_or_else(|| SshError::Channel("Unknown channel".into()))?;
                            let remote_id = ch.remote_id;
                            let success = SshPacket::new(MessageType::ChannelSuccess, {
                                let mut p = Vec::new();
                                SshBuf::write_u32(&mut p, remote_id);
                                p
                            });
                            send_packet(&mut writer, &success, &mut keys).await?;
                        }
                    }
                    _ => {
                        tracing::warn!("Unknown channel request: {}", msg.request_type);
                        if msg.want_reply {
                            let ch = channels.find_by_remote_id(msg.recipient_channel)
                                .ok_or_else(|| SshError::Channel("Unknown channel".into()))?;
                            let remote_id = ch.remote_id;
                            let failure = SshPacket::new(MessageType::ChannelFailure, {
                                let mut p = Vec::new();
                                SshBuf::write_u32(&mut p, remote_id);
                                p
                            });
                            send_packet(&mut writer, &failure, &mut keys).await?;
                        }
                    }
                }
            }

            Some(MessageType::ChannelData) => {
                let msg = ChannelDataMsg::parse(&pkt.payload)?;
                // Could be SFTP data on a subsystem channel
                // For now, log it
                tracing::debug!(
                    "Channel data: channel={}, {} bytes",
                    msg.recipient_channel,
                    msg.data.len()
                );

                // Try to process as SFTP
                if msg.data.len() >= 9 {
                    // SFTP packets are length-prefixed inside channel data
                    let sftp_len = u32::from_be_bytes([
                        msg.data[0],
                        msg.data[1],
                        msg.data[2],
                        msg.data[3],
                    ]) as usize;

                    if sftp_len + 4 <= msg.data.len() && sftp_len >= 5 {
                        if let Ok(sftp_pkt) = SftpPacket::decode(&msg.data[4..4 + sftp_len]) {
                            let mut handler = sftp_handler.lock().await;
                            let response = handler.handle_request(&sftp_pkt);
                            let encoded = response.encode();

                            let ch = channels.find_by_remote_id(msg.recipient_channel)
                                .ok_or_else(|| SshError::Channel("Unknown channel".into()))?;
                            let remote_id = ch.remote_id;

                            let data_pkt = connection::build_channel_data(remote_id, &encoded);
                            send_packet(&mut writer, &data_pkt, &mut keys).await?;
                        }
                    }
                }
            }

            Some(MessageType::ChannelWindowAdjust) => {
                let mut cursor = Cursor::new(pkt.payload.as_slice());
                let recipient = SshBuf::read_u32(&mut cursor)?;
                let bytes_to_add = SshBuf::read_u32(&mut cursor)?;
                if let Some(ch) = channels.find_by_remote_id_mut(recipient) {
                    ch.remote_window = ch.remote_window.saturating_add(bytes_to_add);
                }
            }

            Some(MessageType::ChannelEof) => {
                let mut cursor = Cursor::new(pkt.payload.as_slice());
                let recipient = SshBuf::read_u32(&mut cursor)?;
                if let Some(ch) = channels.find_by_remote_id_mut(recipient) {
                    ch.eof_received = true;
                }
                tracing::debug!("Channel EOF: {}", recipient);
            }

            Some(MessageType::ChannelClose) => {
                let mut cursor = Cursor::new(pkt.payload.as_slice());
                let recipient = SshBuf::read_u32(&mut cursor)?;
                tracing::debug!("Channel close: {}", recipient);

                // Send close back if we haven't already
                if let Some(ch) = channels.find_by_remote_id(recipient) {
                    if !ch.closed {
                        let remote_id = ch.remote_id;
                        let close = connection::build_channel_close(remote_id);
                        send_packet(&mut writer, &close, &mut keys).await?;
                    }
                }
            }

            Some(MessageType::Disconnect) => {
                tracing::info!("Client sent DISCONNECT");
                break;
            }

            Some(MessageType::Ignore) => {
                // Silently ignore
            }

            _ => {
                tracing::warn!("Unhandled message type: {}", pkt.msg_type);
            }
        }
    }

    Ok(())
}

/// Execute a command and capture its output.
async fn execute_command(command: &str) -> String {
    use tokio::process::Command;

    // Split command for safety (basic splitting, not full shell parsing)
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return String::new();
    }

    match Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .await
    {
        Ok(output) => {
            let mut result = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                result.push_str(&stderr);
            }
            result
        }
        Err(e) => format!("Command failed: {}\n", e),
    }
}

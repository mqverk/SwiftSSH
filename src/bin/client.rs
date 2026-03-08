/// SwiftSSH Client — connects to an SSH-2 server, authenticates, and executes commands.
///
/// Usage:
///   swiftssh-client --host <host> --port <port> --user <user> --password <pass> --command <cmd>
///   swiftssh-client --host <host> --user <user> --password <pass> --interactive
use std::io::Cursor;

use clap::Parser;
use tokio::io::{BufReader, BufWriter};
use tokio::net::TcpStream;

use swiftssh::auth;
use swiftssh::connection::{self, ChannelDataMsg, ChannelManager};
use swiftssh::crypto::{self, CipherPair};
use swiftssh::error::{SshError, SshResult};
use swiftssh::packet::types::*;
use swiftssh::packet::{SshBuf, SshPacket};
use swiftssh::session::SessionKeys;
use swiftssh::transport::{
    KexClient, build_kexinit_payload,
    recv_packet, recv_version_string, send_packet, send_version_string,
};

#[derive(Parser, Debug)]
#[command(name = "swiftssh-client", about = "SwiftSSH Client")]
struct Args {
    /// Server hostname or IP
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Server port
    #[arg(long, default_value_t = 2222)]
    port: u16,

    /// Username
    #[arg(long, short = 'u')]
    user: String,

    /// Password (for password auth)
    #[arg(long, short = 'p')]
    password: Option<String>,

    /// Command to execute remotely
    #[arg(long, short = 'c')]
    command: Option<String>,

    /// Interactive shell mode
    #[arg(long, short = 'i')]
    interactive: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    if args.password.is_none() {
        anyhow::bail!("Password required (--password)");
    }

    let addr = format!("{}:{}", args.host, args.port);
    tracing::info!("Connecting to {}", addr);

    let stream = TcpStream::connect(&addr).await?;
    tracing::info!("Connected to {}", addr);

    run_client(stream, &args).await?;
    Ok(())
}

async fn run_client(stream: TcpStream, args: &Args) -> SshResult<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);
    let mut keys = SessionKeys::new();
    let mut channels = ChannelManager::new();

    let client_version = SSH_VERSION_STRING;

    // 1. Version exchange
    send_version_string(&mut writer, client_version).await?;
    let server_version = recv_version_string(&mut reader).await?;
    tracing::info!("Server version: {}", server_version);

    // 2. Key exchange
    // Receive server's KEXINIT first
    let server_kexinit_pkt = recv_packet(&mut reader, &mut keys).await?;
    if server_kexinit_pkt.msg_type != MessageType::KexInit as u8 {
        return Err(SshError::Protocol("Expected KEXINIT from server".into()));
    }
    let server_kexinit_payload = server_kexinit_pkt.payload.clone();

    // Send our KEXINIT
    let client_kexinit_payload = build_kexinit_payload();
    let client_kexinit_packet = SshPacket::new(MessageType::KexInit, client_kexinit_payload.clone());
    send_packet(&mut writer, &client_kexinit_packet, &mut keys).await?;

    // Generate ephemeral keypair and send KEX_ECDH_INIT
    let mut kex = KexClient::new();
    let mut ecdh_init_payload = Vec::new();
    SshBuf::write_string(&mut ecdh_init_payload, &kex.client_ephemeral_pub);
    let ecdh_init_pkt = SshPacket::new(MessageType::KexEcdhInit, ecdh_init_payload);
    send_packet(&mut writer, &ecdh_init_pkt, &mut keys).await?;

    // Receive KEX_ECDH_REPLY
    let reply_pkt = recv_packet(&mut reader, &mut keys).await?;
    if reply_pkt.msg_type != MessageType::KexEcdhReply as u8 {
        return Err(SshError::Protocol("Expected KEX_ECDH_REPLY".into()));
    }

    let mut cursor = Cursor::new(reply_pkt.payload.as_slice());
    let host_key_blob = SshBuf::read_string(&mut cursor)?;
    let server_ephemeral_pub_bytes = SshBuf::read_string(&mut cursor)?;
    let _signature = SshBuf::read_string(&mut cursor)?;

    if server_ephemeral_pub_bytes.len() != 32 {
        return Err(SshError::KeyExchange("Invalid server public key length".into()));
    }
    let mut server_ephemeral_pub = [0u8; 32];
    server_ephemeral_pub.copy_from_slice(&server_ephemeral_pub_bytes);

    // Complete key exchange
    let mut full_client_kexinit = vec![MessageType::KexInit as u8];
    full_client_kexinit.extend_from_slice(&client_kexinit_payload);
    let mut full_server_kexinit = vec![MessageType::KexInit as u8];
    full_server_kexinit.extend_from_slice(&server_kexinit_payload);

    let kex_result = kex.complete(
        &server_ephemeral_pub,
        client_version,
        &server_version,
        &full_client_kexinit,
        &full_server_kexinit,
        &host_key_blob,
    )?;

    // TODO: Verify host key signature in a real implementation

    // Receive NEWKEYS from server
    let newkeys_pkt = recv_packet(&mut reader, &mut keys).await?;
    if newkeys_pkt.msg_type != MessageType::NewKeys as u8 {
        return Err(SshError::Protocol("Expected NEWKEYS".into()));
    }

    // Send our NEWKEYS
    let newkeys = SshPacket::new(MessageType::NewKeys, Vec::new());
    send_packet(&mut writer, &newkeys, &mut keys).await?;

    // Derive session keys
    let session_id = kex_result.exchange_hash.clone();

    let iv_cs = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'A', &session_id, 16);
    let iv_sc = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'B', &session_id, 16);
    let enc_key_cs = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'C', &session_id, 32);
    let enc_key_sc = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'D', &session_id, 32);
    let mac_key_cs = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'E', &session_id, 32);
    let mac_key_sc = crypto::derive_key(&kex_result.shared_secret, &kex_result.exchange_hash, b'F', &session_id, 32);

    // Client encrypts with client->server keys, decrypts with server->client keys
    let cipher_pair = CipherPair::new(&enc_key_cs, &iv_cs, &enc_key_sc, &iv_sc)?;

    keys.session_id = Some(session_id);
    keys.ciphers = Some(cipher_pair);
    keys.send_mac_key = Some(mac_key_cs);
    keys.recv_mac_key = Some(mac_key_sc);

    tracing::info!("Key exchange complete, encryption active");

    // 3. Service request
    let service_req = auth::build_service_request("ssh-userauth");
    send_packet(&mut writer, &service_req, &mut keys).await?;

    let service_accept = recv_packet(&mut reader, &mut keys).await?;
    if service_accept.msg_type != MessageType::ServiceAccept as u8 {
        return Err(SshError::Protocol("Expected SERVICE_ACCEPT".into()));
    }

    // 4. Authenticate
    let password = args.password.as_deref().unwrap_or("");
    let auth_pkt = auth::build_password_auth_request(&args.user, "ssh-connection", password);
    send_packet(&mut writer, &auth_pkt, &mut keys).await?;

    let auth_response = recv_packet(&mut reader, &mut keys).await?;
    if auth_response.msg_type == MessageType::UserAuthSuccess as u8 {
        tracing::info!("Authentication successful");
    } else if auth_response.msg_type == MessageType::UserAuthFailure as u8 {
        return Err(SshError::AuthFailed("Authentication rejected by server".into()));
    } else {
        return Err(SshError::Protocol("Unexpected auth response".into()));
    }

    // 5. Open a session channel
    let ch_id = channels.open_channel("session");
    let ch = channels.get(ch_id).unwrap();
    let open_pkt = connection::build_channel_open(
        "session",
        ch.local_id,
        ch.local_window,
        ch.local_max_packet,
    );
    send_packet(&mut writer, &open_pkt, &mut keys).await?;

    // Receive channel confirmation
    let confirm_pkt = recv_packet(&mut reader, &mut keys).await?;
    if confirm_pkt.msg_type != MessageType::ChannelOpenConfirmation as u8 {
        return Err(SshError::Channel("Channel open failed".into()));
    }

    let mut cursor = Cursor::new(confirm_pkt.payload.as_slice());
    let _recipient = SshBuf::read_u32(&mut cursor)?;
    let remote_id = SshBuf::read_u32(&mut cursor)?;
    let remote_window = SshBuf::read_u32(&mut cursor)?;
    let remote_max_packet = SshBuf::read_u32(&mut cursor)?;
    channels
        .confirm_channel(ch_id, remote_id, remote_window, remote_max_packet)?;

    tracing::info!("Channel {} opened (remote={})", ch_id, remote_id);

    // 6. Execute command or start interactive shell
    if let Some(ref command) = args.command {
        // Send exec request
        let exec_pkt = connection::build_exec_request(remote_id, command, true);
        send_packet(&mut writer, &exec_pkt, &mut keys).await?;

        // Read responses until channel closes
        loop {
            let pkt = match recv_packet(&mut reader, &mut keys).await {
                Ok(p) => p,
                Err(SshError::ConnectionClosed) => break,
                Err(e) => return Err(e),
            };

            match MessageType::from_u8(pkt.msg_type) {
                Some(MessageType::ChannelData) => {
                    let msg = ChannelDataMsg::parse(&pkt.payload)?;
                    print!("{}", String::from_utf8_lossy(&msg.data));
                }
                Some(MessageType::ChannelExtendedData) => {
                    // Extended data (stderr)
                    let mut cursor = Cursor::new(pkt.payload.as_slice());
                    let _channel = SshBuf::read_u32(&mut cursor)?;
                    let _data_type = SshBuf::read_u32(&mut cursor)?;
                    let data = SshBuf::read_string(&mut cursor)?;
                    eprint!("{}", String::from_utf8_lossy(&data));
                }
                Some(MessageType::ChannelSuccess) => {
                    tracing::debug!("Channel success");
                }
                Some(MessageType::ChannelEof) => {
                    tracing::debug!("Channel EOF");
                }
                Some(MessageType::ChannelClose) => {
                    tracing::debug!("Channel closed");
                    // Send close back
                    let close = connection::build_channel_close(remote_id);
                    send_packet(&mut writer, &close, &mut keys).await?;
                    break;
                }
                Some(MessageType::ChannelWindowAdjust) => {
                    // Just update window
                }
                _ => {
                    tracing::debug!("Received msg type: {}", pkt.msg_type);
                }
            }
        }
    } else if args.interactive {
        // Interactive shell mode
        let shell_pkt = connection::build_shell_request(remote_id, true);
        send_packet(&mut writer, &shell_pkt, &mut keys).await?;

        tracing::info!("Interactive shell started. Type commands:");

        // Simple interactive loop: read from stdin, send to channel
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);

        // Spawn stdin reader
        tokio::spawn(async move {
            let stdin = tokio::io::stdin();
            let mut reader = tokio::io::BufReader::new(stdin);
            let mut line = String::new();
            loop {
                line.clear();
                use tokio::io::AsyncBufReadExt;
                match reader.read_line(&mut line).await {
                    Ok(0) => break, // EOF
                    Ok(_) => {
                        if tx.send(line.clone()).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        loop {
            tokio::select! {
                // Data from server
                result = recv_packet(&mut reader, &mut keys) => {
                    match result {
                        Ok(pkt) => {
                            match MessageType::from_u8(pkt.msg_type) {
                                Some(MessageType::ChannelData) => {
                                    let msg = ChannelDataMsg::parse(&pkt.payload)?;
                                    print!("{}", String::from_utf8_lossy(&msg.data));
                                }
                                Some(MessageType::ChannelEof) => {
                                    tracing::debug!("Channel EOF");
                                }
                                Some(MessageType::ChannelClose) => {
                                    let close = connection::build_channel_close(remote_id);
                                    send_packet(&mut writer, &close, &mut keys).await?;
                                    break;
                                }
                                _ => {}
                            }
                        }
                        Err(SshError::ConnectionClosed) => break,
                        Err(e) => return Err(e),
                    }
                }
                // Input from user
                Some(line) = rx.recv() => {
                    let data_pkt = connection::build_channel_data(remote_id, line.as_bytes());
                    send_packet(&mut writer, &data_pkt, &mut keys).await?;
                }
            }
        }
    } else {
        tracing::info!("No command specified. Use --command or --interactive");
    }

    // Send disconnect
    let mut disconnect_payload = Vec::new();
    SshBuf::write_u32(&mut disconnect_payload, 11); // BY_APPLICATION
    SshBuf::write_utf8(&mut disconnect_payload, "Session ended");
    SshBuf::write_utf8(&mut disconnect_payload, "en");
    let disconnect = SshPacket::new(MessageType::Disconnect, disconnect_payload);
    send_packet(&mut writer, &disconnect, &mut keys).await?;

    tracing::info!("Disconnected");
    Ok(())
}

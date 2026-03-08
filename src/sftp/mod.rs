/// SSH File Transfer Protocol (SFTP) subsystem.
///
/// Implements a subset of the SFTP protocol (draft-ietf-secsh-filexfer-02)
/// running over an SSH channel.
///
/// Supported operations:
/// - Open, read, write, close files
/// - List directory contents
/// - Stat/lstat for file attributes
/// - Mkdir/rmdir, remove
use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;

use crate::error::{SshError, SshResult};
use crate::packet::SshBuf;

// SFTP packet types
pub const SSH_FXP_INIT: u8 = 1;
pub const SSH_FXP_VERSION: u8 = 2;
pub const SSH_FXP_OPEN: u8 = 3;
pub const SSH_FXP_CLOSE: u8 = 4;
pub const SSH_FXP_READ: u8 = 5;
pub const SSH_FXP_WRITE: u8 = 6;
pub const SSH_FXP_LSTAT: u8 = 7;
pub const SSH_FXP_FSTAT: u8 = 8;
pub const SSH_FXP_SETSTAT: u8 = 9;
pub const SSH_FXP_OPENDIR: u8 = 11;
pub const SSH_FXP_READDIR: u8 = 12;
pub const SSH_FXP_REMOVE: u8 = 13;
pub const SSH_FXP_MKDIR: u8 = 14;
pub const SSH_FXP_RMDIR: u8 = 15;
pub const SSH_FXP_REALPATH: u8 = 16;
pub const SSH_FXP_STAT: u8 = 17;
pub const SSH_FXP_STATUS: u8 = 101;
pub const SSH_FXP_HANDLE: u8 = 102;
pub const SSH_FXP_DATA: u8 = 103;
pub const SSH_FXP_NAME: u8 = 104;
pub const SSH_FXP_ATTRS: u8 = 105;

// Status codes
pub const SSH_FX_OK: u32 = 0;
pub const SSH_FX_EOF: u32 = 1;
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
pub const SSH_FX_FAILURE: u32 = 4;
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;

// Open flags
pub const SSH_FXF_READ: u32 = 0x00000001;
pub const SSH_FXF_WRITE: u32 = 0x00000002;
pub const SSH_FXF_APPEND: u32 = 0x00000004;
pub const SSH_FXF_CREAT: u32 = 0x00000008;
pub const SSH_FXF_TRUNC: u32 = 0x00000010;

// Attribute flags
pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x00000001;
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x00000002;
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x00000004;
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x00000008;

/// SFTP protocol version we support.
pub const SFTP_VERSION: u32 = 3;

/// File attributes structure.
#[derive(Debug, Clone, Default)]
pub struct FileAttrs {
    pub flags: u32,
    pub size: Option<u64>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub permissions: Option<u32>,
    pub atime: Option<u32>,
    pub mtime: Option<u32>,
}

impl FileAttrs {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        SshBuf::write_u32(&mut buf, self.flags);

        if let Some(size) = self.size {
            buf.extend_from_slice(&size.to_be_bytes());
        }
        if let (Some(uid), Some(gid)) = (self.uid, self.gid) {
            SshBuf::write_u32(&mut buf, uid);
            SshBuf::write_u32(&mut buf, gid);
        }
        if let Some(perms) = self.permissions {
            SshBuf::write_u32(&mut buf, perms);
        }
        if let (Some(atime), Some(mtime)) = (self.atime, self.mtime) {
            SshBuf::write_u32(&mut buf, atime);
            SshBuf::write_u32(&mut buf, mtime);
        }
        buf
    }

    pub fn decode(cursor: &mut Cursor<&[u8]>) -> SshResult<Self> {
        let flags = SshBuf::read_u32(cursor)?;
        let mut attrs = FileAttrs {
            flags,
            ..Default::default()
        };

        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            use byteorder::{BigEndian, ReadBytesExt};
            let size = cursor
                .read_u64::<BigEndian>()
                .map_err(|_| SshError::Sftp("Failed to read file size".into()))?;
            attrs.size = Some(size);
        }
        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            attrs.uid = Some(SshBuf::read_u32(cursor)?);
            attrs.gid = Some(SshBuf::read_u32(cursor)?);
        }
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            attrs.permissions = Some(SshBuf::read_u32(cursor)?);
        }
        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            attrs.atime = Some(SshBuf::read_u32(cursor)?);
            attrs.mtime = Some(SshBuf::read_u32(cursor)?);
        }
        Ok(attrs)
    }
}

/// An SFTP request/response packet.
#[derive(Debug)]
pub struct SftpPacket {
    pub packet_type: u8,
    pub request_id: u32,
    pub data: Vec<u8>,
}

impl SftpPacket {
    pub fn new(packet_type: u8, request_id: u32, data: Vec<u8>) -> Self {
        Self {
            packet_type,
            request_id,
            data,
        }
    }

    /// Encode an SFTP packet into bytes (length-prefixed).
    pub fn encode(&self) -> Vec<u8> {
        let inner_len = 1 + 4 + self.data.len(); // type + request_id + data
        let mut buf = Vec::with_capacity(4 + inner_len);
        SshBuf::write_u32(&mut buf, inner_len as u32);
        SshBuf::write_u8(&mut buf, self.packet_type);
        SshBuf::write_u32(&mut buf, self.request_id);
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode an SFTP packet from bytes (after reading the length prefix).
    pub fn decode(data: &[u8]) -> SshResult<Self> {
        if data.len() < 5 {
            return Err(SshError::Sftp("SFTP packet too short".into()));
        }
        let packet_type = data[0];
        let request_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        let payload = data[5..].to_vec();
        Ok(Self {
            packet_type,
            request_id,
            data: payload,
        })
    }
}

/// Build an SSH_FXP_INIT packet.
pub fn build_sftp_init() -> Vec<u8> {
    let mut buf = Vec::new();
    let inner_len: u32 = 1 + 4; // type byte + version u32
    SshBuf::write_u32(&mut buf, inner_len);
    SshBuf::write_u8(&mut buf, SSH_FXP_INIT);
    SshBuf::write_u32(&mut buf, SFTP_VERSION);
    buf
}

/// Build an SSH_FXP_VERSION response.
pub fn build_sftp_version() -> Vec<u8> {
    let mut buf = Vec::new();
    let inner_len: u32 = 1 + 4;
    SshBuf::write_u32(&mut buf, inner_len);
    SshBuf::write_u8(&mut buf, SSH_FXP_VERSION);
    SshBuf::write_u32(&mut buf, SFTP_VERSION);
    buf
}

/// Build an SSH_FXP_STATUS response.
pub fn build_sftp_status(request_id: u32, status_code: u32, message: &str) -> SftpPacket {
    let mut data = Vec::new();
    SshBuf::write_u32(&mut data, status_code);
    SshBuf::write_utf8(&mut data, message);
    SshBuf::write_utf8(&mut data, "en"); // language
    SftpPacket::new(SSH_FXP_STATUS, request_id, data)
}

/// Build an SSH_FXP_HANDLE response.
pub fn build_sftp_handle(request_id: u32, handle: &[u8]) -> SftpPacket {
    let mut data = Vec::new();
    SshBuf::write_string(&mut data, handle);
    SftpPacket::new(SSH_FXP_HANDLE, request_id, data)
}

/// Build an SSH_FXP_DATA response.
pub fn build_sftp_data(request_id: u32, file_data: &[u8]) -> SftpPacket {
    let mut data = Vec::new();
    SshBuf::write_string(&mut data, file_data);
    SftpPacket::new(SSH_FXP_DATA, request_id, data)
}

/// Build an SSH_FXP_NAME response (for readdir / realpath).
pub fn build_sftp_name(request_id: u32, entries: &[(String, FileAttrs)]) -> SftpPacket {
    let mut data = Vec::new();
    SshBuf::write_u32(&mut data, entries.len() as u32);
    for (name, attrs) in entries {
        SshBuf::write_utf8(&mut data, name);
        SshBuf::write_utf8(&mut data, name); // long name (same for simplicity)
        data.extend_from_slice(&attrs.encode());
    }
    SftpPacket::new(SSH_FXP_NAME, request_id, data)
}

/// Build an SSH_FXP_ATTRS response.
pub fn build_sftp_attrs(request_id: u32, attrs: &FileAttrs) -> SftpPacket {
    SftpPacket::new(SSH_FXP_ATTRS, request_id, attrs.encode())
}

/// Server-side SFTP handler that processes requests against the local filesystem.
pub struct SftpHandler {
    next_handle: u32,
    /// Maps handle bytes -> open file path and flags
    open_files: HashMap<Vec<u8>, (PathBuf, u32)>,
    /// Maps handle bytes -> directory path for readdir
    open_dirs: HashMap<Vec<u8>, (PathBuf, bool)>, // (path, already_listed)
    /// Root directory to restrict file access (chroot-like).
    root: PathBuf,
}

impl SftpHandler {
    pub fn new(root: PathBuf) -> Self {
        Self {
            next_handle: 0,
            open_files: HashMap::new(),
            open_dirs: HashMap::new(),
            root,
        }
    }

    /// Resolve a client-requested path against our root, preventing path traversal.
    fn resolve_path(&self, requested: &str) -> SshResult<PathBuf> {
        let path = if requested.starts_with('/') {
            self.root.join(&requested[1..])
        } else {
            self.root.join(requested)
        };

        // Canonicalize to prevent path traversal.
        // If canonicalize fails (path doesn't exist yet), normalize manually.
        let canonical = match path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                // For non-existent paths, normalize by resolving the parent
                // and appending the filename.
                normalize_path(&path)
            }
        };

        // Verify the resolved path is within our root
        let root_canonical = self.root.canonicalize().unwrap_or_else(|_| normalize_path(&self.root));
        if !canonical.starts_with(&root_canonical) {
            return Err(SshError::Sftp("Access denied: path outside root".into()));
        }

        Ok(canonical)
    }

    fn alloc_handle(&mut self) -> Vec<u8> {
        let handle = self.next_handle.to_be_bytes().to_vec();
        self.next_handle += 1;
        handle
    }

    /// Process an SFTP request and return a response packet.
    pub fn handle_request(&mut self, pkt: &SftpPacket) -> SftpPacket {
        match pkt.packet_type {
            SSH_FXP_REALPATH => self.handle_realpath(pkt),
            SSH_FXP_STAT | SSH_FXP_LSTAT => self.handle_stat(pkt),
            SSH_FXP_OPENDIR => self.handle_opendir(pkt),
            SSH_FXP_READDIR => self.handle_readdir(pkt),
            SSH_FXP_CLOSE => self.handle_close(pkt),
            SSH_FXP_OPEN => self.handle_open(pkt),
            SSH_FXP_READ => self.handle_read(pkt),
            SSH_FXP_WRITE => self.handle_write(pkt),
            SSH_FXP_MKDIR => self.handle_mkdir(pkt),
            SSH_FXP_RMDIR => self.handle_rmdir(pkt),
            SSH_FXP_REMOVE => self.handle_remove(pkt),
            _ => build_sftp_status(
                pkt.request_id,
                SSH_FX_OP_UNSUPPORTED,
                "Unsupported operation",
            ),
        }
    }

    fn handle_realpath(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Not found"),
        };

        let name = resolved.to_string_lossy().to_string();
        build_sftp_name(pkt.request_id, &[(name, FileAttrs::default())])
    }

    fn handle_stat(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => {
                return build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Not found")
            }
        };

        match std::fs::metadata(&resolved) {
            Ok(meta) => {
                let attrs = metadata_to_attrs(&meta);
                build_sftp_attrs(pkt.request_id, &attrs)
            }
            Err(_) => build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Not found"),
        }
    }

    fn handle_opendir(&mut self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => {
                return build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Not found")
            }
        };

        if !resolved.is_dir() {
            return build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Not a directory");
        }

        let handle = self.alloc_handle();
        self.open_dirs.insert(handle.clone(), (resolved, false));
        build_sftp_handle(pkt.request_id, &handle)
    }

    fn handle_readdir(&mut self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let handle = match SshBuf::read_string(&mut cursor) {
            Ok(h) => h,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad handle"),
        };

        let (path, already_listed) = match self.open_dirs.get_mut(&handle) {
            Some(entry) => entry,
            None => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Invalid handle"),
        };

        if *already_listed {
            return build_sftp_status(pkt.request_id, SSH_FX_EOF, "End of directory");
        }

        *already_listed = true;
        let dir_path = path.clone();

        match std::fs::read_dir(&dir_path) {
            Ok(entries) => {
                let mut names: Vec<(String, FileAttrs)> = Vec::new();
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let attrs = entry
                        .metadata()
                        .map(|m| metadata_to_attrs(&m))
                        .unwrap_or_default();
                    names.push((name, attrs));
                }
                build_sftp_name(pkt.request_id, &names)
            }
            Err(_) => {
                build_sftp_status(pkt.request_id, SSH_FX_PERMISSION_DENIED, "Cannot read dir")
            }
        }
    }

    fn handle_close(&mut self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let handle = match SshBuf::read_string(&mut cursor) {
            Ok(h) => h,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad handle"),
        };

        self.open_files.remove(&handle);
        self.open_dirs.remove(&handle);
        build_sftp_status(pkt.request_id, SSH_FX_OK, "OK")
    }

    fn handle_open(&mut self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };
        let flags = match SshBuf::read_u32(&mut cursor) {
            Ok(f) => f,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad flags"),
        };
        // attrs — we read but don't enforce for simplicity
        let _attrs = FileAttrs::decode(&mut cursor).ok();

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => {
                return build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Path error")
            }
        };

        let handle = self.alloc_handle();
        self.open_files.insert(handle.clone(), (resolved, flags));
        build_sftp_handle(pkt.request_id, &handle)
    }

    fn handle_read(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let handle = match SshBuf::read_string(&mut cursor) {
            Ok(h) => h,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad handle"),
        };

        use byteorder::{BigEndian, ReadBytesExt};
        let offset = match cursor.read_u64::<BigEndian>() {
            Ok(o) => o,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad offset"),
        };
        let length = match SshBuf::read_u32(&mut cursor) {
            Ok(l) => l as usize,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad length"),
        };

        let (path, _flags) = match self.open_files.get(&handle) {
            Some(entry) => entry,
            None => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Invalid handle"),
        };

        use std::io::{Read, Seek, SeekFrom};
        match std::fs::File::open(path) {
            Ok(mut file) => {
                if file.seek(SeekFrom::Start(offset)).is_err() {
                    return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Seek failed");
                }
                let mut buf = vec![0u8; length.min(32768)];
                match file.read(&mut buf) {
                    Ok(0) => build_sftp_status(pkt.request_id, SSH_FX_EOF, "EOF"),
                    Ok(n) => {
                        buf.truncate(n);
                        build_sftp_data(pkt.request_id, &buf)
                    }
                    Err(_) => build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Read error"),
                }
            }
            Err(_) => build_sftp_status(pkt.request_id, SSH_FX_NO_SUCH_FILE, "Cannot open"),
        }
    }

    fn handle_write(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let handle = match SshBuf::read_string(&mut cursor) {
            Ok(h) => h,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad handle"),
        };

        use byteorder::{BigEndian, ReadBytesExt};
        let offset = match cursor.read_u64::<BigEndian>() {
            Ok(o) => o,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad offset"),
        };
        let data = match SshBuf::read_string(&mut cursor) {
            Ok(d) => d,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad data"),
        };

        let (path, flags) = match self.open_files.get(&handle) {
            Some(entry) => entry,
            None => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Invalid handle"),
        };

        if flags & SSH_FXF_WRITE == 0 {
            return build_sftp_status(
                pkt.request_id,
                SSH_FX_PERMISSION_DENIED,
                "Not opened for writing",
            );
        }

        use std::io::{Seek, SeekFrom, Write};
        let open_result = std::fs::OpenOptions::new()
            .write(true)
            .create(flags & SSH_FXF_CREAT != 0)
            .truncate(flags & SSH_FXF_TRUNC != 0)
            .open(path);

        match open_result {
            Ok(mut file) => {
                if file.seek(SeekFrom::Start(offset)).is_err() {
                    return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Seek failed");
                }
                match file.write_all(&data) {
                    Ok(()) => build_sftp_status(pkt.request_id, SSH_FX_OK, "OK"),
                    Err(_) => {
                        build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Write error")
                    }
                }
            }
            Err(_) => {
                build_sftp_status(pkt.request_id, SSH_FX_PERMISSION_DENIED, "Cannot open")
            }
        }
    }

    fn handle_mkdir(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => {
                return build_sftp_status(pkt.request_id, SSH_FX_PERMISSION_DENIED, "Bad path")
            }
        };

        match std::fs::create_dir(&resolved) {
            Ok(()) => build_sftp_status(pkt.request_id, SSH_FX_OK, "OK"),
            Err(_) => build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "mkdir failed"),
        }
    }

    fn handle_rmdir(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => {
                return build_sftp_status(pkt.request_id, SSH_FX_PERMISSION_DENIED, "Bad path")
            }
        };

        match std::fs::remove_dir(&resolved) {
            Ok(()) => build_sftp_status(pkt.request_id, SSH_FX_OK, "OK"),
            Err(_) => build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "rmdir failed"),
        }
    }

    fn handle_remove(&self, pkt: &SftpPacket) -> SftpPacket {
        let mut cursor = Cursor::new(pkt.data.as_slice());
        let path_str = match SshBuf::read_utf8(&mut cursor) {
            Ok(p) => p,
            Err(_) => return build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "Bad path"),
        };

        let resolved = match self.resolve_path(&path_str) {
            Ok(p) => p,
            Err(_) => {
                return build_sftp_status(pkt.request_id, SSH_FX_PERMISSION_DENIED, "Bad path")
            }
        };

        match std::fs::remove_file(&resolved) {
            Ok(()) => build_sftp_status(pkt.request_id, SSH_FX_OK, "OK"),
            Err(_) => build_sftp_status(pkt.request_id, SSH_FX_FAILURE, "remove failed"),
        }
    }
}

/// Normalize a path by resolving `.` and `..` components without filesystem access.
fn normalize_path(path: &std::path::Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                components.pop();
            }
            std::path::Component::CurDir => {}
            c => components.push(c),
        }
    }
    components.iter().collect()
}

/// Convert std::fs::Metadata into SFTP FileAttrs.
fn metadata_to_attrs(meta: &std::fs::Metadata) -> FileAttrs {
    use std::os::unix::fs::MetadataExt;

    let flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS;
    let mut attrs = FileAttrs {
        flags,
        size: Some(meta.len()),
        permissions: Some(meta.mode()),
        ..Default::default()
    };

    attrs.uid = Some(meta.uid());
    attrs.gid = Some(meta.gid());
    attrs.flags |= SSH_FILEXFER_ATTR_UIDGID;

    attrs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sftp_packet_roundtrip() {
        let pkt = SftpPacket::new(SSH_FXP_OPEN, 42, vec![1, 2, 3]);
        let encoded = pkt.encode();

        // Skip the 4-byte length prefix for decode
        let decoded = SftpPacket::decode(&encoded[4..]).unwrap();
        assert_eq!(decoded.packet_type, SSH_FXP_OPEN);
        assert_eq!(decoded.request_id, 42);
        assert_eq!(decoded.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_file_attrs_encode_decode() {
        let attrs = FileAttrs {
            flags: SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS,
            size: Some(1024),
            permissions: Some(0o755),
            ..Default::default()
        };

        let encoded = attrs.encode();
        let mut cursor = Cursor::new(encoded.as_slice());
        let decoded = FileAttrs::decode(&mut cursor).unwrap();
        assert_eq!(decoded.size, Some(1024));
        assert_eq!(decoded.permissions, Some(0o755));
    }

    #[test]
    fn test_sftp_handler_path_traversal() {
        let handler = SftpHandler::new(PathBuf::from("/tmp/sftp_test_root"));
        // Attempting to escape root should fail
        let result = handler.resolve_path("../../etc/passwd");
        assert!(result.is_err());
    }
}

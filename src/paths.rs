//! Filesystem layout for swayshare.
//!
//! Three distinct trees are used, with deliberately different lifetimes:
//!
//! * config (`~/.config/swayshare`) — peers, persisted by the user.
//! * data (`~/.local/share/swayshare`) — the long-lived TLS identity, so a
//!   remote peer can pin the same server key between sessions.
//! * runtime (`$XDG_RUNTIME_DIR/swayshare`) — sockets and the generated
//!   wayvnc config holding the session password. Never persisted across boots.

use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("cannot determine XDG config directory")?;
    Ok(base.join("swayshare"))
}

pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

pub fn data_dir() -> Result<PathBuf> {
    let base = dirs::data_dir().context("cannot determine XDG data directory")?;
    Ok(base.join("swayshare"))
}

/// Longest directory path that can still hold our socket names.
///
/// `sockaddr_un.sun_path` is 108 bytes including the terminator, and the
/// longest name we put in here is `control.sock`.
const MAX_RUNTIME_DIR_LEN: usize = 107 - "/control.sock".len();

/// The private runtime directory, created 0700 on first use.
///
/// We deliberately refuse to fall back to a world-readable `/tmp` path: the
/// generated wayvnc config in here contains the session password.
pub fn runtime_dir() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR").context(
        "XDG_RUNTIME_DIR is not set; swayshare needs a private runtime directory \
         for its sockets and session credentials",
    )?;
    let dir = PathBuf::from(base).join("swayshare");
    // Checked up front: a path over the limit fails deep inside bind(2) with
    // an opaque message, and it would do so for wayvnc too.
    let len = dir.as_os_str().as_encoded_bytes().len();
    if len > MAX_RUNTIME_DIR_LEN {
        bail!(
            "XDG_RUNTIME_DIR is too long: {} would need {len} bytes, but unix \
             sockets allow at most {MAX_RUNTIME_DIR_LEN} for the directory",
            dir.display()
        );
    }
    ensure_private_dir(&dir)?;
    Ok(dir)
}

pub fn control_socket() -> Result<PathBuf> {
    Ok(runtime_dir()?.join("control.sock"))
}

/// Create `dir` if missing and force its mode to 0700.
///
/// The mode is re-applied even when the directory already exists, so a
/// previously loosened directory is tightened rather than trusted.
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let meta = fs::metadata(dir)?;
    if !meta.is_dir() {
        bail!("{} exists but is not a directory", dir.display());
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("setting 0700 on {}", dir.display()))?;
    Ok(())
}

/// Write `contents` to `path` with mode 0600, truncating any existing file.
///
/// The mode is passed to `open(2)` so the bytes are never momentarily visible
/// under a laxer mode.
pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {} for writing", path.display()))?;
    // An existing file keeps its old mode, so set it explicitly too.
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    f.flush()?;
    Ok(())
}

/// Replace `path` atomically, so a reader never observes a half-written file.
pub fn write_atomic(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path.parent().context("path has no parent directory")?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("swayshare")
    ));
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(contents.as_bytes())?;
        f.flush()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// Best-effort removal; a missing file is not an error.
pub fn remove_if_present(path: &Path) {
    let _ = fs::remove_file(path);
}

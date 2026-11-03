//! The protocol-speaking core of the KeySeal helper: link parsing, origin
//! rules, trust on first use, the manifest, the job client, SignedAttributes
//! checks, PKCS#11 signing with the CNG fallback on Windows, and the sign
//! and enrol state machine that the headless CLI and the GUI share. Section
//! numbers refer to `spec/protocol-v1.md`.

use std::io::Write;
use std::path::{Path, PathBuf};

pub mod catalogue;
pub mod cms;
#[cfg(any(windows, test))]
pub mod cng;
pub mod doctor;
pub mod document;
pub mod flow;
pub mod install;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod manifest;
pub mod modules;
pub mod origin;
pub mod preferences;
pub mod protocol;
pub mod token;
pub mod trust;
pub mod update;
pub mod worker;

/// The helper's version, sent as `X-KeySeal-Version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where the helper keeps the trust store and manifest cache:
/// `KEYSEAL_CONFIG_DIR`, or `keyseal` in the platform config directory.
pub fn config_dir() -> Result<PathBuf, String> {
    if let Some(dir) = std::env::var_os("KEYSEAL_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    dirs::config_dir()
        .map(|dir| dir.join("keyseal"))
        .ok_or_else(|| "This system has no config directory for the helper.".into())
}

/// Creates `dir` and its missing parents for the config directory, which
/// holds the trust store, the log and downloaded updates: on Unix readable
/// only by the user (0700), tightening `dir` when it already exists.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700).create(dir)?;
        // A folder the user doesn't own, named by KEYSEAL_CONFIG_DIR, stays as it is.
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        Ok(())
    }
    #[cfg(not(unix))]
    builder.create(dir)
}

/// Writes a file in the config directory: on Unix readable only by the
/// user (0600), tightening a file that already exists.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn config_files_are_private() {
        let dir = std::env::temp_dir().join(format!("keyseal-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("trust.json");
        std::fs::write(&file, b"old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let nested = dir.join("manifests");

        create_private_dir(&dir).unwrap();
        create_private_dir(&nested).unwrap();
        write_private(&file, b"new").unwrap();
        write_private(&nested.join("a.json"), b"{}").unwrap();

        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&nested), 0o700);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&nested.join("a.json")), 0o600);
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

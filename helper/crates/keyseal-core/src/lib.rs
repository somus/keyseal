//! The protocol-speaking core of the KeySeal helper: link parsing, origin
//! rules, trust on first use, the manifest, the job client, SignedAttributes
//! checks, PKCS#11 signing with the CNG fallback on Windows, and the sign
//! and enrol state machine that the headless CLI and the GUI share. Section
//! numbers refer to `spec/protocol-v1.md`.

use std::path::PathBuf;

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

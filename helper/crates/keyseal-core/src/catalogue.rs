//! The driver catalogue (`catalogue/README.md`): which PKCS#11 module to
//! load for a plugged-in token, keyed on USB vendor and product id. The
//! helper embeds the catalogue it was built with and keeps the newest
//! verified download in `<config dir>/catalogue`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use nusb::MaybeFuture;
use serde::Deserialize;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

use crate::update::key_id;

/// Public keys that may sign the catalogue, as raw Ed25519 bytes.
/// Placeholder: replace before release with the maintainer's catalogue keys
/// (catalogue/README.md, Signing). Until then only the embedded catalogue is used and
/// [`refresh`] downloads nothing.
pub const CATALOGUE_KEYS: &[[u8; 32]] = &[[0; 32]];

/// Where the catalogue is published; the signature is at the same URL with
/// `.sig` appended: the asset of the KeySeal GitHub release tagged
/// `catalogue`.
pub const CATALOGUE_URL: &str =
    "https://github.com/somus/keyseal/releases/download/catalogue/catalogue.json";

/// The catalogue this helper was built with. Not signature-checked: it is
/// part of the binary.
const EMBEDDED: &str = include_str!("../../../../catalogue/catalogue.json");

const MAX_BYTES: u64 = 1024 * 1024;
const FETCH_BUDGET: Duration = Duration::from_secs(5);
const FETCH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalogue {
    pub version: u64,
    pub generated_at: String,
    pub tokens: Vec<Token>,
}

#[derive(Debug, Deserialize)]
pub struct Token {
    pub name: String,
    pub vendor: String,
    pub usb: Vec<UsbId>,
    /// Keyed by platform id ([`platform`]); paths in the order they are tried.
    pub modules: BTreeMap<String, Vec<String>>,
    pub notes: Option<String>,
    #[serde(default)]
    pub cng: bool,
}

/// Lowercase 4-digit hex.
#[derive(Debug, Deserialize)]
pub struct UsbId {
    pub vid: String,
    pub pid: String,
}

/// Which copy of the catalogue is in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Embedded,
    Fetched,
}

/// A connected USB device.
#[derive(Clone, Debug)]
pub struct UsbDevice {
    pub vid: u16,
    pub pid: u16,
    pub product: Option<String>,
}

/// `catalogue.json.sig`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureFile {
    key_id: String,
    signature: String,
}

impl Catalogue {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| format!("The driver catalogue is malformed: {e}"))
    }

    /// The token a device belongs to.
    pub fn token_for(&self, device: &UsbDevice) -> Option<&Token> {
        let (vid, pid) = (format!("{:04x}", device.vid), format!("{:04x}", device.pid));
        self.tokens
            .iter()
            .find(|token| token.usb.iter().any(|id| id.vid == vid && id.pid == pid))
    }
}

impl Token {
    /// Module paths for `platform`, in order.
    pub fn modules_for(&self, platform: &str) -> &[String] {
        self.modules.get(platform).map_or(&[], Vec::as_slice)
    }
}

/// The catalogue's platform id for this build, if it has one.
pub fn platform() -> Option<&'static str> {
    platform_of(std::env::consts::OS, std::env::consts::ARCH)
}

fn platform_of(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("macos-arm64"),
        ("macos", "x86_64") => Some("macos-x64"),
        ("windows", "x86_64") => Some("windows-x64"),
        ("linux", "x86_64") => Some("linux-x64"),
        _ => None,
    }
}

/// Connected USB devices.
pub fn usb_devices() -> Result<Vec<UsbDevice>, String> {
    let devices = nusb::list_devices()
        .wait()
        .map_err(|e| format!("Couldn't list USB devices: {e}"))?;
    Ok(devices
        .map(|device| UsbDevice {
            vid: device.vendor_id(),
            pid: device.product_id(),
            product: device.product_string().map(str::to_owned),
        })
        .collect())
}

/// The catalogue, if `signature` from one of `keys` verifies strictly over
/// exactly `catalogue`.
fn verify(catalogue: &[u8], signature: &[u8], keys: &[[u8; 32]]) -> Result<Catalogue, String> {
    let file: SignatureFile = serde_json::from_slice(signature)
        .map_err(|e| format!("The driver catalogue signature is malformed: {e}"))?;
    let key = keys
        .iter()
        .find(|key| key_id(key) == file.key_id)
        .ok_or("The driver catalogue is signed by an unknown key.")?;
    let verified = STANDARD
        .decode(&file.signature)
        .ok()
        .and_then(|bytes| Signature::from_slice(&bytes).ok())
        .zip(VerifyingKey::from_bytes(key).ok())
        .is_some_and(|(signature, key)| key.verify_strict(catalogue, &signature).is_ok());
    if !verified {
        return Err("The driver catalogue signature doesn't verify.".into());
    }
    Catalogue::parse(catalogue)
}

/// The catalogue built into the helper.
pub fn embedded() -> Catalogue {
    Catalogue::parse(EMBEDDED.as_bytes()).expect("the embedded catalogue parses")
}

fn cache_dir() -> Option<PathBuf> {
    crate::config_dir().ok().map(|dir| dir.join("catalogue"))
}

/// The cached download, if it is still there and verifies.
pub fn load() -> Option<Catalogue> {
    load_from(&cache_dir()?, CATALOGUE_KEYS)
}

fn load_from(dir: &Path, keys: &[[u8; 32]]) -> Option<Catalogue> {
    let catalogue = std::fs::read(dir.join("catalogue.json")).ok()?;
    let signature = std::fs::read(dir.join("catalogue.json.sig")).ok()?;
    verify(&catalogue, &signature, keys).ok()
}

/// The newer of the cached download and the embedded catalogue.
pub fn current() -> (Catalogue, Source) {
    let embedded = embedded();
    match load() {
        Some(fetched) if fetched.version >= embedded.version => (fetched, Source::Fetched),
        _ => (embedded, Source::Embedded),
    }
}

/// Downloads the catalogue at `url` and its signature, verifies them and
/// replaces the cache.
pub fn fetch(url: &str) -> Result<Catalogue, String> {
    let dir = cache_dir().ok_or("This system has no config directory for the helper.")?;
    let deadline = Instant::now() + FETCH_BUDGET;
    // The system trust store, as every other fetch the helper makes.
    let tls = TlsConfig::builder()
        .root_certs(RootCerts::PlatformVerifier)
        .build();
    let agent: Agent = Agent::config_builder()
        .https_only(true)
        .tls_config(tls)
        .user_agent(format!("keyseal/{}", crate::VERSION))
        .build()
        .into();
    let catalogue = get(&agent, url, deadline)?;
    let signature = get(&agent, &format!("{url}.sig"), deadline)?;
    store(&dir, &catalogue, &signature, CATALOGUE_KEYS)
}

/// [`fetch`]es [`CATALOGUE_URL`] unless it was tried in the last day.
/// `None` when it wasn't due. While [`CATALOGUE_KEYS`] is the placeholder
/// nothing is fetched, so the helper never contacts a URL the project may
/// not own, and that is reported once per process.
pub fn refresh() -> Option<Result<Catalogue, String>> {
    static UNPINNED_REPORTED: AtomicBool = AtomicBool::new(false);
    if CATALOGUE_KEYS == [[0; 32]] {
        return (!UNPINNED_REPORTED.swap(true, Ordering::Relaxed)).then(|| {
            Err("no catalogue key is pinned in this build, so nothing was downloaded.".into())
        });
    }
    let stamp = cache_dir()?.join("checked");
    let due = std::fs::metadata(&stamp)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|checked| SystemTime::now().duration_since(checked).ok())
        .is_none_or(|age| age >= FETCH_INTERVAL);
    if !due {
        return None;
    }
    let result = fetch(CATALOGUE_URL);
    if let Some(dir) = stamp.parent() {
        let _ = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&stamp, b""));
    }
    Some(result)
}

/// Verifies, refuses a version older than the cached or embedded one, and
/// writes both files beside the cache before renaming them into place.
fn store(
    dir: &Path,
    catalogue: &[u8],
    signature: &[u8],
    keys: &[[u8; 32]],
) -> Result<Catalogue, String> {
    let verified = verify(catalogue, signature, keys)?;
    let held = load_from(dir, keys)
        .map_or(0, |cached| cached.version)
        .max(embedded().version);
    if verified.version < held {
        return Err(format!(
            "The driver catalogue has version {}, older than version {held} already held.",
            verified.version
        ));
    }
    let error = |e: std::io::Error| format!("Couldn't write {}: {e}", dir.display());
    std::fs::create_dir_all(dir).map_err(error)?;
    for (name, bytes) in [
        ("catalogue.json", catalogue),
        ("catalogue.json.sig", signature),
    ] {
        let temporary = dir.join(format!("{name}.tmp"));
        std::fs::write(&temporary, bytes).map_err(error)?;
        std::fs::rename(&temporary, dir.join(name)).map_err(error)?;
    }
    Ok(verified)
}

/// A `200` body of at most [`MAX_BYTES`], before `deadline`.
fn get(agent: &Agent, url: &str, deadline: Instant) -> Result<Vec<u8>, String> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or("The driver catalogue download ran out of time.")?;
    let failed = |e: ureq::Error| format!("Couldn't download {url}: {e}");
    agent
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .map_err(failed)?
        .body_mut()
        .with_config()
        .limit(MAX_BYTES)
        .read_to_vec()
        .map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keyseal-catalogue-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn catalogue(version: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": version,
            "generatedAt": "2026-10-22T00:00:00Z",
            "tokens": [{
                "name": "Example Token",
                "vendor": "Example Vendor",
                "usb": [{ "vid": "abcd", "pid": "0001" }],
                "modules": {
                    "macos-arm64": ["/usr/local/lib/libexample.dylib"],
                    "linux-x64": ["/usr/lib/libexample.so", "/usr/lib64/libexample.so"]
                }
            }]
        }))
        .unwrap()
    }

    fn sign(key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "keyId": key_id(&key.verifying_key().to_bytes()),
            "signature": STANDARD.encode(key.sign(bytes).to_bytes()),
        }))
        .unwrap()
    }

    #[test]
    fn verifies_with_a_pinned_key_only() {
        let (key, stranger) = (
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
        );
        let pinned = [key.verifying_key().to_bytes()];
        let bytes = catalogue(100);

        let parsed = verify(&bytes, &sign(&key, &bytes), &pinned).unwrap();
        assert_eq!(parsed.version, 100);
        assert_eq!(parsed.tokens[0].name, "Example Token");

        assert!(verify(&bytes, &sign(&stranger, &bytes), &pinned).is_err());
        assert!(verify(&bytes, b"", &pinned).is_err());
        let mut tampered = bytes.clone();
        tampered[12] ^= 1;
        assert!(verify(&tampered, &sign(&key, &bytes), &pinned).is_err());
        assert!(verify(&bytes, &sign(&key, &bytes), CATALOGUE_KEYS).is_err());
    }

    #[test]
    fn stores_and_refuses_a_rollback_or_an_unsigned_file() {
        let dir = temp_dir("store");
        let key = SigningKey::from_bytes(&[1; 32]);
        let pinned = [key.verifying_key().to_bytes()];

        let unsigned = catalogue(100);
        assert!(store(&dir, &unsigned, b"", &pinned).is_err());
        assert!(load_from(&dir, &pinned).is_none());

        let newer = catalogue(101);
        store(&dir, &newer, &sign(&key, &newer), &pinned).unwrap();
        assert_eq!(load_from(&dir, &pinned).unwrap().version, 101);

        let older = catalogue(100);
        let error = store(&dir, &older, &sign(&key, &older), &pinned).unwrap_err();
        assert!(error.contains("older than version 101"), "{error}");
        assert_eq!(load_from(&dir, &pinned).unwrap().version, 101);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_cache_is_ignored() {
        let dir = temp_dir("tampered");
        let key = SigningKey::from_bytes(&[1; 32]);
        let pinned = [key.verifying_key().to_bytes()];
        let bytes = catalogue(100);
        store(&dir, &bytes, &sign(&key, &bytes), &pinned).unwrap();
        std::fs::write(dir.join("catalogue.json"), catalogue(102)).unwrap();
        assert!(load_from(&dir, &pinned).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn platform_ids() {
        assert_eq!(platform_of("macos", "aarch64"), Some("macos-arm64"));
        assert_eq!(platform_of("macos", "x86_64"), Some("macos-x64"));
        assert_eq!(platform_of("windows", "x86_64"), Some("windows-x64"));
        assert_eq!(platform_of("linux", "x86_64"), Some("linux-x64"));
        assert_eq!(platform_of("linux", "aarch64"), None);
        assert_eq!(platform_of("windows", "aarch64"), None);

        let parsed = Catalogue::parse(&catalogue(1)).unwrap();
        let token = &parsed.tokens[0];
        assert_eq!(
            token.modules_for("linux-x64"),
            ["/usr/lib/libexample.so", "/usr/lib64/libexample.so"]
        );
        assert!(token.modules_for("windows-x64").is_empty());
    }

    #[test]
    fn matches_devices_by_usb_id() {
        let parsed = Catalogue::parse(&catalogue(1)).unwrap();
        let device = |vid, pid| UsbDevice {
            vid,
            pid,
            product: None,
        };
        assert_eq!(
            parsed.token_for(&device(0xabcd, 0x0001)).unwrap().name,
            "Example Token"
        );
        assert!(parsed.token_for(&device(0xabcd, 0x0002)).is_none());
        assert!(parsed.token_for(&device(0x0001, 0xabcd)).is_none());

        let embedded = embedded();
        assert_eq!(
            embedded.token_for(&device(0x096e, 0x080a)).unwrap().name,
            "ePass2003"
        );
    }

    /// Every job refreshes; an unpinned build says why once per process.
    #[test]
    fn reports_the_unpinned_key_once() {
        assert_eq!(CATALOGUE_KEYS, [[0; 32]]);
        assert!(refresh().is_some_and(|result| result.is_err()));
        assert!(refresh().is_none());
    }
}

//! Updates (section 13). After a job the helper reads the latest release's
//! manifest, at most daily or at once after a `426` or a `minHelperVersion`
//! refusal, downloads the newer build for its platform, checks it against
//! the manifest and stages it in the config directory. The next launch
//! verifies the staged build again, swaps it in and runs it with the same
//! arguments. Any failure leaves the current helper to do the job.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, VerifyingKey};
use semver::Version;
use serde::Deserialize;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

use crate::token::sha256_hex;

/// Where releases are published. The release workflow refuses to run unless
/// this names the repository it runs in.
pub const RELEASES: &str = "https://github.com/somus/keyseal/releases/latest/download";

/// The maintainers' Ed25519 public keys, raw. The placeholder below matches
/// no key, so every update fails until the real keys are pinned (see
/// `helper/packaging/sign-manifest.md`).
pub const RELEASE_KEYS: &[[u8; 32]] = &[[0; 32]];

/// Distinct pinned keys that must sign a manifest. This becomes 2 when a
/// second maintainer exists.
pub const THRESHOLD: usize = 1;

/// This build's platform id in the manifest.
pub const PLATFORM: Option<&str> = if cfg!(target_os = "macos") {
    Some("macos-universal")
} else if cfg!(all(windows, target_arch = "x86_64")) {
    Some("windows-x64")
} else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
    Some("linux-x64")
} else {
    None
};

const MANIFEST: &str = "keyseal-update.json";
const SIGNATURES: &str = "keyseal-update.json.sig";
/// In the config directory: when the last check ran, in Unix seconds, and
/// on a second line the last version a [`take_notice`] was given for.
const STAMP: &str = "update-checked";
/// In the config directory: the staged release.
const STAGED: &str = "update";
/// Set on the relaunched helper, so it doesn't apply again.
const RELAUNCHED: &str = "KEYSEAL_UPDATED";
const CHECK_EVERY: Duration = Duration::from_secs(24 * 60 * 60);
const MANIFEST_BUDGET: Duration = Duration::from_secs(5);
const DOWNLOAD_BUDGET: Duration = Duration::from_secs(300);
const MAX_MANIFEST: u64 = 64 * 1024;
const MAX_ASSET: u64 = 64 * 1024 * 1024;

#[cfg(target_os = "macos")]
const APP: &str = "KeySeal.app";

static CHECK_SOON: AtomicBool = AtomicBool::new(false);
/// An update the user has to install themselves, for the windows to show.
static NOTICE: Mutex<Option<String>> = Mutex::new(None);

/// `keyseal-update.json`.
#[derive(Debug, Deserialize)]
pub struct UpdateManifest {
    pub format: u64,
    pub version: String,
    /// Keyed by platform id: `macos-universal`, `windows-x64`, `linux-x64`.
    pub platforms: BTreeMap<String, PlatformFile>,
}

#[derive(Debug, Deserialize)]
pub struct PlatformFile {
    pub file: String,
    pub sha256: String,
}

/// `keyseal-update.json.sig`.
#[derive(Deserialize)]
struct SignatureFile {
    signatures: Vec<SignatureEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignatureEntry {
    key_id: String,
    signature: String,
}

/// The `keyId` of a public key: lowercase hex SHA-256 of its 32 raw bytes.
pub fn key_id(key: &[u8; 32]) -> String {
    sha256_hex(key)
}

/// The manifest, if signatures from at least `threshold` distinct keys of
/// `keys` verify strictly over exactly `manifest`. A `keyId` listed twice
/// makes the file malformed; signatures from unknown keys, and ones that
/// don't verify, are ignored.
pub fn verify_threshold(
    manifest: &[u8],
    signatures: &[u8],
    keys: &[[u8; 32]],
    threshold: usize,
) -> Result<UpdateManifest, String> {
    if threshold == 0 {
        return Err("The update threshold must be at least 1.".into());
    }
    let file: SignatureFile = serde_json::from_slice(signatures)
        .map_err(|e| format!("The update signatures are malformed: {e}"))?;
    let mut seen = BTreeSet::new();
    let mut verified = BTreeSet::new();
    for entry in &file.signatures {
        if !seen.insert(entry.key_id.as_str()) {
            return Err(format!(
                "The update signatures list key {} twice.",
                entry.key_id
            ));
        }
        let Some(key) = keys.iter().find(|key| key_id(key) == entry.key_id) else {
            continue;
        };
        let Ok(bytes) = STANDARD.decode(&entry.signature) else {
            continue;
        };
        let (Ok(signature), Ok(verifying)) =
            (Signature::from_slice(&bytes), VerifyingKey::from_bytes(key))
        else {
            continue;
        };
        if verifying.verify_strict(manifest, &signature).is_ok() {
            verified.insert(*key);
        }
    }
    if verified.len() < threshold {
        return Err(format!(
            "The update manifest has {} of the {threshold} signatures it needs.",
            verified.len()
        ));
    }
    let manifest: UpdateManifest = serde_json::from_slice(manifest)
        .map_err(|e| format!("The update manifest is malformed: {e}"))?;
    if manifest.format != 1 {
        return Err(format!(
            "The update manifest has format {}; this helper reads format 1.",
            manifest.format
        ));
    }
    Ok(manifest)
}

/// What a verified manifest offers this platform: its version and file, or
/// `None` when it isn't newer than `current` or has no build for `platform`.
fn newer(
    manifest: &[u8],
    signatures: &[u8],
    keys: &[[u8; 32]],
    threshold: usize,
    platform: &str,
    current: &str,
) -> Result<Option<(String, PlatformFile)>, String> {
    let mut manifest = verify_threshold(manifest, signatures, keys, threshold)?;
    let offered = Version::parse(&manifest.version)
        .map_err(|e| format!("The update manifest's version is invalid: {e}"))?;
    let current = Version::parse(current).map_err(|e| e.to_string())?;
    if offered <= current {
        return Ok(None);
    }
    let Some(file) = manifest.platforms.remove(platform) else {
        return Ok(None);
    };
    // The name becomes part of a URL and a path.
    let plain = !file.file.starts_with('.')
        && !file.file.is_empty()
        && file
            .file
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c));
    if !plain {
        return Err(format!(
            "The update manifest names an invalid file: {}",
            file.file
        ));
    }
    Ok(Some((manifest.version, file)))
}

fn check_hash(bytes: &[u8], file: &PlatformFile) -> Result<(), String> {
    if !sha256_hex(bytes).eq_ignore_ascii_case(&file.sha256) {
        return Err(format!("{} doesn't match the update manifest.", file.file));
    }
    Ok(())
}

/// Whether a check is due at `now`: none recorded, the last one a day or
/// more ago, or one recorded in the future because the clock moved back.
fn check_due(stamp: &Path, now: SystemTime) -> bool {
    let Some(last) = read_stamp(stamp).0 else {
        return true;
    };
    now.duration_since(UNIX_EPOCH + Duration::from_secs(last))
        .map_or(true, |age| age >= CHECK_EVERY)
}

fn record_check(stamp: &Path, now: SystemTime) {
    let seconds = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    write_stamp(stamp, seconds.as_secs(), &read_stamp(stamp).1);
}

/// The stamp's two lines: when the last check ran and the version last
/// noticed.
fn read_stamp(stamp: &Path) -> (Option<u64>, String) {
    let text = std::fs::read_to_string(stamp).unwrap_or_default();
    let mut lines = text.lines().map(str::trim);
    let checked = lines.next().and_then(|line| line.parse().ok());
    (checked, lines.next().unwrap_or_default().to_owned())
}

fn write_stamp(stamp: &Path, checked: u64, noticed: &str) {
    let _ = std::fs::write(stamp, format!("{checked}\n{noticed}\n"));
}

fn fetch(agent: &Agent, url: &str, limit: u64, deadline: Instant) -> Result<Vec<u8>, String> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or("The update check ran out of time.")?;
    agent
        .get(url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .and_then(|mut response| response.body_mut().with_config().limit(limit).read_to_vec())
        .map_err(|e| format!("{url}: {e}"))
}

/// Reads the manifest at `base`, and if it offers a newer build for
/// `platform`, downloads it, checks it and stages it in `dir`. The version
/// staged, if any.
fn check_and_stage(
    base: &str,
    dir: &Path,
    keys: &[[u8; 32]],
    threshold: usize,
    platform: &str,
    current: &str,
) -> Result<Option<String>, String> {
    // Releases are served over https; a redirect to plain http is refused,
    // although the signed manifest and hashes would catch tampering anyway.
    // Tests serve updates from a local http server.
    let agent: Agent = Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .https_only(base.starts_with("https://"))
        .user_agent(format!("keyseal/{}", crate::VERSION))
        .build()
        .into();
    let base = base.trim_end_matches('/');
    let deadline = Instant::now() + MANIFEST_BUDGET;
    let manifest = fetch(
        &agent,
        &format!("{base}/{MANIFEST}"),
        MAX_MANIFEST,
        deadline,
    )?;
    let signatures = fetch(
        &agent,
        &format!("{base}/{SIGNATURES}"),
        MAX_MANIFEST,
        deadline,
    )?;
    let Some((version, file)) = newer(&manifest, &signatures, keys, threshold, platform, current)?
    else {
        return Ok(None);
    };
    let asset = fetch(
        &agent,
        &format!("{base}/{}", file.file),
        MAX_ASSET,
        Instant::now() + DOWNLOAD_BUDGET,
    )?;
    check_hash(&asset, &file)?;
    // Written beside `dir` and renamed into place, so a launch never sees
    // half a release.
    let temp = dir.with_extension(format!("tmp-{}", std::process::id()));
    let staged = (|| {
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp)?;
        std::fs::write(temp.join(MANIFEST), &manifest)?;
        std::fs::write(temp.join(SIGNATURES), &signatures)?;
        std::fs::write(temp.join(&file.file), &asset)?;
        let _ = std::fs::remove_dir_all(dir);
        std::fs::rename(&temp, dir)
    })();
    if let Err(error) = staged {
        let _ = std::fs::remove_dir_all(&temp);
        return Err(format!("Couldn't stage the update: {error}"));
    }
    Ok(Some(version))
}

/// Takes the release staged in `dir`, verifies it again and installs the
/// verified bytes over the helper at `exe`, or with `replace` false only
/// [`keep`]s them. The version installed, or `None` when nothing is
/// staged. The staged release is gone afterwards either way.
fn apply_staged(
    dir: &Path,
    exe: &Path,
    replace: bool,
    keys: &[[u8; 32]],
    threshold: usize,
    platform: &str,
    current: &str,
) -> Result<Option<String>, String> {
    // Renaming it first means one launch applies it when two start at once.
    let taken = dir.with_extension(format!("applying-{}", std::process::id()));
    if std::fs::rename(dir, &taken).is_err() {
        return Ok(None);
    }
    let result = (|| {
        let read = |name: &str| {
            std::fs::read(taken.join(name))
                .map_err(|e| format!("The staged update is incomplete: {e}"))
        };
        let (manifest, signatures) = (read(MANIFEST)?, read(SIGNATURES)?);
        let Some((version, file)) =
            newer(&manifest, &signatures, keys, threshold, platform, current)?
        else {
            return Ok(None);
        };
        let asset = read(&file.file)?;
        check_hash(&asset, &file)?;
        let config = dir.parent().ok_or("The staged update has no folder.")?;
        if !replace {
            return Err(keep(&asset, exe, &version, config)?);
        }
        #[cfg(target_os = "macos")]
        install_bundle(&asset, exe)?;
        #[cfg(not(target_os = "macos"))]
        install_binary(&asset, exe, &version, config)?;
        Ok(Some(version))
    })();
    let _ = std::fs::remove_dir_all(&taken);
    result
}

/// Replaces the app bundle around `exe` with the one in the zip `asset`,
/// unpacked beside it so the swap is a rename on one volume.
#[cfg(target_os = "macos")]
fn install_bundle(asset: &[u8], exe: &Path) -> Result<(), String> {
    let bundle = exe
        .ancestors()
        .nth(3)
        .filter(|path| path.extension().is_some_and(|ext| ext == "app"))
        .ok_or("The helper isn't running from its app bundle.")?;
    let folder = bundle.parent().ok_or("The app bundle has no folder.")?;
    let unpack = folder.join(format!(".keyseal-update-{}", std::process::id()));
    let result = (|| {
        std::fs::create_dir(&unpack).map_err(|e| e.to_string())?;
        let zip = unpack.join("update.zip");
        std::fs::write(&zip, asset).map_err(|e| e.to_string())?;
        let unpacked = Command::new("/usr/bin/ditto")
            .args(["-x", "-k"])
            .arg(&zip)
            .arg(&unpack)
            .status()
            .is_ok_and(|status| status.success());
        let new = unpack.join(APP);
        if !unpacked || !new.join("Contents/MacOS/keyseal").is_file() {
            return Err("The update didn't unpack.".to_string());
        }
        let old = unpack.join("previous.app");
        std::fs::rename(bundle, &old).map_err(|e| e.to_string())?;
        if let Err(error) = std::fs::rename(&new, bundle) {
            let _ = std::fs::rename(&old, bundle);
            return Err(error.to_string());
        }
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&unpack);
    result.map_err(|e| format!("Couldn't replace {}: {e}", bundle.display()))
}

/// Replaces the binary at `exe`. A running exe on Windows can be renamed
/// but not overwritten, so it moves aside and the next launch deletes it.
/// A Linux binary in a folder the user can't write (an AppImage there)
/// stays, and the new one is [`keep`]t.
#[cfg(any(not(target_os = "macos"), test))]
fn install_binary(asset: &[u8], exe: &Path, version: &str, config: &Path) -> Result<(), String> {
    let new = exe.with_extension(if cfg!(windows) { "new.exe" } else { "new" });
    if let Err(error) = std::fs::write(&new, asset) {
        let _ = std::fs::remove_file(&new);
        if cfg!(windows) || !unwritable(&error) {
            return Err(format!("Couldn't write {}: {error}", new.display()));
        }
        return Err(keep(asset, exe, version, config)?);
    }
    let swapped = make_executable(&new).and_then(|()| {
        if cfg!(windows) {
            let old = exe.with_extension("old.exe");
            let _ = std::fs::remove_file(&old);
            std::fs::rename(exe, &old)?;
            std::fs::rename(&new, exe).inspect_err(|_| {
                let _ = std::fs::rename(&old, exe);
            })
        } else {
            std::fs::rename(&new, exe)
        }
    });
    if let Err(error) = swapped {
        let _ = std::fs::remove_file(&new);
        return Err(format!("Couldn't replace {}: {error}", exe.display()));
    }
    Ok(())
}

/// Leaves the new build in `config` for the user to install over `exe`,
/// with a [`take_notice`] saying so the first time for each version. The
/// notice, for the log.
fn keep(asset: &[u8], exe: &Path, version: &str, config: &Path) -> Result<String, String> {
    let keep = config.join(format!("keyseal-{version}"));
    std::fs::write(&keep, asset)
        .and_then(|()| make_executable(&keep))
        .map_err(|e| e.to_string())?;
    let notice = format!(
        "KeySeal {version} is downloaded to {}. Install it over {} to update.",
        keep.display(),
        exe.display()
    );
    let stamp = config.join(STAMP);
    let (checked, noticed) = read_stamp(&stamp);
    if noticed != version {
        write_stamp(&stamp, checked.unwrap_or(0), version);
        *NOTICE.lock().unwrap_or_else(|e| e.into_inner()) = Some(notice.clone());
    }
    Ok(notice)
}

/// The folder of the helper is one the user can't write: owned by root, or
/// on a read-only file system.
#[cfg(any(not(target_os = "macos"), test))]
fn unwritable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
    )
}

fn make_executable(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    let _ = path;
    Ok(())
}

/// A `426` or a `minHelperVersion` refusal: the next check runs even if
/// one ran today.
pub fn check_soon() {
    CHECK_SOON.store(true, Ordering::Relaxed);
}

/// An update downloaded but left for the user to install, once.
pub fn take_notice() -> Option<String> {
    NOTICE.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// The file an update replaces, and whether it may. The Linux update is an
/// AppImage, so it replaces the AppImage the helper runs from (its
/// executable is inside the image's read-only mount) and never a deb or
/// tarball install. Elsewhere it replaces the executable.
fn install_target(appimage: Option<PathBuf>) -> Option<(PathBuf, bool)> {
    match appimage {
        Some(image) if cfg!(target_os = "linux") => Some((image, true)),
        _ => Some((std::env::current_exe().ok()?, !cfg!(target_os = "linux"))),
    }
}

/// On launch: installs a staged release and runs it with `args`, returning
/// its exit code. `None` means this helper carries on.
pub fn relaunch_if_staged(args: &[&str]) -> Option<ExitCode> {
    let (exe, replace) = install_target(std::env::var_os("APPIMAGE").map(PathBuf::from))?;
    if cfg!(windows) {
        let _ = std::fs::remove_file(exe.with_extension("old.exe"));
    }
    if std::env::var_os(RELAUNCHED).is_some() {
        return None;
    }
    let dir = crate::config_dir().ok()?.join(STAGED);
    let staged = apply_staged(
        &dir,
        &exe,
        replace,
        RELEASE_KEYS,
        THRESHOLD,
        PLATFORM?,
        crate::VERSION,
    );
    let version = match staged {
        Ok(version) => version?,
        Err(message) => {
            eprintln!("The update wasn't installed: {message}");
            return None;
        }
    };
    let mut command = Command::new(&exe);
    command.args(args).env(RELAUNCHED, "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        eprintln!("Couldn't start KeySeal {version}: {error}");
        None
    }
    #[cfg(not(unix))]
    match command.status() {
        Ok(status) => Some(ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(1),
        )),
        Err(error) => {
            eprintln!("Couldn't start KeySeal {version}: {error}");
            None
        }
    }
}

/// After a job: stages a newer release when a check is due or was asked
/// for. The GUI calls this on a background thread; headless runs skip it.
pub fn after_job() {
    if PLATFORM.is_none() || std::env::var("KEYSEAL_HEADLESS").is_ok_and(|v| v == "1") {
        return;
    }
    let forced = CHECK_SOON.swap(false, Ordering::Relaxed);
    if let Err(message) = check(forced) {
        eprintln!("Update check failed: {message}");
    }
}

/// `keyseal update`: checks now.
pub fn check_now() -> Result<(), String> {
    match check(true)? {
        Some(version) => {
            println!("KeySeal {version} is downloaded and installs the next time KeySeal starts.")
        }
        None => println!("KeySeal {} is up to date.", crate::VERSION),
    }
    Ok(())
}

fn check(forced: bool) -> Result<Option<String>, String> {
    let platform = PLATFORM.ok_or("There are no KeySeal updates for this platform.")?;
    let config = crate::config_dir()?;
    std::fs::create_dir_all(&config).map_err(|e| e.to_string())?;
    let stamp = config.join(STAMP);
    let now = SystemTime::now();
    if !forced && !check_due(&stamp, now) {
        return Ok(None);
    }
    record_check(&stamp, now);
    check_and_stage(
        RELEASES,
        &config.join(STAGED),
        RELEASE_KEYS,
        THRESHOLD,
        platform,
        crate::VERSION,
    )
}

/// `keyseal update verify <manifest> <signatures>`: what the release
/// workflow and maintainers run before publishing, with the pinned keys.
pub fn verify_files(manifest: &str, signatures: &str) -> Result<(), String> {
    let read = |path: &str| std::fs::read(path).map_err(|e| format!("{path}: {e}"));
    let verified = verify_threshold(
        &read(manifest)?,
        &read(signatures)?,
        RELEASE_KEYS,
        THRESHOLD,
    )?;
    println!(
        "KeySeal {} verified with {THRESHOLD} of {} keys.",
        verified.version,
        RELEASE_KEYS.len()
    );
    for (platform, file) in &verified.platforms {
        println!("{platform}  {}  {}", file.sha256, file.file);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const MANIFEST_BYTES: &[u8] = br#"{"format":1,"version":"1.4.0","platforms":{"macos-universal":{"file":"keyseal-helper-1.4.0-macos-universal.zip","sha256":"00"}}}"#;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    fn signatures(entries: &[(&SigningKey, &[u8])]) -> Vec<u8> {
        let entries: Vec<_> = entries
            .iter()
            .map(|(key, message)| {
                json!({
                    "keyId": key_id(&public(key)),
                    "signature": STANDARD.encode(key.sign(message).to_bytes()),
                })
            })
            .collect();
        serde_json::to_vec(&json!({ "signatures": entries })).unwrap()
    }

    /// A manifest offering `asset` as `file` for platform `test-x64`,
    /// listing `listed` as its hash, and its signatures by `keys`.
    fn release(
        version: &str,
        file: &str,
        listed: &str,
        keys: &[&SigningKey],
    ) -> (Vec<u8>, Vec<u8>) {
        let manifest = serde_json::to_vec(&json!({
            "format": 1,
            "version": version,
            "platforms": { "test-x64": { "file": file, "sha256": listed } },
        }))
        .unwrap();
        let entries: Vec<_> = keys.iter().map(|key| (*key, manifest.as_slice())).collect();
        let signed = signatures(&entries);
        (manifest, signed)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keyseal-update-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Serves `files` over HTTP on a free port; returns the base URL.
    fn serve(files: HashMap<String, Vec<u8>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut request)
                    .unwrap();
                let path = request
                    .split(' ')
                    .nth(1)
                    .unwrap_or("/")
                    .trim_start_matches('/');
                let (status, body) = match files.get(path) {
                    Some(body) => ("200 OK", body.clone()),
                    None => ("404 Not Found", Vec::new()),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
            }
        });
        base
    }

    #[test]
    fn accepts_a_threshold_of_pinned_keys() {
        let (a, b, c) = (signing_key(1), signing_key(2), signing_key(3));
        let pinned = [public(&a), public(&b), public(&c)];

        let one = signatures(&[(&a, MANIFEST_BYTES)]);
        let manifest = verify_threshold(MANIFEST_BYTES, &one, &pinned, 1).unwrap();
        assert_eq!(manifest.version, "1.4.0");
        assert_eq!(
            manifest.platforms["macos-universal"].file,
            "keyseal-helper-1.4.0-macos-universal.zip"
        );
        assert!(verify_threshold(MANIFEST_BYTES, &one, &pinned, 2).is_err());

        let two = signatures(&[(&a, MANIFEST_BYTES), (&c, MANIFEST_BYTES)]);
        assert!(verify_threshold(MANIFEST_BYTES, &two, &pinned, 2).is_ok());
        assert!(verify_threshold(MANIFEST_BYTES, &two, &pinned, 3).is_err());
    }

    #[test]
    fn rejects_duplicate_key_ids_and_ignores_unknown_or_bad_signatures() {
        let (a, b, stranger) = (signing_key(1), signing_key(2), signing_key(9));
        let pinned = [public(&a), public(&b)];

        let repeated = signatures(&[(&a, MANIFEST_BYTES), (&a, MANIFEST_BYTES)]);
        let error = verify_threshold(MANIFEST_BYTES, &repeated, &pinned, 1).unwrap_err();
        assert!(error.contains("twice"), "{error}");

        let unknown = signatures(&[(&a, MANIFEST_BYTES), (&stranger, MANIFEST_BYTES)]);
        assert!(verify_threshold(MANIFEST_BYTES, &unknown, &pinned, 2).is_err());
        assert!(verify_threshold(MANIFEST_BYTES, &unknown, &pinned, 1).is_ok());

        let other_bytes = signatures(&[(&a, MANIFEST_BYTES), (&b, b"something else")]);
        assert!(verify_threshold(MANIFEST_BYTES, &other_bytes, &pinned, 2).is_err());

        let mut tampered = MANIFEST_BYTES.to_vec();
        tampered[30] ^= 1;
        let signed = signatures(&[(&a, MANIFEST_BYTES)]);
        assert!(verify_threshold(&tampered, &signed, &pinned, 1).is_err());

        let garbage = br#"{"signatures":[{"keyId":"00","signature":"!!"}]}"#;
        assert!(verify_threshold(MANIFEST_BYTES, garbage, &pinned, 1).is_err());
    }

    #[test]
    fn refuses_zero_threshold_and_other_formats() {
        let a = signing_key(1);
        let signed = signatures(&[(&a, MANIFEST_BYTES)]);
        assert!(verify_threshold(MANIFEST_BYTES, &signed, &[public(&a)], 0).is_err());

        let format_2 = br#"{"format":2,"version":"2.0.0","platforms":{}}"#;
        let signed = signatures(&[(&a, format_2)]);
        assert!(
            verify_threshold(format_2, &signed, &[public(&a)], 1)
                .unwrap_err()
                .contains("format 2")
        );
    }

    #[test]
    fn offers_only_newer_versions_with_plain_file_names() {
        let a = signing_key(1);
        let keys = [public(&a)];
        let offer = |version: &str, file: &str, platform: &str| {
            let (manifest, signed) = release(version, file, "00", &[&a]);
            newer(&manifest, &signed, &keys, 1, platform, "1.2.3")
        };
        let (version, file) = offer("1.10.0", "keyseal-1.10.0", "test-x64")
            .unwrap()
            .unwrap();
        assert_eq!(
            (version.as_str(), file.file.as_str()),
            ("1.10.0", "keyseal-1.10.0")
        );
        assert!(offer("1.2.3", "keyseal", "test-x64").unwrap().is_none());
        assert!(offer("1.2.2", "keyseal", "test-x64").unwrap().is_none());
        assert!(
            offer("1.2.4-rc.1", "keyseal", "test-x64")
                .unwrap()
                .is_some()
        );
        assert!(offer("2.0.0", "keyseal", "other-x64").unwrap().is_none());
        assert!(offer("2.0", "keyseal", "test-x64").is_err());
        assert!(offer("2.0.0", "../keyseal", "test-x64").is_err());
        assert!(offer("2.0.0", ".keyseal", "test-x64").is_err());
    }

    #[test]
    fn checks_at_most_daily() {
        let dir = temp_dir("stamp");
        let stamp = dir.join(STAMP);
        let start = UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        assert!(check_due(&stamp, start));
        record_check(&stamp, start);
        assert!(!check_due(&stamp, start));
        assert!(!check_due(
            &stamp,
            start + CHECK_EVERY - Duration::from_secs(1)
        ));
        assert!(check_due(&stamp, start + CHECK_EVERY));
        // A clock that moved back doesn't stop checks for good.
        assert!(check_due(&stamp, start - Duration::from_secs(60)));
        // The noticed version survives a check.
        write_stamp(&stamp, 1, "1.1.0");
        record_check(&stamp, start);
        assert_eq!(read_stamp(&stamp), (Some(1_800_000_000), "1.1.0".into()));
        std::fs::write(&stamp, "garbage").unwrap();
        assert!(check_due(&stamp, start));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stages_only_a_newer_signed_matching_build() {
        let (a, stranger) = (signing_key(1), signing_key(9));
        let keys = [public(&a)];
        let build = b"new build".to_vec();
        let hash = sha256_hex(&build);
        let host = |version: &str, asset: &[u8], key: &SigningKey| {
            let (manifest, signed) = release(version, "keyseal-new", &hash, &[key]);
            serve(HashMap::from([
                (MANIFEST.to_owned(), manifest),
                (SIGNATURES.to_owned(), signed),
                ("keyseal-new".to_owned(), asset.to_vec()),
            ]))
        };
        let dir = temp_dir("stage").join(STAGED);

        let base = host("1.1.0", &build, &a);
        let staged = check_and_stage(&base, &dir, &keys, 1, "test-x64", "1.0.0").unwrap();
        assert_eq!(staged.as_deref(), Some("1.1.0"));
        assert_eq!(std::fs::read(dir.join("keyseal-new")).unwrap(), build);
        assert!(dir.join(MANIFEST).is_file() && dir.join(SIGNATURES).is_file());

        assert!(
            check_and_stage(&base, &dir, &keys, 1, "test-x64", "1.1.0")
                .unwrap()
                .is_none()
        );
        let tampered = host("1.1.0", b"other build", &a);
        let error = check_and_stage(&tampered, &dir, &keys, 1, "test-x64", "1.0.0").unwrap_err();
        assert!(error.contains("doesn't match"), "{error}");
        let forged = host("1.1.0", &build, &stranger);
        assert!(check_and_stage(&forged, &dir, &keys, 1, "test-x64", "1.0.0").is_err());
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    /// Stages `asset` as release 1.1.0 in `dir`, as `check_and_stage` would.
    fn stage(dir: &Path, asset: &[u8], listed: &str, key: &SigningKey) {
        let (manifest, signed) = release("1.1.0", "keyseal-new", listed, &[key]);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(MANIFEST), manifest).unwrap();
        std::fs::write(dir.join(SIGNATURES), signed).unwrap();
        std::fs::write(dir.join("keyseal-new"), asset).unwrap();
    }

    /// A fake installed helper in `root` and the update that replaces it:
    /// the binary itself, or on macOS its app bundle as a zip.
    #[cfg(not(target_os = "macos"))]
    fn installed(root: &Path) -> (PathBuf, Vec<u8>) {
        let exe = root.join(if cfg!(windows) {
            "keyseal.exe"
        } else {
            "keyseal"
        });
        std::fs::write(&exe, b"old build").unwrap();
        (exe, b"new build".to_vec())
    }

    #[cfg(target_os = "macos")]
    fn installed(root: &Path) -> (PathBuf, Vec<u8>) {
        let bundle = |at: &Path, contents: &[u8]| {
            let macos = at.join(APP).join("Contents/MacOS");
            std::fs::create_dir_all(&macos).unwrap();
            std::fs::write(macos.join("keyseal"), contents).unwrap();
            macos.join("keyseal")
        };
        let exe = bundle(&root.join("Applications"), b"old build");
        let new = root.join("new");
        bundle(&new, b"new build");
        let zip = root.join("new.zip");
        let zipped = Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(new.join(APP))
            .arg(&zip)
            .status()
            .unwrap();
        assert!(zipped.success());
        (exe, std::fs::read(zip).unwrap())
    }

    #[test]
    fn applies_a_staged_build_that_verifies() {
        let (a, stranger) = (signing_key(1), signing_key(9));
        let keys = [public(&a)];
        let root = temp_dir("apply");
        let dir = root.join(STAGED);
        let (exe, asset) = installed(&root);

        assert!(
            apply_staged(&dir, &exe, true, &keys, 1, "test-x64", "1.0.0")
                .unwrap()
                .is_none()
        );

        stage(&dir, &asset, "00", &a);
        let error = apply_staged(&dir, &exe, true, &keys, 1, "test-x64", "1.0.0").unwrap_err();
        assert!(error.contains("doesn't match"), "{error}");
        assert!(!dir.exists(), "a bad staged update is discarded");

        stage(&dir, &asset, &sha256_hex(&asset), &stranger);
        assert!(apply_staged(&dir, &exe, true, &keys, 1, "test-x64", "1.0.0").is_err());
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");

        stage(&dir, &asset, &sha256_hex(&asset), &a);
        assert!(
            apply_staged(&dir, &exe, true, &keys, 1, "test-x64", "1.1.0")
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");

        stage(&dir, &asset, &sha256_hex(&asset), &a);
        let applied = apply_staged(&dir, &exe, true, &keys, 1, "test-x64", "1.0.0").unwrap();
        assert_eq!(applied.as_deref(), Some("1.1.0"));
        assert_eq!(std::fs::read(&exe).unwrap(), b"new build");
        assert!(!dir.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The all-zero placeholder decodes to a point of order 4, for which a
    /// signature with the identity as R and s = 0 passes a cofactorless
    /// check for about one message in four. Strict verification refuses
    /// every one.
    #[test]
    fn the_placeholder_key_refuses_a_forged_signature() {
        use ed25519_dalek::Verifier;
        assert_eq!(RELEASE_KEYS, [[0; 32]]);
        let placeholder = VerifyingKey::from_bytes(&RELEASE_KEYS[0]).unwrap();
        let mut forged = [0; 64];
        forged[0] = 1;
        let signature = Signature::from_bytes(&forged);
        let mut weak = 0;
        for minor in 0..32 {
            let manifest = serde_json::to_vec(&json!({
                "format": 1,
                "version": format!("9.{minor}.0"),
                "platforms": {},
            }))
            .unwrap();
            weak += usize::from(placeholder.verify(&manifest, &signature).is_ok());
            let signed = serde_json::to_vec(&json!({ "signatures": [{
                "keyId": key_id(&RELEASE_KEYS[0]),
                "signature": STANDARD.encode(forged),
            }]}))
            .unwrap();
            assert!(verify_threshold(&manifest, &signed, RELEASE_KEYS, THRESHOLD).is_err());
        }
        assert!(weak > 0, "the forgery never passes a weak check");
    }

    /// The helper's folder can't be written: the build is left in the
    /// config directory with a notice, for a permission error or a
    /// read-only file system (an AppImage mount) alike. A deb or tarball
    /// install is never replaced. The notice comes once per version.
    #[cfg(unix)]
    #[test]
    fn keeps_the_build_when_the_folder_is_unwritable() {
        use std::io::{Error, ErrorKind};
        use std::os::unix::fs::PermissionsExt;
        assert!(unwritable(&Error::from(ErrorKind::PermissionDenied)));
        assert!(unwritable(&Error::from(ErrorKind::ReadOnlyFilesystem)));
        assert!(!unwritable(&Error::from(ErrorKind::NotFound)));

        let root = temp_dir("unwritable");
        let (folder, config) = (root.join("bin"), root.join("config"));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let exe = folder.join("keyseal");
        std::fs::write(&exe, b"old build").unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555)).unwrap();
        let root_user = std::fs::write(folder.join("probe"), b"").is_ok();
        let result = install_binary(b"new build", &exe, "1.1.0", &config);
        let notice = take_notice();
        let again = install_binary(b"new build", &exe, "1.1.0", &config);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755)).unwrap();
        if !root_user {
            let error = result.unwrap_err();
            let kept = config.join("keyseal-1.1.0");
            assert!(error.contains(&kept.display().to_string()), "{error}");
            assert_eq!(notice, Some(error));
            assert_eq!(std::fs::read(&kept).unwrap(), b"new build");
            let mode = std::fs::metadata(&kept).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
            assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
            assert!(again.is_err());
            assert_eq!(take_notice(), None, "noticed once per version");
        }

        // Not replaced even where it could be, and noticed for a new version.
        let a = signing_key(1);
        let dir = config.join(STAGED);
        stage(&dir, b"new image", &sha256_hex(b"new image"), &a);
        let error =
            apply_staged(&dir, &exe, false, &[public(&a)], 1, "test-x64", "1.0.0").unwrap_err();
        assert!(error.starts_with("KeySeal 1.1.0 is downloaded"), "{error}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
        assert_eq!(
            std::fs::read(config.join("keyseal-1.1.0")).unwrap(),
            b"new image"
        );
        assert!(!dir.exists());
        assert_eq!(take_notice().is_some(), root_user);
        keep(b"newer build", &exe, "1.2.0", &config).unwrap();
        assert!(take_notice().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An AppImage is replaced as a whole, not the executable inside its
    /// read-only mount; outside one, Linux replaces nothing.
    #[cfg(unix)]
    #[test]
    fn updates_the_appimage_itself() {
        let root = temp_dir("appimage");
        let image = root.join("keyseal-x86_64.AppImage");
        std::fs::write(&image, b"old image").unwrap();
        let target = install_target(Some(image.clone())).unwrap();
        let exe = std::env::current_exe().unwrap();
        let linux = cfg!(target_os = "linux");
        if linux {
            assert_eq!(target, (image.clone(), true));
        } else {
            assert_eq!(target, (exe.clone(), true));
        }
        install_binary(b"new image", &image, "1.1.0", &root).unwrap();
        assert_eq!(std::fs::read(&image).unwrap(), b"new image");
        assert!(!root.join("keyseal-x86_64.new").exists());
        assert_eq!(install_target(None), Some((exe, !linux)));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// When the new bundle can't be moved into place, the old one goes back.
    #[cfg(target_os = "macos")]
    #[test]
    fn restores_the_bundle_when_the_swap_fails() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_dir("rollback");
        let (exe, _) = installed(&root);
        // A bundle without write permission can't be moved to another
        // folder, so the second rename fails after the first succeeded.
        let new = root.join("locked");
        let macos = new.join(APP).join("Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(macos.join("keyseal"), b"new build").unwrap();
        std::fs::set_permissions(new.join(APP), std::fs::Permissions::from_mode(0o555)).unwrap();
        let zip = root.join("locked.zip");
        let zipped = Command::new("/usr/bin/ditto")
            .args(["-c", "-k", "--keepParent"])
            .arg(new.join(APP))
            .arg(&zip)
            .status()
            .unwrap();
        assert!(zipped.success());

        let error = install_bundle(&std::fs::read(&zip).unwrap(), &exe).unwrap_err();
        assert!(error.starts_with("Couldn't replace"), "{error}");
        assert_eq!(std::fs::read(&exe).unwrap(), b"old build");
        let _ = Command::new("/bin/chmod")
            .arg("-R")
            .arg("u+w")
            .arg(&root)
            .status();
        let _ = std::fs::remove_dir_all(&root);
    }
}

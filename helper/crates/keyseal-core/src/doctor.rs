//! `keyseal doctor`: what the helper sees, as text for a support request
//! and as the rows the settings window shows. [`run`] looks at the system
//! the way a job would, loading drivers through [`flow::open_backend`];
//! [`in_child`] runs it in a `keyseal doctor --json` process, so a running
//! app never initialises a driver outside a job.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::catalogue::{self, Source};
use crate::flow;
use crate::modules::{self, Attempt, Candidate};
use crate::origin;
use crate::token;
use crate::trust::{Record, TrustStore};
use crate::worker;

/// What `keyseal doctor` found.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Connected USB devices, with the catalogue token each one is.
    pub devices: Vec<Device>,
    /// Every place a job looks for the key, in order.
    pub drivers: Vec<Driver>,
    pub status: Status,
    /// The whole report, as `keyseal doctor` prints it.
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    /// `vid:pid` in lowercase hex.
    pub id: String,
    pub product: Option<String>,
    /// The catalogue token's name, when the device is one.
    pub token: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Driver {
    /// The module's file name, or the certificate store.
    pub name: String,
    /// The path and where it came from, as the report names it.
    pub detail: String,
    /// The plugged-in catalogue token this driver is for.
    pub token: Option<String>,
    pub state: DriverState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "state", content = "reason")]
pub enum DriverState {
    /// Loaded and opened a token; a job would use it.
    Used,
    /// Loaded, but sees no token.
    NoToken,
    /// Didn't load or open, for this reason.
    Failed(String),
    /// Not installed.
    Missing,
    /// Installed, but an earlier driver was used.
    NotTried,
}

/// The outcome: whether a job could use a token now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "reason")]
pub enum Status {
    /// A token opened through [`DriverState::Used`].
    Ready,
    /// Drivers are installed, but no token is plugged in.
    NoToken,
    /// Nothing is installed, or every attempt failed for this reason.
    Failed(String),
}

impl Report {
    /// The report [`in_child`] reads.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a report serialises")
    }
}

/// Looks at the system as a job would, given the GPU the windows would
/// use (`keyseal_ui::check_gpu`).
pub fn run(gpu: Result<Option<String>, String>) -> Report {
    report(&gather(gpu))
}

/// Runs [`run`] in `keyseal doctor --json`, this executable, and reads its
/// report. In a process of its own, a driver that crashes or hangs can't
/// take the settings window with it; one that hangs is stopped after
/// [`CHILD_LIMIT`].
pub fn in_child() -> Result<Report, String> {
    let exe = std::env::current_exe().map_err(|e| format!("Couldn't find KeySeal: {e}"))?;
    let mut child = Command::new(exe)
        .args(["doctor", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Couldn't run keyseal doctor: {e}"))?;
    // Read on another thread, so a full pipe never stalls the child.
    let mut stdout = child.stdout.take().expect("piped stdout");
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout, &mut bytes);
        bytes
    });
    let deadline = Instant::now() + CHILD_LIMIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(TOO_LONG.into());
            }
            Err(e) => return Err(format!("Couldn't run keyseal doctor: {e}")),
        }
    }
    let bytes = reader.join().unwrap_or_default();
    serde_json::from_slice(&bytes).map_err(|e| format!("keyseal doctor gave no report: {e}"))
}

/// How long [`in_child`] waits: a slot wait and a few driver loads.
const CHILD_LIMIT: Duration = Duration::from_secs(30);
const TOO_LONG: &str = "Checking took too long: a token driver stopped responding. Unplug the token, plug it back in, then try again.";

/// What [`report`] needs, read from the system.
struct Facts {
    config: Result<(PathBuf, Result<Vec<Record>, String>), String>,
    gpu: Result<Option<String>, String>,
    insecure: bool,
    proxies: Vec<&'static str>,
    /// The version downloaded now, or why the download failed.
    refreshed: Option<Result<u64, String>>,
    catalogue: (u64, String, Source),
    devices: Result<Vec<Device>, String>,
    /// Each candidate and whether it is installed.
    candidates: Result<Vec<(Candidate, bool)>, String>,
    /// Each attempt and how it went, when there were candidates.
    tried: Vec<(Attempt, Result<(), String>)>,
    /// `None`: no token is plugged in.
    opened: Result<Option<Opened>, String>,
}

/// The token a job would use.
struct Opened {
    /// The PKCS#11 module, and where it runs: the token worker's path, or
    /// `None` for this process.
    module: Option<(PathBuf, Result<Option<PathBuf>, String>)>,
    pin_warning: Option<&'static str>,
    /// SHA-256 and subject of each certificate visible before login.
    certificates: Result<Vec<(String, String)>, String>,
}

fn gather(gpu: Result<Option<String>, String>) -> Facts {
    let config = crate::config_dir().map(|dir| {
        let records = TrustStore::new(&dir).list();
        (dir, records)
    });
    let proxies = [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ]
    .into_iter()
    .filter(|name| std::env::var_os(name).is_some())
    .collect();
    let refreshed = catalogue::refresh().map(|fetched| fetched.map(|c| c.version));
    let (catalogue, source) = catalogue::current();
    let devices = catalogue::usb_devices().map(|devices| {
        devices
            .iter()
            .map(|device| Device {
                id: format!("{:04x}:{:04x}", device.vid, device.pid),
                product: device.product.clone(),
                token: catalogue.token_for(device).map(|token| token.name.clone()),
            })
            .collect()
    });
    let candidates = modules::candidates().map(|candidates| {
        candidates
            .into_iter()
            .map(|candidate| {
                let installed = candidate.path.exists();
                (candidate, installed)
            })
            .collect::<Vec<_>>()
    });
    let mut tried = Vec::new();
    let mut opened = Ok(None);
    if candidates.is_ok() {
        // Opened as a job would: each found module in turn, then on Windows
        // the certificate store.
        let backend = flow::open_backend(&mut || Ok(()), &mut |attempt, outcome| {
            tried.push((attempt.clone(), outcome.map_err(str::to_owned)));
        });
        opened = match backend {
            Ok(backend) => {
                let used = tried.iter().find(|(_, outcome)| outcome.is_ok());
                let module = match used {
                    Some((Attempt::Module(candidate), _)) => {
                        let runs = match worker::backend_for(&candidate.path) {
                            Ok(worker::Backend::InProcess) => Ok(None),
                            Ok(worker::Backend::Worker) => {
                                worker::locate().map(Some).map_err(|e| e.0)
                            }
                            Err(e) => Err(e.0),
                        };
                        Some((candidate.path.clone(), runs))
                    }
                    _ => None,
                };
                let token = backend.token();
                Ok(Some(Opened {
                    module,
                    pin_warning: token.pin_warning(),
                    certificates: token
                        .certificates(false)
                        .map(|certificates| {
                            certificates
                                .iter()
                                .map(|c| (c.sha256.clone(), token::subject(&c.der)))
                                .collect()
                        })
                        .map_err(|e| e.0),
                }))
            }
            Err(failure) if failure.message == token::NO_TOKEN => Ok(None),
            Err(failure) => Err(failure.message),
        };
    }
    Facts {
        config,
        gpu,
        insecure: origin::insecure_origins_allowed(),
        proxies,
        refreshed,
        catalogue: (catalogue.version, catalogue.generated_at, source),
        devices,
        candidates,
        tried,
        opened,
    }
}

fn report(facts: &Facts) -> Report {
    let mut lines = Vec::new();
    let status = match write(facts, &mut lines) {
        Ok(status) => status,
        Err(message) => {
            lines.push(format!("error: {message}"));
            Status::Failed(message)
        }
    };
    let mut text = lines.join("\n");
    text.push('\n');
    Report {
        devices: facts.devices.clone().unwrap_or_default(),
        drivers: drivers(facts),
        status,
        text,
    }
}

/// The report's lines, stopping at the first error.
fn write(facts: &Facts, lines: &mut Vec<String>) -> Result<Status, String> {
    lines.push(format!("keyseal {}", crate::VERSION));
    lines.push(format!(
        "OS: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    ));
    match &facts.config {
        Ok((dir, records)) => {
            lines.push(format!("Config directory: {}", dir.display()));
            match records {
                Ok(records) if records.is_empty() => lines.push("Trusted origins: none".into()),
                Ok(records) => {
                    lines.push("Trusted origins:".into());
                    for record in records {
                        lines.push(format!(
                            "  {} (trusted at {} Unix time)",
                            record.origin, record.trusted_at
                        ));
                    }
                }
                Err(message) => lines.push(format!("Trusted origins: {message}")),
            }
        }
        Err(message) => lines.push(format!("Config directory: {message}")),
    }
    lines.push(match &facts.gpu {
        Ok(Some(device)) => format!("GPU: {device}"),
        Ok(None) => "GPU: checked when a window opens".into(),
        Err(message) => format!("GPU: {message}"),
    });
    if facts.insecure {
        lines.push(
            "KEYSEAL_ALLOW_INSECURE_ORIGINS=1: http://localhost and http://127.0.0.1 are allowed"
                .into(),
        );
    }
    if !facts.proxies.is_empty() {
        lines.push(format!(
            "Proxy: {} set, but the helper doesn't use proxies, since the address a server resolves to can't be checked through one",
            facts.proxies.join(", ")
        ));
    }

    match &facts.refreshed {
        Some(Ok(version)) => lines.push(format!("Driver catalogue: downloaded version {version}")),
        Some(Err(message)) => lines.push(format!("Driver catalogue: update failed: {message}")),
        None => {}
    }
    let (version, generated_at, source) = &facts.catalogue;
    let copy = match source {
        Source::Embedded => "embedded",
        Source::Fetched => "downloaded",
    };
    lines.push(format!(
        "Driver catalogue: version {version} of {generated_at} ({copy})"
    ));
    match &facts.devices {
        Ok(devices) => {
            lines.push("USB devices:".into());
            for device in devices {
                lines.push(format!(
                    "  {} {} ({})",
                    device.id,
                    device.product.as_deref().unwrap_or("unnamed"),
                    device.token.as_deref().unwrap_or("not in the catalogue")
                ));
            }
        }
        Err(message) => lines.push(format!("USB devices: {message}")),
    }

    lines.push("PKCS#11 modules:".into());
    for (candidate, installed) in facts.candidates.as_ref().map_err(String::clone)? {
        let state = if *installed { "found" } else { "missing" };
        lines.push(format!(
            "  {} [{}] ({state})",
            candidate.path.display(),
            candidate.source
        ));
    }
    lines.push("Tried:".into());
    for (attempt, outcome) in &facts.tried {
        lines.push(match outcome {
            Ok(()) => format!("  {attempt}: used"),
            Err(message) => format!("  {attempt}: {message}"),
        });
    }
    let Some(opened) = facts.opened.as_ref().map_err(String::clone)? else {
        lines.push("Tokens: none plugged in".into());
        return Ok(Status::NoToken);
    };
    if let Some((path, runs)) = &opened.module {
        lines.push(match runs.as_ref().map_err(String::clone)? {
            None => "Runs in this process".into(),
            Some(worker) => format!("Runs in the token worker at {}", worker.display()),
        });
        lines.push(format!("Opened the first token of {}", path.display()));
    }
    if let Some(warning) = opened.pin_warning {
        lines.push(format!("  {warning}"));
    }
    let certificates = opened.certificates.as_ref().map_err(String::clone)?;
    lines.push(format!(
        "Certificates visible before login: {}",
        certificates.len()
    ));
    for (sha256, subject) in certificates {
        lines.push(format!("  {sha256}  {subject}"));
    }
    Ok(Status::Ready)
}

/// Each candidate with how its attempt went, then the certificate store
/// when it was tried.
fn drivers(facts: &Facts) -> Vec<Driver> {
    let state = |attempt: &Attempt| {
        facts
            .tried
            .iter()
            .find(|(tried, _)| tried == attempt)
            .map(|(_, outcome)| match outcome {
                Ok(()) => DriverState::Used,
                Err(message) if message == token::NO_TOKEN => DriverState::NoToken,
                Err(message) => DriverState::Failed(message.clone()),
            })
    };
    let candidates = facts.candidates.as_deref().unwrap_or_default();
    let mut drivers: Vec<Driver> = candidates
        .iter()
        .map(|(candidate, installed)| {
            let attempt = Attempt::Module(candidate.clone());
            Driver {
                name: candidate.path.file_name().map_or_else(
                    || candidate.path.display().to_string(),
                    |name| name.to_string_lossy().into_owned(),
                ),
                detail: attempt.to_string(),
                token: match &candidate.source {
                    modules::Source::UsbMatch(name) => Some(name.clone()),
                    _ => None,
                },
                state: match state(&attempt) {
                    Some(state) => state,
                    None if *installed => DriverState::NotTried,
                    None => DriverState::Missing,
                },
            }
        })
        .collect();
    if let Some(state) = state(&Attempt::Cng) {
        drivers.push(Driver {
            name: "Windows certificate store".into(),
            detail: Attempt::Cng.to_string(),
            token: None,
            state,
        });
    }
    drivers
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(path: &str, source: modules::Source) -> Candidate {
        Candidate {
            path: path.into(),
            source,
        }
    }

    fn facts() -> Facts {
        let plugged = candidate(
            "/usr/local/lib/libcastle.dylib",
            modules::Source::UsbMatch("HYP2003".into()),
        );
        let known = candidate("/usr/local/lib/libeTPkcs11.dylib", modules::Source::Known);
        let missing = candidate("/usr/local/lib/libmtoken.dylib", modules::Source::Known);
        Facts {
            config: Ok((
                "/config/keyseal".into(),
                Ok(vec![Record {
                    origin: "https://dash.example.org".into(),
                    trusted_at: 1_700_000_000,
                }]),
            )),
            gpu: Ok(Some("Apple M2".into())),
            insecure: false,
            proxies: vec![],
            refreshed: None,
            catalogue: (3, "2026-10-01".into(), Source::Embedded),
            devices: Ok(vec![Device {
                id: "2ccf:080a".into(),
                product: Some("HYP2003".into()),
                token: Some("HYP2003".into()),
            }]),
            candidates: Ok(vec![
                (plugged.clone(), true),
                (known.clone(), true),
                (missing, false),
            ]),
            tried: vec![(Attempt::Module(plugged), Ok(()))],
            opened: Ok(Some(Opened {
                module: Some(("/usr/local/lib/libcastle.dylib".into(), Ok(None))),
                pin_warning: None,
                certificates: Ok(vec![("ab12".into(), "ASHA RAO".into())]),
            })),
        }
    }

    #[test]
    fn reports_the_token_and_each_driver() {
        let report = report(&facts());
        assert_eq!(report.status, Status::Ready);
        let expected = format!(
            "keyseal {}\n\
             OS: {} {}\n\
             Config directory: /config/keyseal\n\
             Trusted origins:\n  https://dash.example.org (trusted at 1700000000 Unix time)\n\
             GPU: Apple M2\n\
             Driver catalogue: version 3 of 2026-10-01 (embedded)\n\
             USB devices:\n  2ccf:080a HYP2003 (HYP2003)\n\
             PKCS#11 modules:\n\
             \x20 /usr/local/lib/libcastle.dylib [catalogue, HYP2003 plugged in] (found)\n\
             \x20 /usr/local/lib/libeTPkcs11.dylib [known drivers] (found)\n\
             \x20 /usr/local/lib/libmtoken.dylib [known drivers] (missing)\n\
             Tried:\n\
             \x20 /usr/local/lib/libcastle.dylib [catalogue, HYP2003 plugged in]: used\n\
             Runs in this process\n\
             Opened the first token of /usr/local/lib/libcastle.dylib\n\
             Certificates visible before login: 1\n  ab12  ASHA RAO\n",
            crate::VERSION,
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        assert_eq!(report.text, expected);
        let states: Vec<_> = report
            .drivers
            .iter()
            .map(|d| (d.name.as_str(), d.token.as_deref(), &d.state))
            .collect();
        assert_eq!(
            states,
            [
                ("libcastle.dylib", Some("HYP2003"), &DriverState::Used),
                ("libeTPkcs11.dylib", None, &DriverState::NotTried),
                ("libmtoken.dylib", None, &DriverState::Missing),
            ]
        );
    }

    #[test]
    fn reports_a_missing_token_and_stops_at_a_failure() {
        let mut no_token = facts();
        let known = no_token.candidates.as_ref().unwrap()[1].0.clone();
        no_token.tried = vec![(Attempt::Module(known), Err(token::NO_TOKEN.into()))];
        no_token.opened = Ok(None);
        let no_token = report(&no_token);
        assert_eq!(no_token.status, Status::NoToken);
        assert!(no_token.text.ends_with(&format!(
            "/usr/local/lib/libeTPkcs11.dylib [known drivers]: {}\nTokens: none plugged in\n",
            token::NO_TOKEN
        )));
        assert_eq!(no_token.drivers[1].state, DriverState::NoToken);

        let mut failed = facts();
        let reason = "Couldn't start the token driver: bad".to_owned();
        let plugged = failed.candidates.as_ref().unwrap()[0].0.clone();
        failed.tried = vec![(Attempt::Module(plugged), Err(reason.clone()))];
        failed.opened = Err(reason.clone());
        let failed = report(&failed);
        assert_eq!(failed.status, Status::Failed(reason.clone()));
        assert!(failed.text.ends_with(&format!("error: {reason}\n")));
        assert_eq!(failed.drivers[0].state, DriverState::Failed(reason));

        let mut unlisted = facts();
        unlisted.candidates = Err("KEYSEAL_PKCS11_MODULE must be an absolute path".into());
        let unlisted = report(&unlisted);
        assert!(unlisted.text.ends_with(
            "PKCS#11 modules:\nerror: KEYSEAL_PKCS11_MODULE must be an absolute path\n"
        ));
        assert!(unlisted.drivers.is_empty());
    }

    #[test]
    fn the_report_survives_json() {
        let report = report(&facts());
        assert_eq!(
            serde_json::from_str::<Report>(&report.to_json()).unwrap(),
            report
        );
    }
}

//! `keyseal`: the KeySeal helper. `run` handles a `keyseal://` link in the
//! GPUI Kit windows, or headless with `KEYSEAL_HEADLESS=1`; `settings` opens
//! the settings window; `list` and `doctor` inspect the setup; `install`,
//! `uninstall` and `update` manage the helper itself.
// A browser starting the helper on Windows opens no console window.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod headless;

use std::io::Write;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use keyseal_core::backend;
use keyseal_core::certificate;
use keyseal_core::flow::{self, Environment, Failure, Outcome, Ui};
use keyseal_core::origin;
use keyseal_core::protocol::KeyUsage;
use keyseal_core::trust::TrustStore;
use keyseal_core::{doctor, install, update};
use zeroize::Zeroizing;

use headless::Headless;

const USAGE: &str = "Usage: keyseal run <keyseal://link> | settings | list | doctor [--json | --forget <origin>] | install | uninstall | update [verify <manifest> <signatures>] | --version";

/// The log is started afresh once it passes this size.
const MAX_LOG_BYTES: u64 = 1_000_000;

fn main() -> ExitCode {
    // A GUI-subsystem program has no console; started from a terminal,
    // `keyseal doctor` and the other commands print to that terminal's.
    #[cfg(windows)]
    // SAFETY: AttachConsole takes no pointers and only fails when there is
    // no parent console: started from Explorer, the Start menu or a browser.
    let terminal = unsafe {
        windows::Win32::System::Console::AttachConsole(
            windows::Win32::System::Console::ATTACH_PARENT_PROCESS,
        )
    }
    .is_ok();
    #[cfg(not(windows))]
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["--version"] => {
            println!("keyseal {}", keyseal_core::VERSION);
            Ok(())
        }
        // Opened without a terminal. On macOS that is the `keyseal://`
        // handler, and the link arrives as an open-URL event, which the
        // windows receive. On Windows and Linux it is the app itself, from
        // the Start menu, the app menu or the file manager.
        [] if !headless() && !terminal => launch(if cfg!(target_os = "macos") {
            keyseal_ui::Start::UrlEvent
        } else {
            keyseal_ui::Start::Settings
        }),
        ["run", link] => return run_updated(link),
        ["settings"] => launch(keyseal_ui::Start::Settings),
        ["list"] => list(),
        ["doctor"] => return doctor(false),
        ["doctor", "--json"] => return doctor(true),
        ["doctor", "--forget", origin] => forget(origin),
        ["install"] => install::install(),
        ["uninstall"] => install::uninstall(),
        ["update"] => update::check_now().map(|text| println!("{text}")),
        ["update", "verify", manifest, signatures] => {
            update::verify_files(manifest, signatures).map(|text| println!("{text}"))
        }
        // How Windows and Linux hand over a link.
        [link] if link.starts_with("keyseal:") => return run_updated(link),
        // How macOS hands over a link: an Apple Event to the app, read here
        // when there are no windows to receive it.
        #[cfg(target_os = "macos")]
        [] if headless() => {
            match keyseal_core::macos::launch_url(std::time::Duration::from_secs(3)) {
                Some(link) => return run_updated(&link),
                None => {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the job with the newest helper: a staged update replaces this one
/// first. The windows look for the next update after the job.
fn run_updated(link: &str) -> ExitCode {
    if let Some(code) = update::relaunch_if_staged(&["run", link], log) {
        return code;
    }
    run(link)
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn headless() -> bool {
    env_var("KEYSEAL_HEADLESS").as_deref() == Some("1")
}

fn run(link: &str) -> ExitCode {
    if !headless() {
        launch(keyseal_ui::Start::Link(link.to_owned()));
    }
    let mut ui = Headless {
        trust_origin: env_var("KEYSEAL_HEADLESS_TRUST_ORIGIN"),
        pin: env_var("KEYSEAL_PIN").map(Zeroizing::new),
    };
    // The flow has already shown any error through the UI. A headless run
    // leaves the update notice, the driver catalogue and the update check
    // to the windows' next job (`keyseal_ui::start_job`): it runs in CI and
    // scripts, which want only the job.
    match run_flow(link, &mut ui) {
        Ok(outcome) => {
            println!("{} You can return to the page.", outcome.text());
            ExitCode::SUCCESS
        }
        Err(_) => ExitCode::FAILURE,
    }
}

fn run_flow(link: &str, ui: &mut dyn Ui) -> Result<Outcome, Failure> {
    let config_dir = keyseal_core::config_dir().inspect_err(|message| ui.show_error(message))?;
    let env = Environment {
        allow_insecure: origin::insecure_origins_allowed(),
        config_dir,
    };
    flow::run(link, ui, &env)
}

/// Hands the main thread to the windows; the process ends with them.
fn launch(start: keyseal_ui::Start) -> ! {
    let config_dir = keyseal_core::config_dir().unwrap_or_else(|message| {
        log(&message);
        std::process::exit(1)
    });
    keyseal_ui::launch(start, config_dir, log, doctor::in_child, |link, ui| {
        // A link from the open-URL event arrives here first, so a staged
        // update is installed now; `run_updated` has done it for the others.
        #[cfg(target_os = "macos")]
        update::relaunch_if_staged(&["run", link], log);
        log("Job started.");
        match run_flow(link, ui) {
            Ok(outcome) => {
                log(outcome.text());
                0
            }
            Err(failure) => {
                log(&format!("error: {}", failure.message));
                1
            }
        }
    })
}

/// Writes `message` to stderr and to `keyseal.log` in the config directory,
/// since a helper started by the browser has no terminal. Never given the
/// link (it holds the job token) or the PIN.
fn log(message: &str) {
    // The file first, and stderr without panicking: the panic hook calls
    // this, and a closed stderr would otherwise abort before the file.
    write_log_file(message);
    let _ = writeln!(std::io::stderr(), "{message}");
}

fn write_log_file(message: &str) {
    let Ok(dir) = keyseal_core::config_dir() else {
        return;
    };
    let path = dir.join("keyseal.log");
    let full = std::fs::metadata(&path).is_ok_and(|m| m.len() > MAX_LOG_BYTES);
    let file = keyseal_core::create_private_dir(&dir).and_then(|_| {
        let mut options = std::fs::OpenOptions::new();
        options
            .create(true)
            .append(!full)
            .write(true)
            .truncate(full);
        // Readable only by the user, as everything in the config directory.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let file = options.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(file)
    });
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{seconds} {message}");
    }
}

/// `keyseal list`: the certificates on each token, before login, or with
/// one token after logging in with `KEYSEAL_PIN` when none are visible.
/// With several tokens each is named first, and the PIN isn't tried: it
/// belongs to one of them, and a wrong PIN counts against the others.
fn list() -> Result<(), String> {
    backend::open_each(
        KeyUsage::DigitalSignature,
        &mut |_, _| {},
        &mut |name, backend| {
            let backend = backend?;
            let token = backend.token();
            if let Some(name) = &name {
                println!("{name}:");
            }
            let mut certificates = token.certificates(false)?;
            if certificates.is_empty()
                && name.is_none()
                && let Some(pin) = env_var("KEYSEAL_PIN").map(Zeroizing::new)
            {
                token.login(pin).map_err(|e| e.to_string())?;
                certificates = token.certificates(false)?;
            }
            if certificates.is_empty() {
                println!(
                    "{}",
                    if name.is_none() {
                        "No certificates are visible on the token. Set KEYSEAL_PIN to look after login."
                    } else {
                        "No certificates are visible on this token. To look after login, set KEYSEAL_PIN with only this token plugged in."
                    }
                );
            }
            for certificate in certificates {
                let role = if certificate::is_signing_certificate(&certificate.der, KeyUsage::default())
                {
                    "signing"
                } else {
                    "other"
                };
                println!(
                    "{}  {role:7}  {}",
                    certificate.sha256,
                    certificate::subject(&certificate.der)
                );
            }
            token.close();
            Ok(())
        },
    )
    .map_err(|error| Failure::from(error).message)
}

/// `keyseal doctor`: what the helper sees, as text or with `json` as the
/// report the settings window reads. Fails when no module loads.
fn doctor(json: bool) -> ExitCode {
    let report = doctor::run(keyseal_ui::check_gpu());
    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.text);
    }
    match report.status {
        doctor::Status::Failed(_) => ExitCode::FAILURE,
        doctor::Status::Ready | doctor::Status::NoToken => ExitCode::SUCCESS,
    }
}

fn forget(origin: &str) -> Result<(), String> {
    let store = TrustStore::new(&keyseal_core::config_dir()?);
    if store.forget(origin)? {
        println!("Forgot {origin}.");
    } else {
        println!("{origin} wasn't trusted.");
    }
    Ok(())
}

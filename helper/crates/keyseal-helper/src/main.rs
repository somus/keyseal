//! `keyseal`: the KeySeal helper. `run` handles a `keyseal://` link in the
//! GPUI Kit windows, or headless with `KEYSEAL_HEADLESS=1`; `settings` opens
//! the settings window; `list` and `doctor` inspect the setup; `install`,
//! `uninstall` and `update` manage the helper itself.
// A browser starting the helper on Windows opens no console window.
#![cfg_attr(windows, windows_subsystem = "windows")]

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use keyseal_core::flow::{
    self, DigestConfirm, Environment, Failure, JobView, Outcome, PinPrompt, Ui,
};
use keyseal_core::origin::{self, Origin};
use keyseal_core::protocol::Kind;
use keyseal_core::token;
use keyseal_core::trust::TrustStore;
use keyseal_core::{doctor, install, update};
use zeroize::Zeroizing;

const USAGE: &str = "Usage: keyseal run <keyseal://link> | settings | list | doctor [--json | --forget <origin>] | install | uninstall | update [verify <manifest> <signatures>] | --version";

/// The log is started afresh once it passes this size.
const MAX_LOG_BYTES: u64 = 1_000_000;

fn main() -> ExitCode {
    // A GUI-subsystem program has no console; started from a terminal,
    // `keyseal doctor` and the other commands print to that terminal's.
    #[cfg(windows)]
    // SAFETY: AttachConsole takes no pointers and only fails when there is
    // no parent console, which is fine.
    unsafe {
        let _ = windows::Win32::System::Console::AttachConsole(
            windows::Win32::System::Console::ATTACH_PARENT_PROCESS,
        );
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["--version"] => {
            println!("keyseal {}", keyseal_core::VERSION);
            Ok(())
        }
        // Launched by the `keyseal://` handler on macOS: no terminal, and the
        // link arrives as an open-URL event, which the windows receive.
        [] if cfg!(target_os = "macos") && !headless() && !std::io::stdin().is_terminal() => {
            launch(keyseal_ui::Start::UrlEvent)
        }
        ["run", link] => return run_updated(link),
        ["settings"] => launch(keyseal_ui::Start::Settings),
        ["list"] => list(),
        ["doctor"] => return doctor(false),
        ["doctor", "--json"] => return doctor(true),
        ["doctor", "--forget", origin] => forget(origin),
        ["install"] => install::install(),
        ["uninstall"] => install::uninstall(),
        ["update"] => update::check_now(),
        ["update", "verify", manifest, signatures] => update::verify_files(manifest, signatures),
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
    if let Some(code) = update::relaunch_if_staged(&["run", link]) {
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
    // The flow has already shown any error through the UI.
    match run_flow(link, &mut ui) {
        Ok(Outcome::Signed) => {
            println!("Signed. You can return to the page.");
            ExitCode::SUCCESS
        }
        Ok(Outcome::Enrolled) => {
            println!("Certificate enrolled. You can return to the page.");
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
        update::relaunch_if_staged(&["run", link]);
        log("Job started.");
        let code = match run_flow(link, ui) {
            Ok(Outcome::Signed) => {
                log("Signed.");
                0
            }
            Ok(Outcome::Enrolled) => {
                log("Certificate enrolled.");
                0
            }
            Err(failure) => {
                log(&format!("error: {}", failure.message));
                1
            }
        };
        // An update this helper couldn't install over itself.
        if let Some(notice) = update::take_notice() {
            ui.show_info(&notice);
        }
        code
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
    let file = std::fs::create_dir_all(&dir).and_then(|_| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(!full)
            .write(true)
            .truncate(full)
            .open(&path)
    });
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Ok(mut file) = file {
        let _ = writeln!(file, "{seconds} {message}");
    }
}

/// Answers the flow from the environment and prints what a window would show.
struct Headless {
    trust_origin: Option<String>,
    /// `KEYSEAL_PIN`, zeroised when used or dropped.
    pin: Option<Zeroizing<String>>,
}

fn describe(job: &JobView) {
    if job.origin.insecure {
        eprintln!("INSECURE DEVELOPMENT ORIGIN: plain HTTP, never trusted permanently.");
    }
    eprintln!("Origin: {}", job.origin);
    if let Some(branding) = job.branding {
        eprintln!("Integrator: {}", branding.manifest.name);
    }
    eprintln!("Title: {}", job.title);
    eprintln!("Signer: {}", job.signer);
    if job.documents.len() > 1 {
        eprintln!("Documents: {}", job.documents.len());
        for (index, document) in job.documents.iter().enumerate() {
            eprintln!("  {}. {}", index + 1, document.title);
        }
    }
}

/// Each document's digest, beside its title when the job has several.
fn describe_digests(job: &JobView, digests: &[String]) {
    match (job.documents, digests) {
        (_, [digest]) => eprintln!("Document digest: {digest}"),
        (documents, digests) => {
            eprintln!("Document digests:");
            for (document, digest) in documents.iter().zip(digests) {
                eprintln!("  {}: {digest}", document.title);
            }
        }
    }
}

impl Ui for Headless {
    fn confirm_origin(&mut self, origin: &Origin) -> bool {
        let origin = origin.as_string();
        if self.trust_origin.as_deref() == Some(origin.as_str()) {
            eprintln!("First contact with {origin}: trusted by KEYSEAL_HEADLESS_TRUST_ORIGIN.");
            return true;
        }
        eprintln!(
            "First contact with {origin}. A headless run trusts a new origin only when KEYSEAL_HEADLESS_TRUST_ORIGIN={origin}."
        );
        false
    }

    fn choose_certificate(&mut self, job: &JobView, subjects: &[String]) -> Option<usize> {
        describe(job);
        eprintln!("Several certificates fit this job, and a headless run can't choose one:");
        for subject in subjects {
            eprintln!("  {subject}");
        }
        None
    }

    fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>> {
        describe(prompt.job);
        if let Some(certificate) = &prompt.certificate {
            eprintln!("Certificate: {certificate}");
        }
        match (&prompt.digests, prompt.job.kind) {
            (Some(digests), _) => describe_digests(prompt.job, digests),
            (None, Kind::Sign) => {
                eprintln!("The document digests will be shown for confirmation before signing.")
            }
            (None, Kind::Enrol) => eprintln!("Enrol the certificate on this token."),
        }
        if let Some(warning) = prompt.pin_warning {
            eprintln!("{warning}");
        }
        if prompt.pin_pad {
            eprintln!("Enter the PIN on the token's PIN pad.");
            return Some(Zeroizing::default());
        }
        // The PIN is used once per job and never retried.
        let pin = self.pin.take();
        if pin.is_none() {
            eprintln!("KEYSEAL_PIN isn't set.");
        }
        pin
    }

    fn confirm_digest(&mut self, confirm: &DigestConfirm) -> bool {
        describe(confirm.job);
        eprintln!("Certificate: {}", confirm.certificate);
        describe_digests(confirm.job, &confirm.digests);
        eprintln!("Signing confirmed (headless).");
        true
    }

    fn confirm_enrol(&mut self, job: &JobView) -> bool {
        describe(job);
        eprintln!("Enrolling a certificate from the Windows certificate store (headless).");
        true
    }

    fn show_error(&mut self, message: &str) {
        eprintln!("error: {message}");
    }

    fn show_info(&mut self, message: &str) {
        eprintln!("{message}");
    }
}

/// `keyseal list`: the certificates on the token, before login, or after
/// logging in with `KEYSEAL_PIN` when none are visible.
fn list() -> Result<(), String> {
    let backend =
        flow::open_backend(&mut || Ok(()), &mut |_, _| {}).map_err(|failure| failure.message)?;
    let token = backend.token();
    let mut certificates = token.certificates(false)?;
    if certificates.is_empty()
        && let Some(pin) = env_var("KEYSEAL_PIN").map(Zeroizing::new)
    {
        token.login(pin)?;
        certificates = token.certificates(false)?;
    }
    if certificates.is_empty() {
        println!("No certificates are visible on the token. Set KEYSEAL_PIN to look after login.");
    }
    for certificate in certificates {
        let role = if token::is_signing_certificate(&certificate.der) {
            "signing"
        } else {
            "other"
        };
        println!(
            "{}  {role:7}  {}",
            certificate.sha256,
            token::subject(&certificate.der)
        );
    }
    Ok(())
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

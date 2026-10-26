//! The KeySeal helper's windows, built with GPUI Kit. GPUI owns the main
//! thread; the job's flow runs on a background thread with [`WindowUi`],
//! whose prompts send a request to the main thread and block until the user
//! answers, and whose progress only sends one. A window closed without an
//! answer counts as Cancel; cancelling closes the job window at once, and
//! the flow unwinds behind it. Links that arrive while the app runs (macOS
//! sends them to the running app) start a job when none is running.

mod native;
mod strings;
mod views;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use gpui_kit::{App, KeyBinding, Menu, MenuItem, QuitMode, actions};
use keyseal_core::doctor::Report;
use keyseal_core::flow::{DigestConfirm, JobView, PinPrompt, Progress, Step, Ui};
use keyseal_core::origin::Origin;
use keyseal_core::protocol::{Kind, plain};
use zeroize::Zeroizing;

actions!(keyseal, [OpenSettings]);

/// How the application starts.
pub enum Start {
    /// Run the job in this `keyseal://` link.
    Link(String),
    /// Open the settings window and quit when it closes.
    Settings,
    /// Launched by the `keyseal://` handler on macOS: the link arrives as an
    /// open-URL event. Without one within a second, this opens the settings
    /// window.
    UrlEvent,
}

/// Looks at the tokens and drivers as `keyseal doctor` does. Blocks, so the
/// settings window runs it on the background executor.
pub type Probe = fn() -> Result<Report, String>;

/// What the main thread acts on.
pub(crate) enum Event {
    /// A `keyseal://` link to run.
    Link(String),
    /// No link arrived within a second of an open-URL launch.
    NoLink,
    /// A request from the flow for the windows.
    Ui(Box<Request>),
    /// The job is over: close every window.
    Finished,
    /// A job's thread ended, after the catalogue and update checks, with
    /// this exit code.
    Done(i32),
    /// A window closed after Settings opened: the app quits once none is
    /// left and no job runs.
    SettingsClosed,
}

/// One job at a time. A job runs until its windows are done with, and its
/// thread lives on through the catalogue and update checks; the process
/// exits when the last thread ends.
#[derive(Default)]
struct Jobs {
    running: bool,
    alive: usize,
}

impl Jobs {
    /// Whether a link may start a job now; if so, the job is running.
    fn start(&mut self) -> bool {
        if self.running {
            return false;
        }
        self.running = true;
        self.alive += 1;
        true
    }

    fn finished(&mut self) {
        self.running = false;
    }

    /// A job's thread ended; whether none is left.
    fn done(&mut self) -> bool {
        self.alive = self.alive.saturating_sub(1);
        self.alive == 0
    }

    /// No job has started, or every one has ended.
    fn idle(&self) -> bool {
        self.alive == 0
    }
}

/// Opens one window with sample data and runs until it closes. `view` is
/// one of [`GALLERY_VIEWS`].
#[cfg(feature = "gallery")]
pub fn gallery(view: &str) {
    let view = view.to_owned();
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);
            cx.bind_keys(views::key_bindings());
            views::gallery(&view, cx);
            cx.activate(true);
        });
}

#[cfg(feature = "gallery")]
pub use views::GALLERY_VIEWS;

/// Runs the application on this thread and exits the process when it ends:
/// with `job`'s exit code after a job, else 0. `log` records what the user
/// can't see in a terminal; `probe` is `keyseal doctor` for the settings
/// window, run off the main thread; `job` runs one link through the flow.
pub fn launch(
    start: Start,
    config_dir: PathBuf,
    log: fn(&str),
    probe: Probe,
    job: fn(&str, &mut dyn Ui) -> i32,
) -> ! {
    if let Err(message) = check_gpu() {
        log(&message);
        std::process::exit(1);
    }
    // GPUI panics when it can't set up the GPU, before any window opens;
    // record that where a browser-started helper can be diagnosed. Only the
    // main thread's panics: the job thread handles the link, never logged.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().name() == Some("main") {
            log(&format!("KeySeal stopped: {info}"));
        }
        default_hook(info);
    }));
    let (events, mut incoming) = unbounded();
    // Off macOS, GPUI quits by default once the last window closes, which
    // ends a job between the trust prompt and the job window. Every way out
    // of a run calls `std::process::exit` instead.
    let app = gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .with_quit_mode(QuitMode::Explicit);
    // Read for the app's lifetime: macOS hands every later link to it.
    let links = events.clone();
    app.on_open_urls(move |urls| {
        for url in urls {
            let _ = links.unbounded_send(Event::Link(url));
        }
    });
    app.run(move |cx| {
        gpui_kit::init(cx);
        cx.bind_keys(views::key_bindings());
        cx.bind_keys([KeyBinding::new("cmd-,", OpenSettings, None)]);
        let preferences = keyseal_core::preferences::Preferences::load(&config_dir);
        native::set_translucent_windows(preferences.translucent_windows, cx);
        views::set_always_show_details(preferences.always_show_details, cx);
        let settings_dir = config_dir.clone();
        let settings_events = events.clone();
        cx.on_action(move |_: &OpenSettings, cx| {
            settings_only(
                settings_dir.clone(),
                log,
                probe,
                settings_events.clone(),
                cx,
            )
        });
        cx.set_menus([Menu::new(strings::APP_NAME)
            .items([MenuItem::action(strings::SETTINGS_MENU_ITEM, OpenSettings)])]);
        cx.activate(true);

        match start {
            Start::Link(link) => {
                let _ = events.unbounded_send(Event::Link(link));
            }
            Start::Settings => settings_only(config_dir.clone(), log, probe, events.clone(), cx),
            Start::UrlEvent => {
                let events = events.clone();
                cx.spawn(async move |cx| {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    let _ = events.unbounded_send(Event::NoLink);
                })
                .detach();
            }
        }

        let mut windows = views::Windows::new(log);
        let mut jobs = Jobs::default();
        // A finished job's exit code, held while Settings stays open.
        let mut exit_code = 0;
        cx.spawn(async move |cx| {
            while let Some(event) = incoming.next().await {
                cx.update(|cx| match event {
                    Event::Link(link) if jobs.start() => {
                        start_job(link, windows.job_closed(), events.clone(), log, job)
                    }
                    Event::Link(_) => windows.busy(cx),
                    Event::NoLink if jobs.idle() => {
                        settings_only(config_dir.clone(), log, probe, events.clone(), cx)
                    }
                    Event::NoLink => {}
                    Event::Ui(request) => windows.handle(*request, cx),
                    Event::Finished => {
                        jobs.finished();
                        windows.close_all(cx);
                    }
                    Event::Done(code) => {
                        if jobs.done() {
                            if !views::settings_open(cx) {
                                std::process::exit(code)
                            }
                            exit_code = code;
                        }
                    }
                    Event::SettingsClosed => {
                        if cx.windows().is_empty() && jobs.idle() {
                            std::process::exit(exit_code)
                        }
                    }
                });
            }
        })
        .detach();
    });
    std::process::exit(0)
}

/// Runs `link` on a thread of its own; `cancelled` is set when the signer
/// cancels the job or closes its window.
fn start_job(
    link: String,
    cancelled: Arc<AtomicBool>,
    events: UnboundedSender<Event>,
    log: fn(&str),
    job: fn(&str, &mut dyn Ui) -> i32,
) {
    std::thread::spawn(move || {
        let mut ui = WindowUi {
            events: events.clone(),
            log,
            cancelled,
        };
        let code = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(&link, &mut ui)))
            .unwrap_or(1);
        // The daily catalogue and update checks run once the job is over
        // and its windows are gone, never before or during it.
        let _ = events.unbounded_send(Event::Finished);
        if let Some(Err(message)) = keyseal_core::catalogue::refresh() {
            log(&format!("Driver catalogue update failed: {message}"));
        }
        keyseal_core::update::after_job();
        let _ = events.unbounded_send(Event::Done(code));
    });
}

/// Opens the settings window; the app quits when the last window closes
/// and no job is running.
fn settings_only(
    config_dir: PathBuf,
    log: fn(&str),
    probe: Probe,
    events: UnboundedSender<Event>,
    cx: &mut App,
) {
    views::open_settings(config_dir, log, probe, cx);
    cx.on_window_closed(move |_, _| {
        let _ = events.unbounded_send(Event::SettingsClosed);
    })
    .detach();
}

/// The GPU the windows would render on, checked without opening a window:
/// the Metal device on macOS, `None` where this can't be told cheaply.
pub fn check_gpu() -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        metal::Device::system_default()
            .map(|device| Some(device.name().to_owned()))
            .ok_or_else(|| strings::NO_GPU.to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    Ok(None)
}

/// What the windows show about a job, copied off the flow's borrowed view.
#[derive(Clone)]
pub(crate) struct Job {
    host: String,
    insecure: bool,
    brand: Option<Brand>,
    kind: Kind,
    /// The job is claimed: the title, signer and documents are its own.
    /// Before the claim they're empty and the window shows the host only.
    claimed: bool,
    title: String,
    signer: String,
    /// A sign job's document titles, in order; empty for enrol.
    documents: Vec<String>,
}

#[derive(Clone)]
struct Brand {
    name: String,
    icon: Option<Vec<u8>>,
    /// `0xrrggbb`.
    accent: Option<u32>,
    /// The manifest's `translucent`: false asks for opaque windows.
    translucent: bool,
}

impl Job {
    fn of(view: &JobView) -> Self {
        Self {
            host: host(view.origin),
            insecure: view.origin.insecure,
            brand: view.branding.map(|branding| Brand {
                name: branding.manifest.name.clone(),
                icon: branding.icon.clone(),
                accent: branding
                    .manifest
                    .accent_color
                    .as_deref()
                    .and_then(|color| u32::from_str_radix(color.trim_start_matches('#'), 16).ok()),
                translucent: branding.manifest.translucent != Some(false),
            }),
            kind: view.kind,
            claimed: true,
            title: view.title.to_owned(),
            signer: view.signer.to_owned(),
            documents: view
                .documents
                .iter()
                .map(|document| plain(&document.title))
                .collect(),
        }
    }

    /// The job a link asks for, before it's claimed: never branding, which
    /// comes with the claimed job.
    fn unclaimed(origin: &Origin, kind: Kind) -> Self {
        Self {
            host: host(origin),
            insecure: origin.insecure,
            brand: None,
            kind,
            claimed: false,
            title: String::new(),
            signer: String::new(),
            documents: Vec::new(),
        }
    }

    /// The job signs several documents at once.
    fn is_batch(&self) -> bool {
        self.documents.len() > 1
    }
}

/// The origin's host, in the A-label form the origin holds, with the port
/// when it isn't the scheme's default.
fn host(origin: &Origin) -> String {
    let origin = origin.as_string();
    url::Url::parse(&origin)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?.to_owned();
            Some(match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host,
            })
        })
        .unwrap_or(origin)
}

/// Lowercase hex in groups of 8, four groups to a line.
pub(crate) fn group_digest(hex: &str) -> String {
    let groups: Vec<&str> = hex
        .as_bytes()
        .chunks(8)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();
    groups
        .chunks(4)
        .map(|line| line.join(" "))
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) enum Request {
    Trust {
        host: String,
        insecure: bool,
        reply: mpsc::Sender<bool>,
    },
    Job {
        job: Job,
        stage: Stage,
    },
    /// The job window gives way to a message, open until the user closes it.
    Message {
        heading: &'static str,
        message: String,
        reply: mpsc::Sender<()>,
    },
    /// The job window's `HWND`.
    #[cfg(windows)]
    WindowHandle {
        reply: mpsc::Sender<Option<isize>>,
    },
}

/// What the job window asks for. Each stage holds the channel its answer
/// goes back on; dropping it answers Cancel.
pub(crate) enum Stage {
    Pin {
        certificate: Option<String>,
        /// One per document, in order.
        digests: Option<Vec<String>>,
        pin_pad: bool,
        warning: Option<&'static str>,
        reply: mpsc::Sender<Option<Zeroizing<String>>>,
    },
    Confirm {
        certificate: String,
        /// One per document, in order.
        digests: Vec<String>,
        reply: mpsc::Sender<bool>,
    },
    Choose {
        subjects: Vec<String>,
        reply: mpsc::Sender<Option<usize>>,
    },
    /// Enrol through CNG: the job before the certificate store is read.
    Enrol { reply: mpsc::Sender<bool> },
    /// Answered; the flow is working until its next step or prompt.
    Busy,
    /// The flow is at this step.
    Progress(Step),
}

/// The flow's [`Ui`] on the background thread.
pub struct WindowUi {
    events: UnboundedSender<Event>,
    /// Records each step in `keyseal.log`; never given the link or the PIN.
    log: fn(&str),
    /// The signer cancelled the job or closed its window.
    cancelled: Arc<AtomicBool>,
}

impl WindowUi {
    fn ask<T>(&self, request: impl FnOnce(mpsc::Sender<T>) -> Request) -> Option<T> {
        let (reply, answer) = mpsc::channel();
        self.events
            .unbounded_send(Event::Ui(Box::new(request(reply))))
            .ok()?;
        answer.recv().ok()
    }

    /// A prompt the job waits on the signer for; Cancel once they cancelled.
    fn ask_signer<T>(&self, request: impl FnOnce(mpsc::Sender<T>) -> Request) -> Option<T> {
        if self.cancelled.load(Ordering::Relaxed) {
            return None;
        }
        (self.log)("Waiting for the signer.");
        self.ask(request)
    }
}

impl Ui for WindowUi {
    fn confirm_origin(&mut self, origin: &Origin) -> bool {
        self.ask_signer(|reply| Request::Trust {
            host: host(origin),
            insecure: origin.insecure,
            reply,
        })
        .unwrap_or(false)
    }

    fn choose_certificate(&mut self, job: &JobView, subjects: &[String]) -> Option<usize> {
        let subjects = subjects.iter().map(|subject| plain(subject)).collect();
        self.ask_signer(|reply| Request::Job {
            job: Job::of(job),
            stage: Stage::Choose { subjects, reply },
        })
        .flatten()
    }

    fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>> {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(prompt.job),
            stage: Stage::Pin {
                certificate: prompt.certificate.as_deref().map(plain),
                digests: prompt.digests.clone(),
                pin_pad: prompt.pin_pad,
                warning: prompt.pin_warning,
                reply,
            },
        })
        .flatten()
    }

    fn confirm_digest(&mut self, confirm: &DigestConfirm) -> bool {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(confirm.job),
            stage: Stage::Confirm {
                certificate: plain(&confirm.certificate),
                digests: confirm.digests.clone(),
                reply,
            },
        })
        .unwrap_or(false)
    }

    fn confirm_enrol(&mut self, job: &JobView) -> bool {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(job),
            stage: Stage::Enrol { reply },
        })
        .unwrap_or(false)
    }

    fn show_error(&mut self, message: &str) {
        // A job the signer cancelled opens no more windows; the error is in
        // the log.
        if self.cancelled.load(Ordering::Relaxed) {
            return;
        }
        self.ask(|reply| Request::Message {
            heading: strings::ERROR_HEADING,
            message: plain(message),
            reply,
        });
    }

    fn show_info(&mut self, message: &str) {
        self.ask(|reply| Request::Message {
            heading: strings::INFO_HEADING,
            message: plain(message),
            reply,
        });
    }

    fn progress(&mut self, progress: Progress) -> bool {
        if self.cancelled.load(Ordering::Relaxed) {
            return false;
        }
        // Each step's time also ends the one before.
        (self.log)(match progress.step {
            Step::Connecting => "Connecting.",
            Step::OpeningToken => "Claimed. Opening the token.",
            Step::CheckingCertificate => "Checking the certificate.",
            Step::Downloading => "Certificate checked. Downloading the documents.",
            Step::Signing => "Signing.",
            Step::Sending => "Signed. Sending the signatures.",
        });
        let job = match progress.job {
            Some(view) => Job::of(view),
            None => Job::unclaimed(progress.origin, progress.kind),
        };
        let _ = self.events.unbounded_send(Event::Ui(Box::new(Request::Job {
            job,
            stage: Stage::Progress(progress.step),
        })));
        true
    }

    #[cfg(windows)]
    fn window_handle(&self) -> Option<isize> {
        self.ask(|reply| Request::WindowHandle { reply }).flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_one_job_at_a_time_and_exits_after_the_last() {
        let mut jobs = Jobs::default();
        assert!(jobs.idle());
        assert!(jobs.start());
        // A second link while the first job's windows are up is refused.
        assert!(!jobs.start());
        jobs.finished();
        // Once they are gone, a link starts a job while the first job's
        // thread still runs the catalogue and update checks.
        assert!(jobs.start());
        assert!(!jobs.done(), "the second job keeps the app alive");
        assert!(!jobs.idle());
        jobs.finished();
        assert!(jobs.done());
        assert!(jobs.idle());
    }

    #[test]
    fn groups_digests_for_reading() {
        let sha256 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(
            group_digest(sha256),
            "00112233 44556677 8899aabb ccddeeff\n00112233 44556677 8899aabb ccddeeff"
        );
        let sha384 = "0123456789abcdef".repeat(6);
        let grouped = group_digest(&sha384);
        assert_eq!(grouped.lines().count(), 3);
        assert_eq!(grouped.replace([' ', '\n'], ""), sha384);
        assert_eq!(group_digest("abc"), "abc");
        assert_eq!(group_digest(""), "");
    }

    #[test]
    fn shows_hosts_with_non_default_ports() {
        let origin = |url: &str| Origin::of_url(&url::Url::parse(url).unwrap(), true).unwrap();
        assert_eq!(
            host(&origin("https://dash.example.org/v1/jobs/x")),
            "dash.example.org"
        );
        assert_eq!(
            host(&origin("https://dash.example.org:8443/")),
            "dash.example.org:8443"
        );
        assert_eq!(
            host(&origin("https://bücher.example/")),
            "xn--bcher-kva.example"
        );
        assert_eq!(host(&origin("http://127.0.0.1:3000/")), "127.0.0.1:3000");
    }
}

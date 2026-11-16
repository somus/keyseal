//! The KeySeal helper's windows, built with GPUI Kit. GPUI owns the main
//! thread; the job's flow runs on a background thread and reaches the
//! windows through the `bridge` module. Cancelling closes the job window at
//! once, and the flow unwinds behind it. Links that arrive while the app
//! runs (macOS sends them to the running app) start a job when none is
//! running.

mod bridge;
mod native;
mod strings;
mod views;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use gpui_kit::{App, KeyBinding, Menu, MenuItem, QuitMode, actions};
use keyseal_core::doctor::Report;
use keyseal_core::flow::Ui;

use bridge::{Request, WindowUi};

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

/// Where [`log`] writes, set once by [`launch`].
static LOG: OnceLock<fn(&str)> = OnceLock::new();

/// Records `message` in `keyseal.log`, what the user can't see in a
/// terminal; nothing before [`launch`], in tests and in the gallery.
pub(crate) fn log(message: &str) {
    if let Some(log) = LOG.get() {
        log(message);
    }
}

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
            if let Err(message) = views::gallery(&view, cx) {
                eprintln!("{message}");
                std::process::exit(2);
            }
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
    let _ = LOG.set(log);
    if let Err(message) = check_gpu() {
        log(&message);
        std::process::exit(1);
    }
    // GPUI panics when it can't set up the GPU, before any window opens;
    // record that where a browser-started helper can be diagnosed. The job
    // thread's panics are recorded by where they happened only: their
    // message could quote the link, which the log never holds.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        match std::thread::current().name() {
            Some("main") => log(&format!("KeySeal stopped: {info}")),
            Some(JOB_THREAD) => {
                if let Some(location) = info.location() {
                    log(&format!("The job stopped at {location}"));
                }
            }
            _ => {}
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
            settings_only(settings_dir.clone(), probe, settings_events.clone(), cx)
        });
        cx.set_menus([Menu::new(strings::APP_NAME)
            .items([MenuItem::action(strings::SETTINGS_MENU_ITEM, OpenSettings)])]);
        cx.activate(true);

        match start {
            Start::Link(link) => {
                let _ = events.unbounded_send(Event::Link(link));
            }
            Start::Settings => settings_only(config_dir.clone(), probe, events.clone(), cx),
            Start::UrlEvent => {
                let events = events.clone();
                cx.spawn(async move |cx| {
                    cx.background_executor().timer(Duration::from_secs(1)).await;
                    let _ = events.unbounded_send(Event::NoLink);
                })
                .detach();
            }
        }

        let mut windows = views::Windows::default();
        let mut jobs = Jobs::default();
        // A finished job's exit code, held while Settings stays open.
        let mut exit_code = 0;
        cx.spawn(async move |cx| {
            while let Some(event) = incoming.next().await {
                cx.update(|cx| match event {
                    Event::Link(link) if jobs.start() => {
                        start_job(link, windows.job_closed(), events.clone(), job)
                    }
                    Event::Link(_) => windows.busy(cx),
                    Event::NoLink if jobs.idle() => {
                        settings_only(config_dir.clone(), probe, events.clone(), cx)
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

/// The name of a job's thread, whose panics are logged.
const JOB_THREAD: &str = "job";

/// Runs `link` on a thread of its own, then the steps after a job: the
/// notice of an update left to install, the driver catalogue and the
/// update check. `cancelled` is set when the signer cancels the job or
/// closes its window. A panic in the job shows the error window; the panic
/// hook has logged it.
fn start_job(
    link: String,
    cancelled: Arc<AtomicBool>,
    events: UnboundedSender<Event>,
    job: fn(&str, &mut dyn Ui) -> i32,
) {
    let thread = std::thread::Builder::new().name(JOB_THREAD.into());
    let spawned = thread.spawn(move || {
        let mut ui = WindowUi {
            events: events.clone(),
            cancelled,
        };
        let code =
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(&link, &mut ui))) {
                Ok(code) => {
                    // An update this helper couldn't install over itself.
                    if let Some(notice) = keyseal_core::update::take_notice() {
                        ui.show_info(&notice);
                    }
                    code
                }
                Err(_) => {
                    ui.show_error(keyseal_core::flow::INTERNAL_ERROR);
                    1
                }
            };
        // The daily catalogue and update checks run once the job is over
        // and its windows are gone, never before or during it. A headless
        // run does none of these steps.
        let _ = events.unbounded_send(Event::Finished);
        if let Some(Err(message)) = keyseal_core::catalogue::refresh() {
            log(&format!("Driver catalogue update failed: {message}"));
        }
        if let Err(message) = keyseal_core::update::after_job() {
            log(&format!("Update check failed: {message}"));
        }
        let _ = events.unbounded_send(Event::Done(code));
    });
    spawned.expect("failed to spawn the job thread");
}

/// Opens the settings window; the app quits when the last window closes
/// and no job is running.
fn settings_only(config_dir: PathBuf, probe: Probe, events: UnboundedSender<Event>, cx: &mut App) {
    views::open_settings(config_dir, probe, cx);
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
}

//! The windows: the first-contact trust prompt, the job window, the message
//! window and the settings window, and [`Windows`], which opens them as the
//! flow's requests arrive.

#[cfg(any(feature = "gallery", test))]
mod gallery;
mod job;
mod message;
mod settings;
#[cfg(test)]
mod testing;
mod trust;
mod widgets;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use gpui_kit::{
    AnyWindowHandle, App, AppContext, Entity, KeyBinding, Render, WeakEntity, Window, WindowBounds,
    WindowOptions, actions, px, size,
};

use crate::{Request, Stage, native, strings};
#[cfg(feature = "gallery")]
pub use gallery::GALLERY_VIEWS;
#[cfg(feature = "gallery")]
pub(crate) use gallery::gallery;
#[cfg(test)]
pub(crate) use gallery::sample_report;
pub(crate) use job::set_always_show_details;
use job::{JobWindow, job_size, job_title};
use message::MessageWindow;
use settings::settings_window;
pub(crate) use settings::{open_settings, settings_open};
use trust::{TrustWindow, trust_height};

actions!(keyseal, [Submit, Cancel]);

/// Escape cancels in the job, message and settings windows. Enter closes
/// the message window and submits the job window's PIN stage only: it never
/// confirms a signature, a certificate or an enrolment.
const CONTEXT: &str = "KeySealWindow";
/// The trust prompt takes Escape only: a stray Enter mustn't trust a site.
const TRUST_CONTEXT: &str = "KeySealTrust";

pub(crate) fn key_bindings() -> Vec<KeyBinding> {
    vec![
        KeyBinding::new("enter", Submit, Some(CONTEXT)),
        KeyBinding::new("escape", Cancel, Some(CONTEXT)),
        KeyBinding::new("escape", Cancel, Some(TRUST_CONTEXT)),
    ]
}

/// The windows open for the flow's requests.
pub(crate) struct Windows {
    log: fn(&str),
    job: Option<(AnyWindowHandle, WeakEntity<JobWindow>)>,
    /// The signer cancelled the job or closed its window: later job
    /// requests answer Cancel. Shared with the job's thread.
    job_closed: Arc<AtomicBool>,
    /// The message that a link arrived while a job runs, while it is open.
    busy: Option<AnyWindowHandle>,
}

impl Windows {
    pub(crate) fn new(log: fn(&str)) -> Self {
        Self {
            log,
            job: None,
            job_closed: Arc::default(),
            busy: None,
        }
    }

    /// Set when the signer cancels the job that starts now.
    pub(crate) fn job_closed(&self) -> Arc<AtomicBool> {
        self.job_closed.clone()
    }

    pub(crate) fn handle(&mut self, request: Request, cx: &mut App) {
        match request {
            Request::Trust {
                host,
                insecure,
                reply,
            } => {
                // The first-contact prompt never shows branding (section 5).
                native::set_brand(None, true, cx);
                open(
                    strings::TRUST_WINDOW_TITLE,
                    440.,
                    trust_height(insecure),
                    self.log,
                    cx,
                    |window, cx| {
                        let view = cx.new(|cx| TrustWindow::new(host, insecure, reply, window, cx));
                        let weak = view.downgrade();
                        window.on_window_should_close(cx, move |_, cx| {
                            let _ = weak.update(cx, |view, _| view.reply.take());
                            true
                        });
                        view
                    },
                );
            }
            // Dropping the stage answers Cancel.
            Request::Job { .. } if self.job_closed.load(Ordering::Relaxed) => {}
            Request::Job { job, stage } => {
                if let Some((handle, view)) = &self.job {
                    let view = view.clone();
                    // A prompt after progress comes forward, as a new window
                    // would: the signer may have gone back to the browser.
                    let prompt = !matches!(stage, Stage::Busy | Stage::Progress(_));
                    let _ = handle.update(cx, |_, window, cx| {
                        let _ = view.update(cx, |view, cx| view.show(job, stage, window, cx));
                        if prompt {
                            window.activate_window();
                        }
                    });
                    if prompt {
                        cx.activate(true);
                    }
                    return;
                }
                let closed = self.job_closed.clone();
                let log = self.log;
                let (width, height) = job_size(&job);
                let (handle, view) = open(
                    job_title(&job),
                    width,
                    height,
                    self.log,
                    cx,
                    |window, cx| {
                        let view = cx.new(|cx| JobWindow::new(job, stage, closed, log, window, cx));
                        let weak = view.downgrade();
                        window.on_window_should_close(cx, move |_, cx| {
                            let _ = weak.update(cx, |view, _| view.cancelled());
                            true
                        });
                        view
                    },
                );
                self.job = Some((handle, view.downgrade()));
            }
            Request::Message {
                heading,
                message,
                reply,
            } => {
                if let Some((handle, _)) = self.job.take() {
                    let _ = handle.update(cx, |_, window, _| window.remove_window());
                }
                self.message(heading, message, Some(reply), cx);
            }
            #[cfg(windows)]
            Request::WindowHandle { reply } => {
                use raw_window_handle::{HasWindowHandle, RawWindowHandle};
                let hwnd = self.job.as_ref().and_then(|(handle, _)| {
                    handle
                        .update(cx, |_, window, _| {
                            match HasWindowHandle::window_handle(window).ok()?.as_raw() {
                                RawWindowHandle::Win32(win32) => Some(win32.hwnd.get()),
                                _ => None,
                            }
                        })
                        .ok()
                        .flatten()
                });
                let _ = reply.send(hwnd);
            }
        }
    }

    /// A link arrived while a job runs; the job's windows stay. One such
    /// message at a time: a later link brings it forward.
    pub(crate) fn busy(&mut self, cx: &mut App) {
        if let Some(handle) = self.busy
            && handle
                .update(cx, |_, window, _| window.activate_window())
                .is_ok()
        {
            return;
        }
        self.busy = Some(self.message(strings::BUSY_HEADING, strings::BUSY.into(), None, cx));
    }

    /// The job is over: closes its windows, and the next job starts afresh.
    /// Settings, which the signer may have opened from an error, stays open.
    pub(crate) fn close_all(&mut self, cx: &mut App) {
        let settings = settings_window(cx);
        for handle in cx.windows() {
            if Some(handle) != settings {
                let _ = handle.update(cx, |_, window, _| window.remove_window());
            }
        }
        self.job = None;
        self.job_closed = Arc::default();
        self.busy = None;
        native::set_brand(None, true, cx);
    }

    pub(super) fn message(
        &self,
        heading: &'static str,
        message: String,
        reply: Option<mpsc::Sender<()>>,
        cx: &mut App,
    ) -> AnyWindowHandle {
        let (handle, _) = open(strings::APP_NAME, 460., 260., self.log, cx, |window, cx| {
            let view = cx.new(|cx| MessageWindow::new(heading, message, reply, window, cx));
            let weak = view.downgrade();
            window.on_window_should_close(cx, move |_, cx| {
                let _ = weak.update(cx, |view, _| view.reply.take());
                true
            });
            view
        });
        handle
    }
}

/// Opens a window, or ends the process when the platform can't render one.
fn open<V: Render>(
    title: &'static str,
    width: f32,
    height: f32,
    log: fn(&str),
    cx: &mut App,
    build: impl FnOnce(&mut Window, &mut App) -> Entity<V>,
) -> (AnyWindowHandle, Entity<V>) {
    let (titlebar, window_background) = native::window_chrome(title, cx);
    let options = WindowOptions {
        window_bounds: Some(WindowBounds::centered(size(px(width), px(height)), cx)),
        titlebar: Some(titlebar),
        window_background,
        is_minimizable: false,
        is_resizable: false,
        // Matches keyseal.desktop, which gives the windows their icon on Linux.
        app_id: Some("keyseal".into()),
        ..Default::default()
    };
    let build = |window: &mut Window, cx: &mut App| {
        native::follow_appearance(window, cx);
        build(window, cx)
    };
    let opened = gpui_kit::open_window(options, cx, build).unwrap_or_else(|error| {
        log(&format!("{} {error}", strings::NO_GPU));
        std::process::exit(1)
    });
    // A window opens after the link's network round trip, or in a helper
    // already running from an earlier job, so the browser is usually still in
    // front; without this the window can sit behind it or on another desktop.
    cx.activate(true);
    opened
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AppContext, TestAppContext};

    use crate::views::testing::{certificate, job, open_windows, pass_input_delay, setup};

    use crate::{Request, Stage};

    #[gpui_kit::test]
    fn the_brand_accent_shows_in_the_job_window_only(cx: &mut TestAppContext) {
        use gpui_kit::component::ActiveTheme;
        let mut windows = setup(cx);
        let brand = gpui_kit::Hsla::from(gpui_kit::rgb(0x1f6feb));
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Busy,
                },
                cx,
            );
            assert_eq!(cx.theme().primary, brand);
            windows.handle(
                Request::Trust {
                    host: "dash.example.org".into(),
                    insecure: false,
                    reply: mpsc::channel().0,
                },
                cx,
            );
            // The first-contact prompt never shows branding.
            assert_ne!(cx.theme().primary, brand);
            windows.close_all(cx);
            assert_ne!(cx.theme().primary, brand);
        });
    }

    #[gpui_kit::test]
    fn the_manifest_and_the_preference_turn_glass_off(cx: &mut TestAppContext) {
        use gpui_kit::component::ActiveTheme;
        let mut windows = setup(cx);
        let opaque = |cx: &gpui_kit::App| cx.theme().background.a == 1.;
        let busy = |job| Request::Job {
            job,
            stage: Stage::Busy,
        };
        cx.update(|cx| {
            windows.handle(busy(job()), cx);
            // Glass where the platform and the system's settings allow it.
            let glass = !opaque(cx);
            assert_eq!(
                glass,
                crate::native::glass_platform() && !crate::native::reduce_transparency()
            );
            windows.close_all(cx);

            let mut opaque_job = job();
            opaque_job.brand.as_mut().unwrap().translucent = false;
            windows.handle(busy(opaque_job), cx);
            assert!(opaque(cx));
            windows.close_all(cx);
            windows.handle(busy(job()), cx);
            assert_eq!(!opaque(cx), glass);
            windows.close_all(cx);

            crate::native::set_translucent_windows(false, cx);
            windows.handle(busy(job()), cx);
            assert!(opaque(cx));
        });
    }

    /// A link during a job gets a window of its own, which later links
    /// reuse; after the job every window closes and the next job opens a
    /// new job window.
    #[gpui_kit::test]
    fn a_second_job_starts_afresh(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let choose = |reply| Request::Job {
            job: job(),
            stage: Stage::Choose {
                certificates: vec![certificate("One")],
                reply,
            },
        };
        let (reply, _first) = mpsc::channel();
        cx.update(|cx| windows.handle(choose(reply), cx));
        cx.update(|cx| windows.busy(cx));
        let open = open_windows(cx);
        assert_eq!(open.len(), 2);
        cx.update(|cx| windows.busy(cx));
        assert_eq!(open_windows(cx), open);
        cx.update(|cx| windows.close_all(cx));
        cx.run_until_parked();
        assert!(open_windows(cx).is_empty());

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| windows.handle(choose(reply), cx));
        let open = open_windows(cx);
        assert_eq!(open.len(), 1);
        pass_input_delay(cx);
        cx.update_window(open[0], |_, window, cx| {
            window.render_frame(cx);
            window.click("submit", cx);
        })
        .unwrap();
        assert_eq!(answer.recv(), Ok(Some(0)));
    }
}

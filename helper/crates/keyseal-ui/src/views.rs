//! The windows: the first-contact trust prompt, the job window, the message
//! window and the settings window, and [`Windows`], which opens them as the
//! flow's requests arrive.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::radio::Radio;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::switch::Switch;
use gpui_kit::component::{ActiveTheme, Disableable, Icon, Sizable, StyledExt, h_flex, v_flex};
use gpui_kit::{
    AnyElement, AnyWindowHandle, App, AppContext, ClipboardItem, Context, Div, Entity, FocusHandle,
    Focusable, Global, Hsla, Image, ImageFormat, InteractiveElement, IntoElement, KeyBinding,
    ParentElement, Render, RenderImage, Role, SharedString, StatefulInteractiveElement, Styled,
    Subscription, Task, TestSupportExt, WeakEntity, Window, WindowBounds, WindowOptions, actions,
    div, img, prelude::FluentBuilder, px, rems, rgb, size, white,
};
use keyseal_core::doctor::{Driver, DriverState, Report, Status};
use keyseal_core::flow::Step;
use keyseal_core::modules;
use keyseal_core::preferences::Preferences;
use keyseal_core::protocol::Kind;
use keyseal_core::trust::{Record, TrustStore};
use zeroize::Zeroizing;

use crate::{Job, Probe, Request, Stage, group_digest, native, strings};

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
}

impl Windows {
    pub(crate) fn new(log: fn(&str)) -> Self {
        Self {
            log,
            job: None,
            job_closed: Arc::default(),
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
                    260.,
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

    /// A link arrived while a job runs; the job's windows stay.
    pub(crate) fn busy(&self, cx: &mut App) {
        self.message(strings::BUSY_HEADING, strings::BUSY.into(), None, cx);
    }

    /// The job is over: closes every window, and the next job starts afresh.
    /// Closes the job's windows. Settings, which the signer may have opened
    /// from an error, stays open.
    pub(crate) fn close_all(&mut self, cx: &mut App) {
        let settings = settings_window(cx);
        for handle in cx.windows() {
            if Some(handle) != settings {
                let _ = handle.update(cx, |_, window, _| window.remove_window());
            }
        }
        self.job = None;
        self.job_closed = Arc::default();
        native::set_brand(None, true, cx);
    }

    fn message(
        &self,
        heading: &'static str,
        message: String,
        reply: Option<mpsc::Sender<()>>,
        cx: &mut App,
    ) {
        open(strings::APP_NAME, 460., 260., self.log, cx, |window, cx| {
            let view = cx.new(|cx| MessageWindow::new(heading, message, reply, window, cx));
            let weak = view.downgrade();
            window.on_window_should_close(cx, move |_, cx| {
                let _ = weak.update(cx, |view, _| view.reply.take());
                true
            });
            view
        });
    }
}

/// The open settings window, which a second request focuses.
struct SettingsHandle(AnyWindowHandle);

impl Global for SettingsHandle {}

/// The settings window, while it is open.
fn settings_window(cx: &mut App) -> Option<AnyWindowHandle> {
    let SettingsHandle(handle) = *cx.try_global::<SettingsHandle>()?;
    handle.update(cx, |_, _, _| ()).ok().map(|()| handle)
}

pub(crate) fn settings_open(cx: &mut App) -> bool {
    settings_window(cx).is_some()
}

pub(crate) fn open_settings(config_dir: PathBuf, log: fn(&str), probe: Probe, cx: &mut App) {
    if let Some(handle) = settings_window(cx) {
        let _ = handle.update(cx, |_, window, _| window.activate_window());
        return;
    }
    let (handle, _) = open(
        strings::SETTINGS_WINDOW_TITLE,
        560.,
        600.,
        log,
        cx,
        |window, cx| cx.new(|cx| SettingsWindow::new(config_dir, probe, window, cx)),
    );
    cx.set_global(SettingsHandle(handle));
}

/// The signer's choice to open the job window with the certificate and the
/// digest shown.
struct AlwaysShowDetails(bool);

impl Global for AlwaysShowDetails {}

pub(crate) fn set_always_show_details(on: bool, cx: &mut App) {
    cx.set_global(AlwaysShowDetails(on));
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

/// The job window's size: taller for a batch, so its list of documents
/// shows a few.
fn job_size(job: &Job) -> (f32, f32) {
    (520., if job.is_batch() { 640. } else { 560. })
}

fn job_title(job: &Job) -> &'static str {
    match job.kind {
        Kind::Sign if job.is_batch() => strings::SIGN_BATCH_WINDOW_TITLE,
        Kind::Sign => strings::SIGN_WINDOW_TITLE,
        Kind::Enrol => strings::ENROL_WINDOW_TITLE,
    }
}

fn window_frame(focus: &FocusHandle, context: &'static str, window: &mut Window, cx: &App) -> Div {
    window.set_rem_size(native::font_size());
    v_flex()
        .key_context(context)
        .track_focus(focus)
        .size_full()
        .pt(native::titlebar_inset())
        .font_family(cx.theme().font_family.clone())
        .text_size(rems(1.))
        .bg(cx.theme().background)
        .text_color(cx.theme().foreground)
}

/// A Lucide icon (ISC, `icons/LICENSE`), `name` as in `icons/<name>.svg`.
/// Only the icons the windows use are bundled.
fn icon(name: &'static str) -> Icon {
    let svg: &[u8] = match name {
        "shield-question-mark" => include_bytes!("../icons/shield-question-mark.svg"),
        "shield-alert" => include_bytes!("../icons/shield-alert.svg"),
        "signature" => include_bytes!("../icons/signature.svg"),
        "id-card" => include_bytes!("../icons/id-card.svg"),
        "file-text" => include_bytes!("../icons/file-text.svg"),
        "user-round" => include_bytes!("../icons/user-round.svg"),
        "badge-check" => include_bytes!("../icons/badge-check.svg"),
        "fingerprint-pattern" => include_bytes!("../icons/fingerprint-pattern.svg"),
        "chevron-down" => include_bytes!("../icons/chevron-down.svg"),
        "chevron-right" => include_bytes!("../icons/chevron-right.svg"),
        "triangle-alert" => include_bytes!("../icons/triangle-alert.svg"),
        "usb" => include_bytes!("../icons/usb.svg"),
        "lock-keyhole" => include_bytes!("../icons/lock-keyhole.svg"),
        "circle-alert" => include_bytes!("../icons/circle-alert.svg"),
        "hourglass" => include_bytes!("../icons/hourglass.svg"),
        "info" => include_bytes!("../icons/info.svg"),
        "globe" => include_bytes!("../icons/globe.svg"),
        "globe-lock" => include_bytes!("../icons/globe-lock.svg"),
        "trash" => include_bytes!("../icons/trash.svg"),
        "folder" => include_bytes!("../icons/folder.svg"),
        "layers" => include_bytes!("../icons/layers.svg"),
        "eye" => include_bytes!("../icons/eye.svg"),
        "circle-check" => include_bytes!("../icons/circle-check.svg"),
        "package" => include_bytes!("../icons/package.svg"),
        "refresh-cw" => include_bytes!("../icons/refresh-cw.svg"),
        "copy" => include_bytes!("../icons/copy.svg"),
        // KeySeal's own mark, from brand/keyseal-mark.svg.
        "keyseal" => include_bytes!("../icons/keyseal.svg"),
        _ => unreachable!("icon {name} isn't bundled"),
    };
    Icon::default().data(svg)
}

/// KeySeal's colour, for its own mark in Settings. The windows otherwise
/// keep the platform's accent, or the integrator's.
const BRAND: u32 = 0x5e5686;

/// A tinted square holding an icon, the way the platforms mark what a
/// dialog is about.
fn icon_tile(name: &'static str, tint: Hsla, cx: &App) -> impl IntoElement {
    div()
        .flex_none()
        .size_10()
        .rounded(cx.theme().radius_lg)
        .bg(tint.opacity(0.15))
        .flex()
        .items_center()
        .justify_center()
        .child(icon(name).size_5().text_color(tint))
}

/// The integrator's logo in the header tile, with a badge saying what the
/// job does. The tile is the size of [`icon_tile`], so the logo never
/// outgrows the site's name beside it (section 6.4).
fn logo_tile(logo: Arc<RenderImage>, badge: &'static str, cx: &App) -> impl IntoElement {
    let palette = native::palette(cx);
    div()
        .flex_none()
        .relative()
        .size_10()
        .child(img(logo).size_10().rounded(cx.theme().radius_lg))
        .child(
            div()
                .absolute()
                .right(px(-4.))
                .bottom(px(-4.))
                .size_5()
                .rounded_full()
                .bg(native::color(palette.window).alpha(1.))
                .border_1()
                .border_color(native::color(palette.separator))
                .flex()
                .items_center()
                .justify_center()
                .child(icon(badge).size_3().text_color(cx.theme().primary)),
        )
}

/// A strip with an icon and a sentence: a warning, or the insecure banner.
fn banner(
    id: &'static str,
    name: &'static str,
    tint: Hsla,
    text: &'static str,
    cx: &App,
) -> impl IntoElement {
    h_flex()
        .id(id)
        .role(Role::Alert)
        .aria_label(text)
        .items_start()
        .gap_2()
        .px_3()
        .py_2()
        .rounded(cx.theme().radius_lg)
        .bg(tint.opacity(0.14))
        .text_sm()
        .child(icon(name).size_4().mt_0p5().flex_none().text_color(tint))
        .child(div().flex_1().child(text))
        .test_support()
}

fn insecure_banner(cx: &App) -> impl IntoElement {
    banner(
        "insecure",
        "shield-alert",
        cx.theme().danger,
        strings::INSECURE_BANNER,
        cx,
    )
}

/// A grouped box of rows with dividers between them: a macOS form group,
/// a Windows settings card, a libadwaita boxed list.
fn group(rows: impl IntoIterator<Item = AnyElement>, cx: &App) -> Div {
    let palette = native::palette(cx);
    let separator = native::color(palette.separator);
    v_flex()
        // Full height in a scrolling column, which would otherwise squeeze it.
        .flex_shrink_0()
        .rounded(cx.theme().radius_lg)
        .border_1()
        .border_color(separator)
        .bg(native::color(palette.group))
        .overflow_hidden()
        .children(rows.into_iter().enumerate().map(move |(index, row)| {
            div()
                .when(index > 0, |this| this.border_t_1().border_color(separator))
                .child(row)
        }))
}

/// A group's row: an icon, then a label over its value, read out as
/// "label: value". With `shown`, that text stands for the value on screen,
/// in the monospace font.
fn field(
    id: &'static str,
    icon_name: &'static str,
    label: impl Into<SharedString>,
    value: impl Into<SharedString>,
    shown: Option<SharedString>,
    cx: &App,
) -> AnyElement {
    let label = label.into();
    let value = value.into();
    let mono = shown.is_some();
    h_flex()
        .items_start()
        .gap_3()
        .px_3()
        .py_2()
        .child(
            icon(icon_name)
                .size_4()
                .mt_0p5()
                .flex_none()
                .text_color(cx.theme().muted_foreground),
        )
        .child(
            v_flex()
                .flex_1()
                .min_w_0()
                .gap_0p5()
                .child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(label.clone()),
                )
                .child(
                    div()
                        .id(id)
                        .aria_label(SharedString::from(format!("{label}: {value}")))
                        .when(mono, |this| {
                            this.font_family(cx.theme().mono_font_family.clone())
                                .text_sm()
                        })
                        .child(shown.unwrap_or(value))
                        .test_support(),
                ),
        )
        .into_any_element()
}

/// The list of a batch's documents takes the height the window has left,
/// at least this much, and scrolls inside itself.
const DOCUMENT_LIST_MIN_HEIGHT: f32 = 120.;

/// A batch's documents in order, each numbered with its title and, once
/// round 1 has them, its digest, in a group that scrolls inside itself.
fn document_list(titles: &[String], digests: Option<&[String]>, cx: &App) -> AnyElement {
    let palette = native::palette(cx);
    let separator = native::color(palette.separator);
    v_flex()
        .id("documents")
        .mt_1()
        .min_h(px(DOCUMENT_LIST_MIN_HEIGHT))
        .overflow_y_scroll()
        .rounded(cx.theme().radius_lg)
        .border_1()
        .border_color(separator)
        .bg(native::color(palette.group))
        .children(titles.iter().enumerate().map(|(index, title)| {
            let digest = digests.and_then(|digests| digests.get(index));
            let label = match digest {
                Some(digest) => format!("{title}: {digest}"),
                None => title.clone(),
            };
            h_flex()
                .id(("document", index))
                .aria_label(SharedString::from(label))
                .items_start()
                .gap_3()
                .px_3()
                .py_2()
                .when(index > 0, |this| this.border_t_1().border_color(separator))
                .child(
                    div()
                        .flex_none()
                        .w_4()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("{}", index + 1)),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap_0p5()
                        .child(div().text_sm().child(title.clone()))
                        .when_some(digest, |this, digest| {
                            this.child(
                                div()
                                    .font_family(cx.theme().mono_font_family.clone())
                                    .text_xs()
                                    .text_color(cx.theme().muted_foreground)
                                    .child(group_digest(digest)),
                            )
                        }),
                )
                .test_support()
        }))
        .into_any_element()
}

/// A section's heading above its group.
/// The About group's first row: KeySeal's mark, name and version.
fn about(cx: &App) -> AnyElement {
    h_flex()
        .px_3()
        .py_3()
        .gap_3()
        .child(
            div()
                .flex_none()
                .size_10()
                .rounded(cx.theme().radius_lg)
                .bg(rgb(BRAND))
                .flex()
                .items_center()
                .justify_center()
                .child(icon("keyseal").size_6().text_color(white())),
        )
        .child(
            v_flex()
                .child(
                    div()
                        .font_weight(native::look().heading_weight)
                        .child(strings::APP_NAME),
                )
                .child(
                    div()
                        .id("version")
                        .aria_label(SharedString::from(format!(
                            "{}: {}",
                            strings::VERSION,
                            keyseal_core::VERSION
                        )))
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(format!("{} {}", strings::VERSION, keyseal_core::VERSION))
                        .test_support(),
                ),
        )
        .into_any_element()
}

fn section(heading: &'static str, cx: &App) -> impl IntoElement {
    div()
        .px_1()
        .text_sm()
        .font_weight(native::look().heading_weight)
        .text_color(cx.theme().muted_foreground)
        .child(heading)
}

fn note(text: &'static str, cx: &App) -> impl IntoElement {
    div()
        .text_sm()
        .text_color(cx.theme().muted_foreground)
        .child(text)
}

/// The window's buttons, laid out as the platform lays out a dialog's:
/// `primary` last on the trailing edge on macOS, first on a band of its
/// own on Windows, last across the full width with libadwaita.
fn button_bar(cancel: Option<Button>, primary: Button, cx: &App) -> Div {
    let look = native::look();
    let cancel = cancel.map(|button| secondary(button, cx));
    let wide = look.buttons != native::Buttons::TrailingPrimaryLast;
    let size = |button: Button| {
        if wide {
            button.flex_1()
        } else {
            button.min_w(px(look.button_min_width))
        }
    };
    let (first, second) = match look.buttons {
        native::Buttons::BandPrimaryFirst => (Some(primary), cancel),
        _ => (cancel, Some(primary)),
    };
    h_flex()
        .gap_2()
        .px_5()
        .py_4()
        .when(!wide, |this| this.justify_end())
        .when(look.buttons == native::Buttons::BandPrimaryFirst, |this| {
            let palette = native::palette(cx);
            this.bg(native::color(palette.band))
                .border_t_1()
                .border_color(native::color(palette.separator))
        })
        .children(first.map(size))
        .children(second.map(size))
}

/// A button other than the window's primary one, in the platform's colours.
fn secondary(button: Button, cx: &App) -> Button {
    let palette = native::palette(cx);
    button
        .bg(native::color(palette.control))
        .border_color(native::color(palette.control_border))
}

/// An alert: an icon over its heading and text, centred where the
/// platform centres them.
fn alert(tile: impl IntoElement, heading: impl IntoElement, body: impl IntoElement) -> Div {
    v_flex()
        .flex_1()
        .gap_3()
        .when(native::look().centered_alerts, |this| {
            this.items_center().text_center()
        })
        .child(tile)
        .child(v_flex().gap_1p5().child(heading).child(body))
}

/// The site's name and what it asks, the way permission prompts phrase it:
/// "example.org wants you to sign a document". The name is the heading.
fn site_heading(host: SharedString, ask: &'static str, cx: &App) -> impl IntoElement {
    v_flex()
        .gap_0p5()
        .child(
            div()
                .id("host")
                .role(Role::Heading)
                .aria_label(host.clone())
                .text_lg()
                .font_weight(native::look().heading_weight)
                .child(host)
                .test_support(),
        )
        .child(div().text_color(cx.theme().muted_foreground).child(ask))
}

/// A spinner beside what the job is doing, read out as that text.
fn progress_line(text: SharedString, cx: &App) -> impl IntoElement {
    let muted = cx.theme().muted_foreground;
    h_flex()
        .id("progress")
        .role(Role::Status)
        .aria_label(text.clone())
        .gap_2()
        .text_sm()
        .text_color(muted)
        .child(Spinner::new().small().color(muted))
        .child(text)
        .test_support()
}

/// How long a window's confirming button stays disabled after the window
/// shows or comes forward, as browsers do for permission prompts: the window
/// takes focus as it opens, so Tab and Enter or Space typed for another
/// window could otherwise press it.
const INPUT_DELAY: Duration = Duration::from_millis(700);

/// Whether [`INPUT_DELAY`] has passed since the window last showed or came
/// forward.
struct InputDelay {
    ready: bool,
    _timer: Task<()>,
    _activation: Subscription,
}

impl InputDelay {
    /// Starts the delay now and again whenever the window becomes active.
    /// `field` is where the view keeps it.
    fn new<T: 'static>(
        field: fn(&mut T) -> &mut InputDelay,
        window: &mut Window,
        cx: &mut Context<T>,
    ) -> Self {
        let activation = cx.observe_window_activation(window, move |this, window, cx| {
            if window.is_window_active() {
                field(this).restart(field, cx);
            }
        });
        Self {
            ready: false,
            _timer: Self::timer(field, cx),
            _activation: activation,
        }
    }

    fn restart<T: 'static>(&mut self, field: fn(&mut T) -> &mut InputDelay, cx: &mut Context<T>) {
        self.ready = false;
        self._timer = Self::timer(field, cx);
        cx.notify();
    }

    fn timer<T: 'static>(field: fn(&mut T) -> &mut InputDelay, cx: &mut Context<T>) -> Task<()> {
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(INPUT_DELAY).await;
            let _ = this.update(cx, |this, cx| {
                field(this).ready = true;
                cx.notify();
            });
        })
    }
}

/// The first-contact prompt (section 5): the host only, never branding.
struct TrustWindow {
    host: SharedString,
    insecure: bool,
    reply: Option<mpsc::Sender<bool>>,
    focus: FocusHandle,
    delay: InputDelay,
}

impl TrustWindow {
    fn new(
        host: String,
        insecure: bool,
        reply: mpsc::Sender<bool>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        Self {
            host: host.into(),
            insecure,
            reply: Some(reply),
            focus,
            delay: InputDelay::new(|this: &mut Self| &mut this.delay, window, cx),
        }
    }

    fn answer(&mut self, trust: bool, window: &mut Window) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(trust);
        }
        window.remove_window();
    }
}

impl Render for TrustWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        window_frame(&self.focus, TRUST_CONTEXT, window, cx)
            .on_action(cx.listener(|this, _: &Cancel, window, _| this.answer(false, window)))
            .child(
                v_flex()
                    .flex_1()
                    .px_6()
                    .pt_5()
                    .pb_2()
                    .gap_4()
                    .when(self.insecure, |this| this.child(insecure_banner(cx)))
                    .child(alert(
                        icon_tile("shield-question-mark", cx.theme().primary, cx),
                        site_heading(self.host.clone(), strings::TRUST_ASK, cx),
                        div()
                            .pt_1()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(strings::TRUST_EXPLANATION),
                    )),
            )
            .child(button_bar(
                Some(
                    Button::new("cancel")
                        .label(strings::CANCEL)
                        .on_click(cx.listener(|this, _, window, _| this.answer(false, window))),
                ),
                // Not the primary button: allowing a site should take a
                // deliberate choice.
                secondary(Button::new("trust"), cx)
                    .label(strings::TRUST)
                    .disabled(!self.delay.ready)
                    .on_click(cx.listener(|this, _, window, _| this.answer(true, window))),
                cx,
            ))
    }
}

/// The window for the rest of the job, one [`Stage`] at a time.
pub(crate) struct JobWindow {
    job: Job,
    /// The brand's logo, decoded when the job arrives so the first frame
    /// shows it.
    icon: Option<Arc<RenderImage>>,
    stage: Stage,
    pin: Entity<InputState>,
    selected: usize,
    /// The certificate and the digest are shown: at first when the signer
    /// chose that in Settings.
    details: bool,
    /// Set when the signer cancels; shared with the job's thread.
    closed: Arc<AtomicBool>,
    log: fn(&str),
    focus: FocusHandle,
    delay: InputDelay,
    _subscriptions: Vec<Subscription>,
}

impl JobWindow {
    fn new(
        job: Job,
        stage: Stage,
        closed: Arc<AtomicBool>,
        log: fn(&str),
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let pin = cx.new(|cx| {
            InputState::new(window, cx)
                .masked(true)
                .placeholder(strings::PIN_PLACEHOLDER)
        });
        // Re-render so the submit button follows whether a PIN is entered.
        let subscription = cx.subscribe(&pin, |_, _, event, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        });
        let mut this = Self {
            job: job.clone(),
            icon: None,
            stage: Stage::Busy,
            pin,
            selected: 0,
            details: cx.try_global::<AlwaysShowDetails>().is_some_and(|on| on.0),
            closed,
            log,
            focus: cx.focus_handle(),
            delay: InputDelay::new(|this: &mut Self| &mut this.delay, window, cx),
            _subscriptions: vec![subscription],
        };
        this.show(job, stage, window, cx);
        this
    }

    fn show(&mut self, job: Job, stage: Stage, window: &mut Window, cx: &mut Context<Self>) {
        window.set_window_title(job_title(&job));
        // The window opens before the claim says whether the job is a batch.
        if job.is_batch() != self.job.is_batch() {
            let (width, height) = job_size(&job);
            window.resize(size(px(width), px(height)));
        }
        native::set_brand(
            job.brand.as_ref().and_then(|brand| brand.accent),
            job.brand.as_ref().is_none_or(|brand| brand.translucent),
            cx,
        );
        self.icon = job
            .brand
            .as_ref()
            .and_then(|brand| brand.icon.clone())
            .and_then(|png| {
                Image::from_bytes(ImageFormat::Png, png)
                    .to_image_data(cx.svg_renderer())
                    .ok()
            });
        self.job = job;
        self.stage = stage;
        self.selected = 0;
        // Each stage's button asks for something new.
        self.delay.restart(|this: &mut Self| &mut this.delay, cx);
        if matches!(self.stage, Stage::Pin { pin_pad: false, .. }) {
            self.pin.update(cx, |pin, cx| pin.focus(window, cx));
        } else {
            window.focus(&self.focus, cx);
        }
        cx.notify();
    }

    fn pin_missing(&self, cx: &App) -> bool {
        matches!(self.stage, Stage::Pin { pin_pad: false, .. })
            && self.pin.read(cx).value().is_empty()
    }

    fn submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.pin_missing(cx) {
            return;
        }
        match std::mem::replace(&mut self.stage, Stage::Busy) {
            Stage::Pin { pin_pad, reply, .. } => {
                let pin = if pin_pad {
                    Zeroizing::default()
                } else {
                    Zeroizing::new(self.pin.read(cx).value().to_string())
                };
                // Also clears the field's undo history. The field's own
                // buffers can't be zeroised.
                self.pin
                    .update(cx, |input, cx| input.set_value("", window, cx));
                let _ = reply.send(Some(pin));
            }
            Stage::Confirm { reply, .. } | Stage::Enrol { reply } => {
                let _ = reply.send(true);
            }
            Stage::Choose { reply, .. } => {
                let _ = reply.send(Some(self.selected));
            }
            Stage::Busy | Stage::Progress(_) => {}
        }
        window.focus(&self.focus, cx);
        cx.notify();
    }

    /// Enter submits the PIN stage from the PIN field or the window itself;
    /// on a focused button it presses that button. In every other stage it
    /// does nothing, even on a button: focus returns to the window after a
    /// PIN, so a second Enter would otherwise sign. Those take a click, or
    /// Space on the focused button.
    fn on_submit(&mut self, _: &Submit, window: &mut Window, cx: &mut Context<Self>) {
        if !matches!(self.stage, Stage::Pin { .. }) {
            return;
        }
        if self.focus.is_focused(window) || self.pin.focus_handle(cx).is_focused(window) {
            self.submit(window, cx);
        } else {
            cx.propagate();
        }
    }

    /// The window closes at once; the flow logs out and reports the
    /// failure behind it.
    fn cancel(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.pin
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.cancelled();
        window.remove_window();
    }

    /// The signer cancelled or closed the window. Dropping the stage's
    /// channel answers Cancel; the flag answers Cancel to what follows.
    fn cancelled(&mut self) {
        if !self.closed.swap(true, Ordering::Relaxed) {
            (self.log)("Cancelled by the signer.");
        }
        self.stage = Stage::Busy;
    }

    fn step_text(&self, step: Step) -> SharedString {
        let batch = self.job.is_batch();
        let text = match step {
            Step::Connecting => strings::STEP_CONNECTING,
            Step::OpeningToken => strings::STEP_OPENING_TOKEN,
            Step::CheckingCertificate => strings::STEP_CHECKING_CERTIFICATE,
            Step::Downloading if batch => strings::STEP_DOWNLOADING_BATCH,
            Step::Downloading => strings::STEP_DOWNLOADING,
            Step::Signing => strings::STEP_SIGNING,
            Step::Sending if batch => strings::STEP_SENDING_BATCH,
            Step::Sending => strings::STEP_SENDING,
        };
        text.replace("{host}", &self.job.host).into()
    }

    fn stage_body(&self, cx: &mut Context<Self>) -> Div {
        let body = v_flex().gap_3();
        match &self.stage {
            Stage::Pin {
                pin_pad,
                warning,
                digests,
                ..
            } => body
                .when_some(*warning, |this, warning| {
                    this.child(banner(
                        "pin-warning",
                        "triangle-alert",
                        cx.theme().warning,
                        warning,
                        cx,
                    ))
                })
                .map(|this| {
                    if *pin_pad {
                        this.child(
                            h_flex()
                                .gap_2()
                                .child(icon("usb").size_4().text_color(cx.theme().muted_foreground))
                                .child(note(strings::PIN_PAD, cx)),
                        )
                    } else {
                        this.child(
                            v_flex()
                                .gap_1p5()
                                .child(div().text_sm().font_medium().child(strings::PIN))
                                .child(
                                    Input::new(&self.pin)
                                        .id("pin")
                                        .aria_label(strings::PIN)
                                        .prefix(
                                            icon("lock-keyhole")
                                                .size_4()
                                                .text_color(cx.theme().muted_foreground),
                                        ),
                                ),
                        )
                    }
                })
                .when(digests.is_none(), |this| {
                    this.child(note(
                        match self.job.kind {
                            Kind::Sign if self.job.is_batch() => strings::DIGESTS_NEXT,
                            Kind::Sign => strings::DIGEST_NEXT,
                            Kind::Enrol => strings::ENROL_NOTE,
                        },
                        cx,
                    ))
                }),
            Stage::Confirm { .. } if self.job.is_batch() => {
                body.child(note(strings::CONFIRM_BATCH_NOTE, cx))
            }
            Stage::Confirm { .. } => body.child(note(strings::CONFIRM_NOTE, cx)),
            Stage::Enrol { .. } => body.child(note(strings::ENROL_STORE_NOTE, cx)),
            Stage::Choose { subjects, .. } => {
                body.child(note(strings::CHOOSE_NOTE, cx)).child(group(
                    subjects.iter().enumerate().map(|(index, subject)| {
                        h_flex()
                            .gap_3()
                            .px_3()
                            .py_2p5()
                            .child(
                                Radio::new(("certificate", index))
                                    .label(subject.clone())
                                    .checked(index == self.selected)
                                    .on_click(cx.listener(move |this, _: &bool, _, cx| {
                                        this.selected = index;
                                        cx.notify();
                                    })),
                            )
                            .into_any_element()
                    }),
                    cx,
                ))
            }
            Stage::Busy => body.child(progress_line(strings::WORKING.into(), cx)),
            Stage::Progress(step) => body.child(progress_line(self.step_text(*step), cx)),
        }
    }
}

impl Render for JobWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (certificate, digests, submit) = match &self.stage {
            Stage::Pin {
                certificate,
                digests,
                ..
            } => (
                certificate.clone(),
                digests.clone(),
                if digests.is_some() {
                    strings::SIGN
                } else {
                    strings::CONTINUE
                },
            ),
            Stage::Confirm {
                certificate,
                digests,
                ..
            } => (
                Some(certificate.clone()),
                Some(digests.clone()),
                strings::CONFIRM,
            ),
            Stage::Choose { .. } | Stage::Enrol { .. } | Stage::Busy | Stage::Progress(_) => {
                (None, None, strings::CONTINUE)
            }
        };
        let busy = matches!(self.stage, Stage::Busy | Stage::Progress(_));
        let brand = self.job.brand.as_ref();
        let accent = brand
            .and_then(|brand| brand.accent)
            .map(|color| Hsla::from(rgb(color)));
        let batch = self.job.is_batch();
        let (kind_icon, ask) = match self.job.kind {
            Kind::Sign if batch => ("signature", strings::SIGN_BATCH_ASK),
            Kind::Sign => ("signature", strings::SIGN_ASK),
            Kind::Enrol => ("id-card", strings::ENROL_ASK),
        };
        // A batch lists its documents' titles; their digests wait behind
        // the details button with the certificate.
        let has_details = certificate.is_some() || digests.is_some();
        let title_label = if batch {
            SharedString::from(
                strings::DOCUMENT_COUNT.replace("{count}", &self.job.documents.len().to_string()),
            )
        } else {
            strings::TITLE.into()
        };
        let mut rows = vec![
            field(
                "title",
                "file-text",
                title_label,
                self.job.title.clone(),
                None,
                cx,
            ),
            field(
                "signer",
                "user-round",
                strings::SIGNER,
                self.job.signer.clone(),
                None,
                cx,
            ),
        ];
        if self.details {
            if let Some(certificate) = certificate {
                rows.push(field(
                    "certificate",
                    "badge-check",
                    strings::CERTIFICATE,
                    certificate,
                    None,
                    cx,
                ));
            }
            if let (Some([digest]), false) = (digests.as_deref(), batch) {
                let shown = SharedString::from(group_digest(digest));
                rows.push(field(
                    "digest",
                    "fingerprint-pattern",
                    strings::DIGEST,
                    digest.clone(),
                    Some(shown),
                    cx,
                ));
            }
        }
        let documents = batch.then(|| {
            let digests = digests.as_deref().filter(|_| self.details);
            document_list(&self.job.documents, digests, cx)
        });
        // The PIN field and the notes stay in view below the job, which
        // scrolls when the details of a batch outgrow the window. A list of
        // certificates scrolls with the job.
        let pinned = !matches!(self.stage, Stage::Choose { .. });

        window_frame(&self.focus, CONTEXT, window, cx)
            .on_action(cx.listener(Self::on_submit))
            .on_action(cx.listener(|this, _: &Cancel, window, cx| this.cancel(window, cx)))
            .when_some(accent, |this, accent| {
                this.border_t_3().border_color(accent)
            })
            .child(
                v_flex()
                    .flex_1()
                    .min_h(px(0.))
                    .child(
                        v_flex()
                            .id("job")
                            .min_h(px(0.))
                            .overflow_y_scroll()
                            .px_5()
                            .pt_4()
                            .map(|this| if pinned { this.pb_4() } else { this.pb_3() })
                            .gap_4()
                            .child(
                                h_flex()
                                    .items_start()
                                    .gap_3()
                                    .map(|this| match self.icon.clone() {
                                        Some(logo) => this.child(logo_tile(logo, kind_icon, cx)),
                                        None => this.child(icon_tile(
                                            kind_icon,
                                            accent.unwrap_or(cx.theme().primary),
                                            cx,
                                        )),
                                    })
                                    .child(
                                        v_flex()
                                            .gap_1()
                                            // Branding stays smaller than the origin
                                            // (section 6.4).
                                            .when_some(brand, |this, brand| {
                                                this.child(
                                                    h_flex()
                                                        .gap_1p5()
                                                        .text_sm()
                                                        .text_color(cx.theme().muted_foreground)
                                                        .child(brand.name.clone()),
                                                )
                                            })
                                            .child(site_heading(
                                                self.job.host.clone().into(),
                                                ask,
                                                cx,
                                            )),
                                    ),
                            )
                            .when(self.job.insecure, |this| this.child(insecure_banner(cx)))
                            .child(
                                v_flex()
                                    .min_h(px(0.))
                                    .gap_1()
                                    // Before the claim there is only the host
                                    // to show.
                                    .when(self.job.claimed, |this| this.child(group(rows, cx)))
                                    .children(documents)
                                    .when(has_details, |this| {
                                        this.child(
                                            h_flex().child(
                                                Button::new("details")
                                                    .ghost()
                                                    .small()
                                                    .icon(icon(if self.details {
                                                        "chevron-down"
                                                    } else {
                                                        "chevron-right"
                                                    }))
                                                    .label(if self.details {
                                                        strings::HIDE_DETAILS
                                                    } else {
                                                        strings::SHOW_DETAILS
                                                    })
                                                    .on_click(cx.listener(|this, _, _, cx| {
                                                        this.details = !this.details;
                                                        cx.notify();
                                                    })),
                                            ),
                                        )
                                    }),
                            )
                            .when(!pinned, |this| this.child(self.stage_body(cx))),
                    )
                    .when(pinned, |this| {
                        this.child(self.stage_body(cx).flex_shrink_0().px_5().pb_3())
                    }),
            )
            .child(button_bar(
                Some(
                    Button::new("cancel")
                        .label(strings::CANCEL)
                        .on_click(cx.listener(|this, _, window, cx| this.cancel(window, cx))),
                ),
                // While the job works, the spinner is beside its step.
                Button::new("submit")
                    .primary()
                    .label(submit)
                    .disabled(busy || self.pin_missing(cx) || !self.delay.ready)
                    .on_click(cx.listener(|this, _, window, cx| this.submit(window, cx))),
                cx,
            ))
    }
}

/// The flow's error or a notice, kept open until the user closes it.
struct MessageWindow {
    heading: &'static str,
    message: SharedString,
    no_driver: bool,
    reply: Option<mpsc::Sender<()>>,
    focus: FocusHandle,
}

impl MessageWindow {
    fn new(
        heading: &'static str,
        message: String,
        reply: Option<mpsc::Sender<()>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        Self {
            heading,
            no_driver: message.starts_with(modules::NO_DRIVER),
            message: message.into(),
            reply,
            focus,
        }
    }

    fn close(&mut self, window: &mut Window) {
        self.reply.take();
        window.remove_window();
    }
}

impl Render for MessageWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (tile, tint) = match self.heading {
            strings::ERROR_HEADING => ("circle-alert", cx.theme().danger),
            strings::BUSY_HEADING => ("hourglass", cx.theme().primary),
            _ => ("info", cx.theme().primary),
        };
        window_frame(&self.focus, CONTEXT, window, cx)
            .on_action(cx.listener(|this, _: &Submit, window, _| this.close(window)))
            .on_action(cx.listener(|this, _: &Cancel, window, _| this.close(window)))
            .child(
                v_flex()
                    .id("error")
                    .role(Role::Alert)
                    .aria_label(self.message.clone())
                    .flex_1()
                    .overflow_y_scroll()
                    .px_6()
                    .pt_5()
                    .pb_2()
                    .child(alert(
                        icon_tile(tile, tint, cx),
                        div()
                            .text_lg()
                            .font_weight(native::look().heading_weight)
                            .child(self.heading),
                        v_flex().gap_2().text_sm().child(self.message.clone()).when(
                            self.no_driver,
                            |this| {
                                this.child(
                                    div()
                                        .id("doctor-hint")
                                        .aria_label(strings::DOCTOR_HINT)
                                        .text_color(cx.theme().muted_foreground)
                                        .child(strings::DOCTOR_HINT)
                                        .test_support(),
                                )
                            },
                        ),
                    ))
                    .test_support(),
            )
            .child(button_bar(
                self.no_driver.then(|| {
                    Button::new("show-tokens")
                        .label(strings::TOKENS)
                        .on_click(|_, _, cx| cx.dispatch_action(&crate::OpenSettings))
                }),
                Button::new("close")
                    .primary()
                    .label(strings::CLOSE)
                    .on_click(cx.listener(|this, _, window, _| this.close(window))),
                cx,
            ))
    }
}

/// Trusted origins with Forget, the tokens and drivers, the signer's
/// preferences, the version and the config directory.
struct SettingsWindow {
    config_dir: PathBuf,
    records: Result<Vec<Record>, String>,
    preferences: Preferences,
    /// The switch whose change wasn't saved, and why.
    preferences_error: Option<(&'static str, String)>,
    probe: Probe,
    /// What the probe found; `None` while it runs.
    tokens: Option<Result<Report, String>>,
    /// The report is on the clipboard.
    copied: bool,
    /// The running probe, dropped with the window.
    _probing: Task<()>,
    focus: FocusHandle,
}

impl SettingsWindow {
    fn new(config_dir: PathBuf, probe: Probe, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        let records = TrustStore::new(&config_dir).list();
        let preferences = Preferences::load(&config_dir);
        let mut this = Self {
            config_dir,
            records,
            preferences,
            preferences_error: None,
            probe,
            tokens: None,
            copied: false,
            _probing: Task::ready(()),
            focus,
        };
        this.check_tokens(cx);
        this
    }

    /// Runs the probe on the background executor; it loads drivers, which
    /// can take seconds.
    fn check_tokens(&mut self, cx: &mut Context<Self>) {
        let probe = self.probe;
        self.tokens = None;
        self.copied = false;
        self._probing = cx.spawn(async move |this, cx| {
            let tokens = cx.background_executor().spawn(async move { probe() }).await;
            let _ = this.update(cx, |this, cx| {
                this.tokens = Some(tokens);
                cx.notify();
            });
        });
        cx.notify();
    }

    fn copy_diagnostics(&mut self, cx: &mut Context<Self>) {
        if let Some(Ok(report)) = &self.tokens {
            cx.write_to_clipboard(ClipboardItem::new_string(report.text.clone()));
            self.copied = true;
            cx.notify();
        }
    }

    fn save_preferences(&mut self, switch: &'static str, cx: &mut Context<Self>) {
        self.preferences_error = self
            .preferences
            .save(&self.config_dir)
            .err()
            .map(|error| (switch, error));
        cx.notify();
    }

    fn set_translucent_windows(&mut self, on: bool, cx: &mut Context<Self>) {
        self.preferences.translucent_windows = on;
        self.save_preferences("translucent-windows", cx);
        native::set_translucent_windows(on, cx);
    }

    fn set_always_show_details(&mut self, on: bool, cx: &mut Context<Self>) {
        self.preferences.always_show_details = on;
        self.save_preferences("always-show-details", cx);
        set_always_show_details(on, cx);
    }

    fn forget(&mut self, origin: &str, cx: &mut Context<Self>) {
        let store = TrustStore::new(&self.config_dir);
        self.records = store.forget(origin).and_then(|_| store.list());
        cx.notify();
    }
}

/// A row with an icon, a title and lines under it, read out as
/// "title: lines".
fn status_row(
    id: impl Into<SharedString>,
    icon_name: &'static str,
    tint: Hsla,
    title: impl Into<SharedString>,
    lines: Vec<SharedString>,
    cx: &App,
) -> AnyElement {
    let title = title.into();
    let label = if lines.is_empty() {
        title.clone()
    } else {
        SharedString::from(format!("{title}: {}", lines.join(", ")))
    };
    h_flex()
        .id(id.into())
        .aria_label(label)
        .items_start()
        .gap_3()
        .px_3()
        .py_2()
        .child(
            icon(icon_name)
                .size_4()
                .mt_0p5()
                .flex_none()
                .text_color(tint),
        )
        .child(
            v_flex()
                .flex_1()
                .min_w_0()
                .gap_0p5()
                .child(title)
                .children(lines.into_iter().map(|line| {
                    div()
                        .text_sm()
                        .text_color(cx.theme().muted_foreground)
                        .child(line)
                })),
        )
        .test_support()
        .into_any_element()
}

/// How a driver went, in plain words, then with `name` its file name, then
/// any reason.
fn driver_lines(driver: &Driver, name: bool) -> Vec<SharedString> {
    let (state, reason) = match &driver.state {
        DriverState::Used => (strings::DRIVER_USED, None),
        DriverState::NoToken => (strings::DRIVER_NO_TOKEN, None),
        DriverState::Failed(reason) => (strings::DRIVER_FAILED, Some(reason.clone())),
        DriverState::Missing => (strings::DRIVER_MISSING, None),
        DriverState::NotTried => (strings::DRIVER_NOT_TRIED, None),
    };
    [
        Some(state.into()),
        name.then(|| driver.name.clone().into()),
        reason.map(Into::into),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The driver that tells most about a plugged-in token: the one used, else
/// one that failed, else one that loaded, else one installed.
fn token_driver<'a>(report: &'a Report, token: &str) -> Option<&'a Driver> {
    let rank = |driver: &&Driver| match driver.state {
        DriverState::Used => 0,
        DriverState::Failed(_) => 1,
        DriverState::NoToken => 2,
        DriverState::NotTried => 3,
        DriverState::Missing => 4,
    };
    report
        .drivers
        .iter()
        .filter(|driver| driver.token.as_deref() == Some(token))
        .min_by_key(rank)
}

impl SettingsWindow {
    /// A switch with its label, what it does, and any error saving it.
    #[allow(clippy::too_many_arguments)]
    fn switch(
        &self,
        id: &'static str,
        icon_name: &'static str,
        label: &'static str,
        note: &'static str,
        checked: bool,
        set: fn(&mut Self, bool, &mut Context<Self>),
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let muted = cx.theme().muted_foreground;
        let error = self
            .preferences_error
            .as_ref()
            .filter(|(switch, _)| *switch == id)
            .map(|(_, error)| error.clone());
        h_flex()
            .px_3()
            .py_2()
            .gap_3()
            .items_start()
            .child(
                icon(icon_name)
                    .size_4()
                    .flex_none()
                    .mt_0p5()
                    .text_color(muted),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .child(label)
                    .child(div().text_sm().text_color(muted).child(note))
                    .when_some(error, |this, error| {
                        this.child(div().text_sm().text_color(cx.theme().danger).child(error))
                    }),
            )
            .child(
                div().flex_none().child(
                    Switch::new(id)
                        .checked(checked)
                        .accessibility_label(label)
                        .on_change(cx.listener(move |this, on: &bool, _, cx| set(this, *on, cx))),
                ),
            )
            .into_any_element()
    }

    /// What the probe found: a summary, each plugged-in token with its
    /// driver, the other drivers that loaded or failed, then Refresh and
    /// Copy diagnostics.
    fn tokens(&self, cx: &mut Context<Self>) -> Vec<AnyElement> {
        let muted = cx.theme().muted_foreground;
        let danger = cx.theme().danger;
        let mut rows = Vec::new();
        match &self.tokens {
            None => rows.push(status_row(
                "tokens-status",
                "hourglass",
                muted,
                strings::CHECKING_TOKENS,
                vec![],
                cx,
            )),
            Some(Err(message)) => rows.push(status_row(
                "tokens-status",
                "circle-alert",
                danger,
                strings::CHECK_FAILED,
                vec![message.clone().into()],
                cx,
            )),
            Some(Ok(report)) => {
                rows.push(match &report.status {
                    Status::Ready => status_row(
                        "tokens-status",
                        "circle-check",
                        cx.theme().success,
                        strings::TOKEN_READY,
                        vec![strings::TOKEN_READY_NOTE.into()],
                        cx,
                    ),
                    Status::NoToken => status_row(
                        "tokens-status",
                        "usb",
                        muted,
                        strings::NO_TOKEN_FOUND,
                        vec![strings::NO_TOKEN_NOTE.into()],
                        cx,
                    ),
                    Status::Failed(reason) => status_row(
                        "tokens-status",
                        "circle-alert",
                        danger,
                        strings::TOKEN_PROBLEM,
                        vec![reason.clone().into()],
                        cx,
                    ),
                });
                for token in report.devices.iter().filter_map(|d| d.token.as_deref()) {
                    let lines = match token_driver(report, token) {
                        Some(driver) => driver_lines(driver, true),
                        None => vec![strings::NO_DRIVER_LISTED.into()],
                    };
                    rows.push(status_row(
                        format!("token {token}"),
                        "usb",
                        muted,
                        token.to_owned(),
                        lines,
                        cx,
                    ));
                }
                for driver in report.drivers.iter().filter(|driver| {
                    driver.token.is_none()
                        && matches!(
                            driver.state,
                            DriverState::Used | DriverState::NoToken | DriverState::Failed(_)
                        )
                }) {
                    rows.push(status_row(
                        format!("driver {}", driver.detail),
                        "package",
                        muted,
                        driver.name.clone(),
                        driver_lines(driver, false),
                        cx,
                    ));
                }
            }
        }
        let checking = self.tokens.is_none();
        let checked = matches!(self.tokens, Some(Ok(_)));
        rows.push(
            h_flex()
                .gap_2()
                .pl_3()
                .pr_2()
                .py_2()
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .text_sm()
                        .text_color(muted)
                        .child(strings::DIAGNOSTICS_NOTE),
                )
                .child(
                    secondary(Button::new("refresh"), cx)
                        .small()
                        .flex_none()
                        .icon(icon("refresh-cw"))
                        .label(strings::REFRESH)
                        .loading(checking)
                        .disabled(checking)
                        .on_click(cx.listener(|this, _, _, cx| this.check_tokens(cx))),
                )
                .child(
                    secondary(Button::new("copy-diagnostics"), cx)
                        .small()
                        .flex_none()
                        .icon(icon("copy"))
                        .label(if self.copied {
                            strings::COPIED
                        } else {
                            strings::COPY_DIAGNOSTICS
                        })
                        .disabled(!checked)
                        .on_click(cx.listener(|this, _, _, cx| this.copy_diagnostics(cx))),
                )
                .into_any_element(),
        );
        rows
    }
}

impl Render for SettingsWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let sites: Vec<AnyElement> = match &self.records {
            Err(message) => vec![
                h_flex()
                    .gap_3()
                    .px_3()
                    .py_2()
                    .child(icon("circle-alert").size_4().text_color(cx.theme().danger))
                    .child(message.clone())
                    .into_any_element(),
            ],
            Ok(records) if records.is_empty() => vec![
                v_flex()
                    .items_center()
                    .gap_2()
                    .px_3()
                    .py_5()
                    .child(icon("globe").size_6().text_color(muted))
                    .child(note(strings::NO_TRUSTED_SITES, cx))
                    .into_any_element(),
            ],
            Ok(records) => records
                .iter()
                .map(|record| {
                    let origin = record.origin.clone();
                    h_flex()
                        .gap_3()
                        .pl_3()
                        .pr_2()
                        .py_1p5()
                        .child(icon("globe-lock").size_4().flex_none().text_color(muted))
                        .child(div().flex_1().min_w_0().child(record.origin.clone()))
                        .child(
                            Button::new(SharedString::from(format!("forget {origin}")))
                                .ghost()
                                .small()
                                .icon(icon("trash"))
                                .tooltip(strings::FORGET)
                                .accessibility_label(SharedString::from(format!(
                                    "{} {origin}",
                                    strings::FORGET
                                )))
                                .on_click(
                                    cx.listener(move |this, _, _, cx| this.forget(&origin, cx)),
                                ),
                        )
                        .into_any_element()
                })
                .collect(),
        };
        let signing = self.switch(
            "always-show-details",
            "eye",
            strings::ALWAYS_SHOW_DETAILS,
            strings::ALWAYS_SHOW_DETAILS_NOTE,
            self.preferences.always_show_details,
            Self::set_always_show_details,
            cx,
        );
        let tokens = self.tokens(cx);
        window_frame(&self.focus, CONTEXT, window, cx)
            .on_action(cx.listener(|_, _: &Cancel, window, _| window.remove_window()))
            .child(
                v_flex()
                    .id("settings")
                    .flex_1()
                    .overflow_y_scroll()
                    .px_5()
                    .pt_4()
                    .pb_5()
                    .gap_2()
                    .child(section(strings::TRUSTED_SITES, cx))
                    .child(group(sites, cx))
                    .child(div().h_3())
                    .child(section(strings::TOKENS, cx))
                    .child(group(tokens, cx))
                    .child(div().h_3())
                    .child(section(strings::SIGNING, cx))
                    .child(group([signing], cx))
                    .when(native::glass_platform(), |this| {
                        let appearance = self.switch(
                            "translucent-windows",
                            "layers",
                            strings::TRANSLUCENT_WINDOWS,
                            strings::TRANSLUCENT_NOTE,
                            self.preferences.translucent_windows,
                            Self::set_translucent_windows,
                            cx,
                        );
                        this.child(div().h_3())
                            .child(section(strings::APPEARANCE, cx))
                            .child(group([appearance], cx))
                    })
                    .child(div().h_3())
                    .child(section(strings::ABOUT, cx))
                    .child(group(
                        [
                            about(cx),
                            field(
                                "config-directory",
                                "folder",
                                strings::CONFIG_DIRECTORY,
                                self.config_dir.display().to_string(),
                                None,
                                cx,
                            ),
                        ],
                        cx,
                    )),
            )
    }
}

/// Every view [`gallery`] opens.
#[cfg(feature = "gallery")]
pub const GALLERY_VIEWS: &[&str] = &[
    "trust",
    "trust-insecure",
    "pin",
    "pin-details",
    "pin-plain",
    "pin-opaque",
    "pin-pad",
    "pin-warning",
    "pin-batch",
    "pin-batch-details",
    "confirm",
    "choose",
    "enrol",
    "busy",
    "progress-connecting",
    "progress-certificate",
    "message",
    "message-driver",
    "busy-message",
    "settings",
    "settings-empty",
    "settings-checking",
    "settings-driver-failed",
];

/// What a probe might find on a Mac with a HYP2003 plugged in: `status`,
/// with the plugged-in driver used, failed, or seeing no token.
#[cfg(any(feature = "gallery", test))]
pub(crate) fn sample_report(status: Status) -> Report {
    use keyseal_core::doctor::Device;
    let plugged = match &status {
        Status::Ready => DriverState::Used,
        Status::NoToken => DriverState::NoToken,
        Status::Failed(reason) => DriverState::Failed(reason.clone()),
    };
    let devices = match &status {
        Status::NoToken => vec![],
        _ => vec![Device {
            id: "2ccf:080a".into(),
            product: Some("HYP2003".into()),
            token: Some("HyperSecu HYP2003".into()),
        }],
    };
    Report {
        devices,
        drivers: vec![
            Driver {
                name: "libcastle.dylib".into(),
                detail: "/usr/local/lib/libcastle.dylib [catalogue, HyperSecu HYP2003 plugged in]"
                    .into(),
                token: Some("HyperSecu HYP2003".into()),
                state: plugged,
            },
            Driver {
                name: "libeTPkcs11.dylib".into(),
                detail: "/usr/local/lib/libeTPkcs11.dylib [known drivers]".into(),
                token: None,
                state: DriverState::NoToken,
            },
            Driver {
                name: "libmtoken.dylib".into(),
                detail: "/usr/local/lib/libmtoken.dylib [known drivers]".into(),
                token: None,
                state: DriverState::Missing,
            },
        ],
        text: "keyseal 0.1.0\nOS: macos aarch64\nTokens: sample\n".into(),
        status,
    }
}

/// Opens `view` with sample data. Answers go nowhere.
#[cfg(feature = "gallery")]
pub(crate) fn gallery(view: &str, cx: &mut App) {
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const CERTIFICATE: &str = "ASHA RAO (Verasys Sub CA 2022), valid until 12 March 2027";
    let job = |kind| Job {
        host: "sign.example.org".into(),
        insecure: false,
        brand: Some(crate::Brand {
            name: "Example Trust".into(),
            icon: (!view.ends_with("-plain"))
                .then(|| include_bytes!("../examples/sample-logo.png").to_vec()),
            accent: Some(0xe8590c),
            translucent: !view.ends_with("-opaque"),
        }),
        kind,
        claimed: true,
        title: "Circular 2026/14: Operation of bank accounts".into(),
        signer: "Asha Rao".into(),
        documents: vec!["Circular 2026/14: Operation of bank accounts".into()],
    };
    let pin = |certificate: Option<&str>, digest: Option<&str>, pin_pad, warning| Stage::Pin {
        certificate: certificate.map(Into::into),
        digests: digest.map(|digest| vec![digest.into()]),
        pin_pad,
        warning,
        reply: mpsc::channel().0,
    };
    let mut windows = Windows::new(|_| {});
    // pin-details: the signer chose to always see the technical details.
    set_always_show_details(matches!(view, "pin-details" | "pin-batch-details"), cx);
    if view.starts_with("pin-batch") {
        // The most a job may carry, one of them with a title that must wrap.
        let mut documents: Vec<String> = (1..=20)
            .map(|n| format!("Resolution 2026/{n:02}: Annual accounts and audit"))
            .collect();
        documents[0] = "Minutes of the 41st meeting of the Board of Trustees held at the registered office on 12 March 2026, with annexures A to F and the statement of accounts".into();
        let digests = (0..documents.len())
            .map(|n| format!("{n:02x}{}", &DIGEST[2..]))
            .collect();
        let mut batch = job(Kind::Sign);
        batch.title = "Board pack for March 2026, 20 documents".into();
        batch.documents = documents;
        windows.handle(
            Request::Job {
                job: batch,
                stage: Stage::Pin {
                    certificate: Some(CERTIFICATE.into()),
                    digests: Some(digests),
                    pin_pad: false,
                    warning: None,
                    reply: mpsc::channel().0,
                },
            },
            cx,
        );
        std::mem::forget(windows);
        return;
    }
    let stage = match view {
        "trust" | "trust-insecure" => {
            windows.handle(
                Request::Trust {
                    host: if view == "trust" {
                        "sign.example.org".into()
                    } else {
                        "localhost:3021".into()
                    },
                    insecure: view == "trust-insecure",
                    reply: mpsc::channel().0,
                },
                cx,
            );
            return;
        }
        "message" | "message-driver" => {
            let message = if view == "message" {
                "The signing service refused the signature: the certificate has expired.".into()
            } else {
                format!(
                    "{} Install your token's driver, then try again.",
                    modules::NO_DRIVER
                )
            };
            windows.message(strings::ERROR_HEADING, message, None, cx);
            return;
        }
        "busy-message" => {
            windows.busy(cx);
            return;
        }
        // Before the claim: the host only, never branding.
        "progress-connecting" => {
            windows.handle(
                Request::Job {
                    job: Job {
                        brand: None,
                        claimed: false,
                        title: String::new(),
                        signer: String::new(),
                        documents: Vec::new(),
                        ..job(Kind::Sign)
                    },
                    stage: Stage::Progress(Step::Connecting),
                },
                cx,
            );
            std::mem::forget(windows);
            return;
        }
        "progress-certificate" => Stage::Progress(Step::CheckingCertificate),
        "settings" | "settings-empty" | "settings-checking" | "settings-driver-failed" => {
            let dir = std::env::temp_dir().join(format!("keyseal-gallery-{view}"));
            let _ = std::fs::remove_dir_all(&dir);
            if view == "settings" {
                let store = TrustStore::new(&dir);
                for url in ["https://sign.example.org/", "https://dash.example.org/"] {
                    let url = url::Url::parse(url).expect("sample URL");
                    let origin =
                        keyseal_core::origin::Origin::of_url(&url, false).expect("sample origin");
                    store.trust(&origin).expect("sample trust store");
                }
            }
            let probe: Probe = match view {
                "settings" => || Ok(sample_report(Status::Ready)),
                "settings-empty" => || Ok(sample_report(Status::NoToken)),
                "settings-checking" => || {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                    Err("Timed out.".into())
                },
                _ => || {
                    Ok(sample_report(Status::Failed(
                        "Couldn't start the token driver: the driver is for another kind of Mac."
                            .into(),
                    )))
                },
            };
            open_settings(dir, |_| {}, probe, cx);
            return;
        }
        // pin-plain: a brand without a logo; pin-opaque: a brand that asks
        // for opaque windows.
        "pin" | "pin-details" | "pin-plain" | "pin-opaque" => {
            pin(Some(CERTIFICATE), Some(DIGEST), false, None)
        }
        "pin-pad" => pin(Some(CERTIFICATE), Some(DIGEST), true, None),
        "pin-warning" => pin(
            None,
            None,
            false,
            Some("A wrong PIN was entered recently; few attempts are left."),
        ),
        "confirm" => Stage::Confirm {
            certificate: CERTIFICATE.into(),
            digests: vec![DIGEST.into()],
            reply: mpsc::channel().0,
        },
        "choose" => Stage::Choose {
            subjects: vec![
                "ASHA RAO (Verasys Sub CA 2022), signing, valid until 12 March 2027".into(),
                "ASHA RAO (Verasys Sub CA 2022), encryption, valid until 12 March 2027".into(),
                "ASHA RAO (eMudhra Sub CA 2023), signing, valid until 2 June 2028".into(),
            ],
            reply: mpsc::channel().0,
        },
        "enrol" => Stage::Enrol {
            reply: mpsc::channel().0,
        },
        _ => Stage::Busy,
    };
    let kind = if matches!(view, "enrol" | "choose" | "pin-warning") {
        Kind::Enrol
    } else {
        Kind::Sign
    };
    windows.handle(
        Request::Job {
            job: job(kind),
            stage,
        },
        cx,
    );
    // Keeps the window's state for the app's lifetime.
    std::mem::forget(windows);
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AnyWindowHandle, AppContext, TestAppContext};
    use keyseal_core::origin::Origin;
    use keyseal_core::protocol::Kind;
    use keyseal_core::trust::TrustStore;

    use keyseal_core::doctor::{Report, Status};
    use keyseal_core::flow::Step;
    use keyseal_core::preferences::Preferences;

    use super::{INPUT_DELAY, Windows, key_bindings, open_settings, sample_report};
    use crate::{Brand, Job, Request, Stage, strings};

    const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn log(_: &str) {}

    fn probe() -> Result<Report, String> {
        Ok(sample_report(Status::Ready))
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keyseal-ui-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn setup(cx: &mut TestAppContext) -> Windows {
        cx.update(|cx| {
            gpui_kit::init(cx);
            cx.bind_keys(key_bindings());
        });
        Windows::new(log)
    }

    fn job() -> Job {
        Job {
            host: "dash.example.org".into(),
            insecure: false,
            brand: Some(Brand {
                name: "Example Trust".into(),
                icon: None,
                accent: Some(0x1f6feb),
                translucent: true,
            }),
            kind: Kind::Sign,
            claimed: true,
            title: "Lease agreement".into(),
            signer: "A. Signer".into(),
            documents: vec!["Lease agreement".into()],
        }
    }

    fn open_windows(cx: &mut TestAppContext) -> Vec<AnyWindowHandle> {
        cx.update(|cx| cx.windows())
    }

    /// Lets [`INPUT_DELAY`] pass, after which confirming buttons respond.
    fn pass_input_delay(cx: &mut TestAppContext) {
        cx.executor().advance_clock(INPUT_DELAY);
        cx.run_until_parked();
    }

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

    #[gpui_kit::test]
    fn trust_prompt_shows_the_host_and_answers(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Trust {
                    host: "localhost:3000".into(),
                    insecure: true,
                    reply,
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("host").label(), Some("localhost:3000"));
            assert!(window.try_find("insecure").is_some());
            // Enter mustn't trust; Escape cancels.
            window.press("enter", cx);
            window.press("escape", cx);
        })
        .unwrap();
        assert_eq!(answer.recv(), Ok(false));

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Trust {
                    host: "dash.example.org".into(),
                    insecure: false,
                    reply,
                },
                cx,
            )
        });
        let handle = *open_windows(cx).last().unwrap();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("insecure").is_none());
            // Keys typed for another window as this one opens can't trust.
            assert_eq!(window.find("trust").disabled(), Some(true));
            window.click("trust", cx);
        })
        .unwrap();
        assert_eq!(answer.try_recv(), Err(mpsc::TryRecvError::Empty));
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("trust", cx);
        })
        .unwrap();
        assert_eq!(answer.recv(), Ok(true));
    }

    #[gpui_kit::test]
    fn job_window_runs_every_stage(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Pin {
                        certificate: Some("CN=A. Signer".into()),
                        digests: Some(vec![DIGEST.into()]),
                        pin_pad: false,
                        warning: Some("One PIN attempt is left before the token locks."),
                        reply,
                    },
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("host").label(), Some("dash.example.org"));
            assert_eq!(
                window.find("title").label(),
                Some(format!("{}: Lease agreement", strings::TITLE).as_str())
            );
            assert_eq!(window.find("pin").focused(), Some(true));
            // The certificate and the digest wait behind the details button.
            assert!(window.try_find("certificate").is_none());
            assert!(window.try_find("digest").is_none());
            window.click("details", cx);
            window.render_frame(cx);
            assert_eq!(
                window.find("certificate").label(),
                Some(format!("{}: CN=A. Signer", strings::CERTIFICATE).as_str())
            );
            assert_eq!(
                window.find("digest").label(),
                Some(format!("{}: {DIGEST}", strings::DIGEST).as_str())
            );
            assert!(window.try_find("pin-warning").is_some());
            assert_eq!(window.find("submit").disabled(), Some(true));
            window.click("pin", cx);
            assert_eq!(window.find("pin").focused(), Some(true));
            window.input("1234", cx);
            // The field is masked, so it doesn't expose its value.
            assert_eq!(window.find("pin").value(), None);
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.recv().unwrap().unwrap().as_str(), "1234");

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Confirm {
                        certificate: "CN=A. Signer".into(),
                        digests: vec![DIGEST.into()],
                        reply,
                    },
                },
                cx,
            )
        });
        assert_eq!(open_windows(cx).len(), 1);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("pin").is_none());
            // Focus is back on the window after the PIN: Enter mustn't sign.
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.try_recv(), Err(mpsc::TryRecvError::Empty));
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| window.click("submit", cx))
            .unwrap();
        assert_eq!(answer.recv(), Ok(true));

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Choose {
                        subjects: vec!["CN=One".into(), "CN=Two".into()],
                        reply,
                    },
                },
                cx,
            )
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.try_recv(), Err(mpsc::TryRecvError::Empty));
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| window.click("submit", cx))
            .unwrap();
        assert_eq!(answer.recv(), Ok(Some(0)));

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Pin {
                        certificate: None,
                        digests: None,
                        pin_pad: false,
                        warning: None,
                        reply,
                    },
                },
                cx,
            )
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("digest").is_none());
            window.press("escape", cx);
        })
        .unwrap();
        assert_eq!(answer.recv(), Err(mpsc::RecvError));
    }

    /// On CNG the digest confirmation, or the enrol go-ahead, is the job's
    /// first window; Enter confirms neither.
    #[gpui_kit::test]
    fn enter_never_confirms_a_first_window(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Confirm {
                        certificate: "CN=A. Signer".into(),
                        digests: vec![DIGEST.into()],
                        reply,
                    },
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.try_recv(), Err(mpsc::TryRecvError::Empty));
        cx.update_window(handle, |_, window, cx| window.press("escape", cx))
            .unwrap();
        assert_eq!(answer.recv(), Err(mpsc::RecvError));

        // The next job.
        cx.update(|cx| windows.close_all(cx));
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Enrol { reply },
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("digest").is_none());
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.try_recv(), Err(mpsc::TryRecvError::Empty));
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| window.click("submit", cx))
            .unwrap();
        assert_eq!(answer.recv(), Ok(true));
    }

    /// A link during a job gets a window of its own; after the job every
    /// window closes and the next job opens a new job window.
    #[gpui_kit::test]
    fn a_second_job_starts_afresh(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let choose = |reply| Request::Job {
            job: job(),
            stage: Stage::Choose {
                subjects: vec!["CN=One".into()],
                reply,
            },
        };
        let (reply, _first) = mpsc::channel();
        cx.update(|cx| windows.handle(choose(reply), cx));
        cx.update(|cx| windows.busy(cx));
        assert_eq!(open_windows(cx).len(), 2);
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

    #[gpui_kit::test]
    fn error_window_replaces_the_job_window(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let (reply, _answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Choose {
                        subjects: vec!["CN=One".into(), "CN=Two".into()],
                        reply,
                    },
                },
                cx,
            )
        });
        let message = format!(
            "{} Install your token's driver.",
            keyseal_core::modules::NO_DRIVER
        );
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Message {
                    heading: strings::ERROR_HEADING,
                    message: message.clone(),
                    reply,
                },
                cx,
            )
        });
        let dir = temp_dir("message-settings");
        let settings_dir = dir.clone();
        cx.update(|cx| {
            cx.on_action(move |_: &crate::OpenSettings, cx| {
                open_settings(settings_dir.clone(), log, probe, cx)
            });
        });
        cx.run_until_parked();
        let open = open_windows(cx);
        assert_eq!(open.len(), 1);
        cx.update_window(open[0], |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("error").label(), Some(message.as_str()));
            assert!(window.try_find("doctor-hint").is_some());
            window.click("show-tokens", cx);
        })
        .unwrap();
        cx.run_until_parked();
        assert_eq!(open_windows(cx).len(), 2);
        cx.update_window(open[0], |_, window, cx| window.click("close", cx))
            .unwrap();
        assert_eq!(answer.recv(), Err(mpsc::RecvError));
        // The job ends; Settings, opened from the error, stays.
        cx.update(|cx| {
            windows.close_all(cx);
            assert!(super::settings_open(cx));
        });
        cx.run_until_parked();
        assert_eq!(open_windows(cx).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn settings_window_forgets_origins(cx: &mut TestAppContext) {
        setup(cx);
        let dir = temp_dir("settings");
        let store = TrustStore::new(&dir);
        let url = url::Url::parse("https://dash.example.org/").unwrap();
        store.trust(&Origin::of_url(&url, false).unwrap()).unwrap();

        let settings_dir = dir.clone();
        cx.update(|cx| open_settings(settings_dir.clone(), log, probe, cx));
        // A second request focuses the open window.
        cx.update(|cx| open_settings(settings_dir, log, probe, cx));
        assert_eq!(open_windows(cx).len(), 1);
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("version").label(),
                Some(format!("{}: {}", strings::VERSION, keyseal_core::VERSION).as_str())
            );
            window.click("forget https://dash.example.org", cx);
        })
        .unwrap();
        assert!(store.list().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn settings_window_shows_the_tokens_and_copies_the_report(cx: &mut TestAppContext) {
        setup(cx);
        let dir = temp_dir("tokens");
        cx.update(|cx| open_settings(dir.clone(), log, probe, cx));
        let handle = open_windows(cx)[0];
        // The probe runs off the main thread; the window shows it's looking.
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("tokens-status").label(),
                Some(strings::CHECKING_TOKENS)
            );
            assert_eq!(window.find("refresh").disabled(), Some(true));
            assert_eq!(window.find("copy-diagnostics").disabled(), Some(true));
        })
        .unwrap();
        cx.run_until_parked();
        let report = sample_report(Status::Ready);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("tokens-status").label(),
                Some(format!("{}: {}", strings::TOKEN_READY, strings::TOKEN_READY_NOTE).as_str())
            );
            assert_eq!(
                window.find("token HyperSecu HYP2003").label(),
                Some(
                    format!(
                        "HyperSecu HYP2003: {}, libcastle.dylib",
                        strings::DRIVER_USED
                    )
                    .as_str()
                )
            );
            // An installed driver that loaded shows; a missing one doesn't.
            assert!(
                window
                    .try_find("driver /usr/local/lib/libeTPkcs11.dylib [known drivers]")
                    .is_some()
            );
            assert!(
                window
                    .try_find("driver /usr/local/lib/libmtoken.dylib [known drivers]")
                    .is_none()
            );
            window.click("copy-diagnostics", cx);
        })
        .unwrap();
        let copied = cx.update(|cx| cx.read_from_clipboard().and_then(|item| item.text()));
        assert_eq!(copied, Some(report.text));
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("refresh", cx);
            window.render_frame(cx);
            assert_eq!(
                window.find("tokens-status").label(),
                Some(strings::CHECKING_TOKENS)
            );
        })
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[gpui_kit::test]
    fn the_job_window_opens_with_details_when_the_signer_asks(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let dir = temp_dir("details");
        cx.update(|cx| open_settings(dir.clone(), log, probe, cx));
        let settings = open_windows(cx)[0];
        cx.update_window(settings, |_, window, cx| {
            window.render_frame(cx);
            window.click("always-show-details", cx);
        })
        .unwrap();
        assert!(Preferences::load(&dir).always_show_details);

        let (reply, _answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Pin {
                        certificate: Some("CN=A. Signer".into()),
                        digests: Some(vec![DIGEST.into()]),
                        pin_pad: false,
                        warning: None,
                        reply,
                    },
                },
                cx,
            )
        });
        let handle = *open_windows(cx).last().unwrap();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("certificate").is_some());
            assert!(window.try_find("digest").is_some());
            // The toggle still hides them.
            window.click("details", cx);
            window.render_frame(cx);
            assert!(window.try_find("digest").is_none());
        })
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A batch's row says how many documents there are, and its titles are
    /// listed; the details add each document's digest beside its title, and
    /// Sign stays one action.
    /// With the most documents a job may carry, the list scrolls and the
    /// PIN field stays in view.
    #[gpui_kit::test]
    fn the_job_window_shows_a_batch(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let mut batch = job();
        batch.title = "Board pack".into();
        batch.documents = (1..=20)
            .map(|n| format!("Resolution {n} of the Board of Trustees, with its annexures"))
            .collect();
        batch.documents[1] = "Minutes".into();
        let digests: Vec<String> = (0..20).map(|n| format!("{n:02}{}", &DIGEST[2..])).collect();
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: batch.clone(),
                    stage: Stage::Pin {
                        certificate: Some("CN=A. Signer".into()),
                        digests: Some(digests.clone()),
                        pin_pad: false,
                        warning: None,
                        reply,
                    },
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("title").label(),
                Some("20 documents: Board pack")
            );
            // The titles show without the details; the digests don't.
            assert_eq!(window.find(("document", 1_usize)).label(), Some("Minutes"));
            assert!(window.try_find("certificate").is_none());
            window.click("details", cx);
            window.render_frame(cx);
            assert!(window.try_find("certificate").is_some());
            // One digest per document, beside its title, not on its own.
            assert!(window.try_find("digest").is_none());
            for (index, title) in batch.documents.iter().enumerate() {
                let expected = format!("{title}: {}", digests[index]);
                assert_eq!(
                    window.find(("document", index)).label(),
                    Some(expected.as_str())
                );
            }
            window.click("pin", cx);
            window.input("1234", cx);
            window.click("submit", cx);
        })
        .unwrap();
        assert_eq!(answer.recv().unwrap().unwrap().as_str(), "1234");

        // The login-first PIN prompt lists the titles before any digest.
        let (reply, _answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: batch.clone(),
                    stage: Stage::Pin {
                        certificate: None,
                        digests: None,
                        pin_pad: false,
                        warning: None,
                        reply,
                    },
                },
                cx,
            )
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find(("document", 1_usize)).label(), Some("Minutes"));
            assert!(window.try_find("certificate").is_none());
        })
        .unwrap();
    }
    /// The job window opens at the first step with the host only, then
    /// shows the claimed job and its steps, and its prompts, in one window.
    #[gpui_kit::test]
    fn the_job_window_shows_progress_from_the_start(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let unclaimed = Job {
            brand: None,
            claimed: false,
            title: String::new(),
            signer: String::new(),
            documents: Vec::new(),
            ..job()
        };
        let progress = |job, step| Request::Job {
            job,
            stage: Stage::Progress(step),
        };
        cx.update(|cx| windows.handle(progress(unclaimed, Step::Connecting), cx));
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("host").label(), Some("dash.example.org"));
            assert!(window.try_find("title").is_none());
            assert!(window.try_find("signer").is_none());
            assert_eq!(
                window.find("progress").label(),
                Some("Connecting to dash.example.org...")
            );
            assert_ne!(window.find("cancel").disabled(), Some(true));
            assert_eq!(window.find("submit").disabled(), Some(true));
        })
        .unwrap();

        cx.update(|cx| windows.handle(progress(job(), Step::CheckingCertificate), cx));
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(
                window.find("title").label(),
                Some(format!("{}: Lease agreement", strings::TITLE).as_str())
            );
            assert_eq!(
                window.find("progress").label(),
                Some("Checking your certificate with dash.example.org...")
            );
        })
        .unwrap();

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Pin {
                        certificate: Some("CN=A. Signer".into()),
                        digests: Some(vec![DIGEST.into()]),
                        pin_pad: false,
                        warning: None,
                        reply,
                    },
                },
                cx,
            )
        });
        assert_eq!(open_windows(cx), [handle]);
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("progress").is_none());
            window.input("1234", cx);
            window.click("submit", cx);
            window.render_frame(cx);
            // Answered: working until the next step.
            assert_eq!(window.find("progress").label(), Some(strings::WORKING));
            assert_ne!(window.find("cancel").disabled(), Some(true));
        })
        .unwrap();
        assert_eq!(answer.recv().unwrap().unwrap().as_str(), "1234");
    }

    /// Cancel closes the job window at once, during a step or at a prompt,
    /// and no window opens for the rest of the job.
    #[gpui_kit::test]
    fn cancelling_closes_the_job_window(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let pin = |reply| Request::Job {
            job: job(),
            stage: Stage::Pin {
                certificate: None,
                digests: None,
                pin_pad: false,
                warning: None,
                reply,
            },
        };

        let cancelled = windows.job_closed();
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Progress(Step::OpeningToken),
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("cancel", cx);
        })
        .unwrap();
        cx.run_until_parked();
        assert!(open_windows(cx).is_empty());
        assert!(cancelled.load(std::sync::atomic::Ordering::Relaxed));
        // The flow's next prompt answers Cancel without a window.
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| windows.handle(pin(reply), cx));
        assert_eq!(answer.recv(), Err(mpsc::RecvError));
        assert!(open_windows(cx).is_empty());

        // At a prompt, once the job is over and the next one starts.
        cx.update(|cx| windows.close_all(cx));
        let cancelled = windows.job_closed();
        assert!(!cancelled.load(std::sync::atomic::Ordering::Relaxed));
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| windows.handle(pin(reply), cx));
        let handle = open_windows(cx)[0];
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.press("escape", cx);
        })
        .unwrap();
        assert_eq!(answer.recv(), Err(mpsc::RecvError));
        cx.run_until_parked();
        assert!(open_windows(cx).is_empty());
        assert!(cancelled.load(std::sync::atomic::Ordering::Relaxed));
    }
}

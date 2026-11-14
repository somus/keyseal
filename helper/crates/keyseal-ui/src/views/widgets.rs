//! The pieces the windows share: the frame, icons, groups and rows, the
//! button bar, and the delay before a confirming button responds.

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use gpui_kit::component::button::Button;
use gpui_kit::component::scroll::ScrollbarHandle;
use gpui_kit::component::spinner::Spinner;
use gpui_kit::component::{ActiveTheme, Icon, Sizable, h_flex, v_flex};
use gpui_kit::{
    AnyElement, App, Bounds, Context, Div, FocusHandle, Hsla, InteractiveElement, IntoElement,
    ParentElement, Pixels, Point, RenderImage, Role, ScrollHandle, SharedString, Size,
    StatefulInteractiveElement, Styled, Subscription, Task, TestSupportExt, Window, div, img,
    prelude::FluentBuilder, px, rems,
};

use crate::{native, strings};

pub(super) fn window_frame(
    focus: &FocusHandle,
    context: &'static str,
    window: &mut Window,
    cx: &App,
) -> Div {
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
pub(super) fn icon(name: &'static str) -> Icon {
    let svg: &[u8] = match name {
        "shield-question-mark" => include_bytes!("../../icons/shield-question-mark.svg"),
        "shield-alert" => include_bytes!("../../icons/shield-alert.svg"),
        "signature" => include_bytes!("../../icons/signature.svg"),
        "id-card" => include_bytes!("../../icons/id-card.svg"),
        "file-text" => include_bytes!("../../icons/file-text.svg"),
        "user-round" => include_bytes!("../../icons/user-round.svg"),
        "badge-check" => include_bytes!("../../icons/badge-check.svg"),
        "fingerprint-pattern" => include_bytes!("../../icons/fingerprint-pattern.svg"),
        "chevron-down" => include_bytes!("../../icons/chevron-down.svg"),
        "chevron-right" => include_bytes!("../../icons/chevron-right.svg"),
        "triangle-alert" => include_bytes!("../../icons/triangle-alert.svg"),
        "usb" => include_bytes!("../../icons/usb.svg"),
        "lock-keyhole" => include_bytes!("../../icons/lock-keyhole.svg"),
        "circle-alert" => include_bytes!("../../icons/circle-alert.svg"),
        "hourglass" => include_bytes!("../../icons/hourglass.svg"),
        "info" => include_bytes!("../../icons/info.svg"),
        "globe" => include_bytes!("../../icons/globe.svg"),
        "globe-lock" => include_bytes!("../../icons/globe-lock.svg"),
        "trash" => include_bytes!("../../icons/trash.svg"),
        "folder" => include_bytes!("../../icons/folder.svg"),
        "layers" => include_bytes!("../../icons/layers.svg"),
        "eye" => include_bytes!("../../icons/eye.svg"),
        "circle-check" => include_bytes!("../../icons/circle-check.svg"),
        "package" => include_bytes!("../../icons/package.svg"),
        "refresh-cw" => include_bytes!("../../icons/refresh-cw.svg"),
        "copy" => include_bytes!("../../icons/copy.svg"),
        // KeySeal's own mark, from brand/keyseal-mark.svg.
        "keyseal" => include_bytes!("../../icons/keyseal.svg"),
        _ => unreachable!("icon {name} isn't bundled"),
    };
    Icon::default().data(svg)
}

/// A tinted square holding an icon, the way the platforms mark what a
/// dialog is about.
pub(super) fn icon_tile(name: &'static str, tint: Hsla, cx: &App) -> impl IntoElement {
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
pub(super) fn logo_tile(logo: Arc<RenderImage>, badge: &'static str, cx: &App) -> impl IntoElement {
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
pub(super) fn banner(
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
        // min_w_0 lets the text wrap instead of widening the strip.
        .child(div().flex_1().min_w_0().child(text))
        .test_support()
}

pub(super) fn insecure_banner(cx: &App) -> impl IntoElement {
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
pub(super) fn group(rows: impl IntoIterator<Item = AnyElement>, cx: &App) -> Div {
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
pub(super) fn field(
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

pub(super) fn note(text: &'static str, cx: &App) -> impl IntoElement {
    div()
        .text_sm()
        .text_color(cx.theme().muted_foreground)
        .child(text)
}

/// The window's buttons, laid out as the platform lays out a dialog's:
/// `primary` last on the trailing edge on macOS, first on a band of its
/// own on Windows, last across the full width with libadwaita.
pub(super) fn button_bar(cancel: Option<Button>, primary: Button, cx: &App) -> Div {
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
pub(super) fn secondary(button: Button, cx: &App) -> Button {
    let palette = native::palette(cx);
    button
        .bg(native::color(palette.control))
        .border_color(native::color(palette.control_border))
}

/// An alert: an icon over its heading and text, centred where the
/// platform centres them.
pub(super) fn alert(
    tile: impl IntoElement,
    heading: impl IntoElement,
    body: impl IntoElement,
) -> Div {
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
pub(super) fn site_heading(host: SharedString, ask: &'static str, cx: &App) -> impl IntoElement {
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
pub(super) fn progress_line(text: SharedString, cx: &App) -> impl IntoElement {
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
pub(super) const INPUT_DELAY: Duration = Duration::from_millis(700);

/// Whether [`INPUT_DELAY`] has passed since the window last showed or came
/// forward.
pub(super) struct InputDelay {
    pub(super) ready: bool,
    _timer: Task<()>,
    _activation: Subscription,
}

impl InputDelay {
    /// Starts the delay now and again whenever the window becomes active.
    /// `field` is where the view keeps it.
    pub(super) fn new<T: 'static>(
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

    pub(super) fn restart<T: 'static>(
        &mut self,
        field: fn(&mut T) -> &mut InputDelay,
        cx: &mut Context<T>,
    ) {
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

/// The scroll handle of an area that shows a scrollbar while it holds more
/// than fits. An area whose content fits can still come out a pixel short of
/// it once the layout is rounded to whole pixels; that is no reason for a
/// scrollbar.
#[derive(Clone, Default)]
pub(super) struct ScrollArea(ScrollHandle);

impl Deref for ScrollArea {
    type Target = ScrollHandle;

    fn deref(&self) -> &ScrollHandle {
        &self.0
    }
}

impl ScrollbarHandle for ScrollArea {
    fn viewport_bounds(&self) -> Bounds<Pixels> {
        self.0.bounds()
    }

    fn offset(&self) -> Point<Pixels> {
        self.0.offset()
    }

    fn set_offset(&self, offset: Point<Pixels>) {
        self.0.set_offset(offset);
    }

    fn content_size(&self) -> Size<Pixels> {
        let mut size = self.0.bounds().size;
        if self.0.max_offset().y > px(2.) {
            size.height += self.0.max_offset().y;
        }
        size
    }
}

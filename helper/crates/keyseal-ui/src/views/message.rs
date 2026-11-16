//! The message window: the flow's error or a notice.

use std::sync::mpsc;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::{ActiveTheme, v_flex};
use gpui_kit::{
    App, Context, FocusHandle, Hsla, InteractiveElement, IntoElement, ParentElement, Render, Role,
    SharedString, StatefulInteractiveElement, Styled, TestSupportExt, Window, div,
    prelude::FluentBuilder,
};
use keyseal_core::modules;

use super::widgets::{ScrollArea, alert, button_bar, icon_tile, scrolling, window_frame};
use super::{CONTEXT, Cancel, Submit};
use crate::{native, strings};

/// What a message is, which gives its heading and its icon.
#[derive(Clone, Copy)]
pub(crate) enum MessageKind {
    /// The flow failed.
    Error,
    /// The flow has something to say.
    Info,
    /// A link arrived while a job runs.
    Busy,
}

impl MessageKind {
    fn heading(self) -> &'static str {
        match self {
            Self::Error => strings::ERROR_HEADING,
            Self::Info => strings::INFO_HEADING,
            Self::Busy => strings::BUSY_HEADING,
        }
    }

    /// The icon in the header tile, and its tint.
    fn icon(self, cx: &App) -> (&'static str, Hsla) {
        match self {
            Self::Error => ("circle-alert", cx.theme().danger),
            Self::Info => ("info", cx.theme().primary),
            Self::Busy => ("hourglass", cx.theme().primary),
        }
    }
}

/// The flow's error or a notice, kept open until the user closes it.
pub(super) struct MessageWindow {
    kind: MessageKind,
    message: SharedString,
    no_driver: bool,
    pub(super) reply: Option<mpsc::Sender<()>>,
    focus: FocusHandle,
    /// Shows a scrollbar while the message is longer than the window.
    scroll: ScrollArea,
}

impl MessageWindow {
    pub(super) fn new(
        kind: MessageKind,
        message: String,
        reply: Option<mpsc::Sender<()>>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let focus = cx.focus_handle();
        window.focus(&focus, cx);
        Self {
            kind,
            no_driver: message.starts_with(modules::NO_DRIVER),
            message: message.into(),
            reply,
            focus,
            scroll: ScrollArea::default(),
        }
    }

    fn close(&mut self, window: &mut Window) {
        self.reply.take();
        window.remove_window();
    }
}

impl Render for MessageWindow {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (tile, tint) = self.kind.icon(cx);
        window_frame(&self.focus, CONTEXT, window, cx)
            .on_action(cx.listener(|this, _: &Submit, window, _| this.close(window)))
            .on_action(cx.listener(|this, _: &Cancel, window, _| this.close(window)))
            .child(
                scrolling(
                    v_flex()
                        .id("error")
                        .role(Role::Alert)
                        .aria_label(self.message.clone())
                        .flex_1()
                        .overflow_y_scroll()
                        .track_scroll(&self.scroll)
                        .px_6()
                        .pt_5()
                        .pb_2()
                        .child(alert(
                            icon_tile(tile, tint, cx),
                            div()
                                .text_lg()
                                .font_weight(native::look().heading_weight)
                                .child(self.kind.heading()),
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
                    &self.scroll,
                )
                .flex_1(),
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AppContext, TestAppContext, VisualTestContext};

    use crate::views::testing::{certificate, job, open_windows, probe, setup, temp_dir};

    use super::MessageKind;
    use crate::bridge::{Request, Stage};
    use crate::views::open_settings;

    /// The scrollbar covers the message and not the buttons below it, so it
    /// is measured against the message alone.
    #[gpui_kit::test]
    fn the_scrollbar_covers_the_message_only(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        cx.update(|cx| {
            windows.handle(
                Request::Message {
                    kind: MessageKind::Error,
                    message: "The token was removed.".into(),
                    reply: mpsc::channel().0,
                },
                cx,
            )
        });
        let handle = open_windows(cx)[0];
        let message = cx
            .update_window(handle, |_, window, cx| {
                window.render_frame(cx);
                window.find("error").bounds()
            })
            .unwrap();
        let scrollbar =
            VisualTestContext::from_window(handle, cx).debug_bounds("scrollbar-overlay");
        assert_eq!(scrollbar, Some(message));
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
                        certificates: vec![certificate("One"), certificate("Two")],
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
                    kind: MessageKind::Error,
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
                open_settings(settings_dir.clone(), probe, cx)
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
            assert!(super::super::settings_open(cx));
        });
        cx.run_until_parked();
        assert_eq!(open_windows(cx).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a message that no driver reached a token offers the tokens in
    /// Settings, with the hint beside it.
    #[gpui_kit::test]
    fn a_no_driver_message_offers_the_tokens(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        for (message, no_driver) in [
            (
                format!(
                    "{} Install your token's driver.",
                    keyseal_core::modules::NO_DRIVER
                ),
                true,
            ),
            ("The token was removed.".to_owned(), false),
        ] {
            cx.update(|cx| {
                windows.handle(
                    Request::Message {
                        kind: MessageKind::Error,
                        message,
                        reply: mpsc::channel().0,
                    },
                    cx,
                )
            });
            let handle = *open_windows(cx).last().unwrap();
            cx.update_window(handle, |_, window, cx| {
                window.render_frame(cx);
                assert_eq!(window.try_find("show-tokens").is_some(), no_driver);
                assert_eq!(window.try_find("doctor-hint").is_some(), no_driver);
            })
            .unwrap();
            cx.update(|cx| windows.close_all(cx));
            cx.run_until_parked();
        }
    }
}

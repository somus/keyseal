//! The message window: the flow's error or a notice.

use std::sync::mpsc;

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{ActiveTheme, v_flex};
use gpui_kit::{
    Context, FocusHandle, InteractiveElement, IntoElement, ParentElement, Render, Role,
    ScrollHandle, SharedString, StatefulInteractiveElement, Styled, TestSupportExt, Window, div,
    prelude::FluentBuilder,
};
use keyseal_core::modules;

use super::widgets::{alert, button_bar, icon_tile, window_frame};
use super::{CONTEXT, Cancel, Submit};
use crate::{native, strings};

/// The flow's error or a notice, kept open until the user closes it.
pub(super) struct MessageWindow {
    heading: &'static str,
    message: SharedString,
    no_driver: bool,
    pub(super) reply: Option<mpsc::Sender<()>>,
    focus: FocusHandle,
    /// Shows a scrollbar while the message is longer than the window.
    scroll: ScrollHandle,
}

impl MessageWindow {
    pub(super) fn new(
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
            scroll: ScrollHandle::new(),
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
                    .track_scroll(&self.scroll)
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
            // Drawn here rather than in the padded message, where it would
            // count toward the message's height and make it scroll by its
            // padding.
            .vertical_scrollbar(&self.scroll)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AppContext, TestAppContext};

    use crate::views::testing::{certificate, job, log, open_windows, probe, setup, temp_dir};

    use crate::views::open_settings;
    use crate::{Request, Stage, strings};

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
            assert!(super::super::settings_open(cx));
        });
        cx.run_until_parked();
        assert_eq!(open_windows(cx).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

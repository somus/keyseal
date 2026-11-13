//! The first-contact trust prompt.

use std::sync::mpsc;

use gpui_kit::component::button::Button;
use gpui_kit::component::{ActiveTheme, Disableable, v_flex};
use gpui_kit::{
    Context, FocusHandle, InteractiveElement, IntoElement, ParentElement, Render, SharedString,
    Styled, Window, div, prelude::FluentBuilder,
};

use super::widgets::{
    InputDelay, alert, button_bar, icon_tile, insecure_banner, secondary, site_heading,
    window_frame,
};
use super::{Cancel, TRUST_CONTEXT};
use crate::strings;

/// The trust prompt's height: taller with the insecure banner, so its
/// buttons stay inside the window.
pub(super) fn trust_height(insecure: bool) -> f32 {
    if insecure { 312. } else { 260. }
}

/// The first-contact prompt (section 5): the host only, never branding.
pub(super) struct TrustWindow {
    host: SharedString,
    insecure: bool,
    pub(super) reply: Option<mpsc::Sender<bool>>,
    focus: FocusHandle,
    delay: InputDelay,
}

impl TrustWindow {
    pub(super) fn new(
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AppContext, TestAppContext};

    use crate::views::testing::{open_windows, pass_input_delay, setup};

    use crate::Request;

    #[gpui_kit::test]
    fn trust_prompt_buttons_fit_the_window(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        for insecure in [false, true] {
            cx.update(|cx| {
                windows.handle(
                    Request::Trust {
                        host: "localhost:3000".into(),
                        insecure,
                        reply: mpsc::channel().0,
                    },
                    cx,
                )
            });
            let handle = *open_windows(cx).last().unwrap();
            cx.update_window(handle, |_, window, cx| {
                window.render_frame(cx);
                let height = window.viewport_size().height;
                for button in ["cancel", "trust"] {
                    let bottom = window.find(button).bounds().bottom();
                    assert!(
                        bottom <= height,
                        "{button} ends at {bottom:?}, below the window's {height:?} (insecure: {insecure})"
                    );
                }
            })
            .unwrap();
        }
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
}

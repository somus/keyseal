//! The job window.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gpui_kit::component::button::{Button, ButtonVariants};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::radio::Radio;
use gpui_kit::component::{ActiveTheme, Disableable, Sizable, StyledExt, h_flex, v_flex};
use gpui_kit::{
    AnyElement, App, AppContext, Context, Div, Entity, FocusHandle, Focusable, Global, Hsla, Image,
    ImageFormat, InteractiveElement, IntoElement, ParentElement, Render, RenderImage, Role,
    SharedString, StatefulInteractiveElement, Styled, Subscription, TestSupportExt, Window, div,
    prelude::FluentBuilder, px, rgb, size,
};
use keyseal_core::flow::Step;
use keyseal_core::protocol::Kind;
use zeroize::Zeroizing;

use super::widgets::{
    InputDelay, banner, button_bar, field, group, icon, icon_tile, insecure_banner, logo_tile,
    note, progress_line, site_heading, window_frame,
};
use super::{CONTEXT, Cancel, Submit};
use crate::{Job, Stage, group_digest, native, strings};

/// The signer's choice to open the job window with the certificate and the
/// digest shown.
struct AlwaysShowDetails(bool);

impl Global for AlwaysShowDetails {}

pub(crate) fn set_always_show_details(on: bool, cx: &mut App) {
    cx.set_global(AlwaysShowDetails(on));
}

/// The job window's size: taller for a batch, so its list of documents
/// shows a few.
pub(super) fn job_size(job: &Job) -> (f32, f32) {
    (520., if job.is_batch() { 640. } else { 560. })
}

pub(super) fn job_title(job: &Job) -> &'static str {
    match job.kind {
        Kind::Sign if job.is_batch() => strings::SIGN_BATCH_WINDOW_TITLE,
        Kind::Sign => strings::SIGN_WINDOW_TITLE,
        Kind::Enrol => strings::ENROL_WINDOW_TITLE,
    }
}

/// Under the PIN field when the token refused the PIN entered last.
fn wrong_pin_line(cx: &App) -> impl IntoElement {
    div()
        .id("pin-wrong")
        .role(Role::Alert)
        .aria_label(strings::PIN_WRONG)
        .text_sm()
        .text_color(cx.theme().danger)
        .child(strings::PIN_WRONG)
        .test_support()
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

/// The window for the rest of the job, one [`Stage`] at a time.
pub(super) struct JobWindow {
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
    pub(super) fn new(
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

    pub(super) fn show(
        &mut self,
        job: Job,
        stage: Stage,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
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

    /// What the submit button does, under the same conditions as the
    /// button: Enter waits for [`INPUT_DELAY`] too.
    fn submit(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.pin_missing(cx) || !self.delay.ready {
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
    pub(super) fn cancelled(&mut self) {
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
            Step::Signing if self.job.kind == Kind::Enrol => strings::STEP_PROVING,
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
                wrong_pin,
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
                        // A key that needs the PIN for each signature has the
                        // pad ask once per document, which the helper can't
                        // tell before login.
                        let text = match self.job.kind {
                            Kind::Sign if self.job.is_batch() => strings::PIN_PAD_BATCH,
                            _ => strings::PIN_PAD,
                        };
                        this.child(
                            h_flex()
                                .id("pin-pad")
                                .role(Role::Note)
                                .aria_label(text)
                                .gap_2()
                                .child(icon("usb").size_4().text_color(cx.theme().muted_foreground))
                                .child(note(text, cx))
                                .test_support(),
                        )
                        .when(*wrong_pin, |this| this.child(wrong_pin_line(cx)))
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
                                )
                                .when(*wrong_pin, |this| this.child(wrong_pin_line(cx))),
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
            Stage::Choose { subjects, .. } => body
                .child(
                    div()
                        .id("choose")
                        .role(Role::Note)
                        .aria_label(strings::CHOOSE_NOTE)
                        .child(note(strings::CHOOSE_NOTE, cx))
                        .test_support(),
                )
                .child(group(
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
                )),
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
                                    // Gives a batch's list the height left above
                                    // what is pinned. Above a list of certificates
                                    // it keeps its height and the job scrolls.
                                    .map(|this| {
                                        if pinned {
                                            this.min_h(px(0.))
                                        } else {
                                            this.flex_shrink_0()
                                        }
                                    })
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{AppContext, TestAppContext};

    use keyseal_core::flow::Step;
    use keyseal_core::preferences::Preferences;

    use crate::views::testing::{
        DIGEST, job, log, open_windows, pass_input_delay, probe, setup, temp_dir,
    };

    use crate::views::open_settings;
    use crate::{Job, Request, Stage, strings};

    /// More certificates than the window holds scroll with the job instead of
    /// squeezing the rows above them.
    #[gpui_kit::test]
    fn a_long_list_of_certificates_stays_below_the_job(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        cx.update(|cx| {
            windows.handle(
                Request::Job {
                    job: job(),
                    stage: Stage::Choose {
                        subjects: (1..=12).map(|n| format!("CN=Signer {n}")).collect(),
                        reply: mpsc::channel().0,
                    },
                },
                cx,
            )
        });
        let handle = *open_windows(cx).last().unwrap();
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            let job = window.find("signer").bounds().bottom();
            let note = window.find("choose").bounds().top();
            assert!(
                note >= job,
                "the note starts at {note:?}, above the job's {job:?}"
            );
        })
        .unwrap();
    }

    /// On a PIN pad, a batch says the pad may ask once per document.
    #[gpui_kit::test]
    fn the_pin_pad_note_names_a_batch(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let mut batch = job();
        batch.documents.push("Annexure".into());
        for (job, text) in [(job(), strings::PIN_PAD), (batch, strings::PIN_PAD_BATCH)] {
            let digests = job.documents.iter().map(|_| DIGEST.into()).collect();
            cx.update(|cx| {
                windows.handle(
                    Request::Job {
                        job,
                        stage: Stage::Pin {
                            certificate: Some("CN=A. Signer".into()),
                            digests: Some(digests),
                            pin_pad: true,
                            warning: None,
                            wrong_pin: false,
                            reply: mpsc::channel().0,
                        },
                    },
                    cx,
                )
            });
            let handle = *open_windows(cx).last().unwrap();
            cx.update_window(handle, |_, window, cx| {
                window.render_frame(cx);
                assert_eq!(window.find("pin-pad").label(), Some(text));
            })
            .unwrap();
            cx.update(|cx| windows.close_all(cx));
        }
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
                        wrong_pin: false,
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
            // Enter waits for the delay, as the button does.
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.try_recv(), Err(mpsc::TryRecvError::Empty));
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| window.press("enter", cx))
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
                        wrong_pin: false,
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

    /// After a wrong PIN the same window asks again: the field is empty and
    /// focused, the message sits by it, and the token's warning shows.
    #[gpui_kit::test]
    fn a_wrong_pin_is_asked_for_again_in_the_same_window(cx: &mut TestAppContext) {
        let mut windows = setup(cx);
        let pin = |wrong_pin, warning, reply| Request::Job {
            job: job(),
            stage: Stage::Pin {
                certificate: Some("CN=A. Signer".into()),
                digests: Some(vec![DIGEST.into()]),
                pin_pad: false,
                warning,
                wrong_pin,
                reply,
            },
        };
        let (reply, answer) = mpsc::channel();
        cx.update(|cx| windows.handle(pin(false, None, reply), cx));
        let handle = open_windows(cx)[0];
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert!(window.try_find("pin-wrong").is_none());
            window.input("0000", cx);
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.recv().unwrap().unwrap().as_str(), "0000");

        let (reply, answer) = mpsc::channel();
        cx.update(|cx| windows.handle(pin(true, Some(strings::PIN_FINAL_TRY), reply), cx));
        assert_eq!(open_windows(cx), [handle]);
        pass_input_delay(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            assert_eq!(window.find("pin-wrong").label(), Some(strings::PIN_WRONG));
            assert_eq!(
                window.find("pin-warning").label(),
                Some(strings::PIN_FINAL_TRY)
            );
            assert_eq!(window.find("pin").focused(), Some(true));
            // The field was cleared, so there is nothing to submit yet.
            assert_eq!(window.find("submit").disabled(), Some(true));
            window.input("1234", cx);
            window.render_frame(cx);
            assert_ne!(window.find("submit").disabled(), Some(true));
            window.press("enter", cx);
        })
        .unwrap();
        assert_eq!(answer.recv().unwrap().unwrap().as_str(), "1234");
    }

    /// From the certificate store the digest confirmation, or the enrol
    /// go-ahead, is the job's first window; Enter confirms neither.
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
                        wrong_pin: false,
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
                        wrong_pin: false,
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
                        wrong_pin: false,
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
                        wrong_pin: false,
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
                wrong_pin: false,
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

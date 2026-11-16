//! The bridge from the flow to the windows: [`WindowUi`] is the flow's
//! [`Ui`] on the job's thread, whose prompts send a [`Request`] to the main
//! thread and block until the user answers, and whose progress only sends
//! one. A window closed without an answer counts as Cancel.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};

use futures::channel::mpsc::UnboundedSender;
use keyseal_core::certificate::CertificateSummary;
use keyseal_core::flow::{DigestConfirm, JobView, PinPrompt, Progress, Step, Ui};
use keyseal_core::origin::Origin;
use keyseal_core::protocol::Kind;
use keyseal_core::token::{PinWarning, TokenSummary};
use zeroize::Zeroizing;

use crate::views::MessageKind;
use crate::{Event, strings};

/// What the windows show about a job, copied off the flow's borrowed view.
#[derive(Clone)]
pub(crate) struct Job {
    pub(crate) host: String,
    pub(crate) insecure: bool,
    pub(crate) brand: Option<Brand>,
    pub(crate) kind: Kind,
    /// The job is claimed: the title, signer and documents are its own.
    /// Before the claim they're empty and the window shows the host only.
    pub(crate) claimed: bool,
    pub(crate) title: String,
    pub(crate) signer: String,
    /// A sign job's document titles, in order; empty for enrol.
    pub(crate) documents: Vec<String>,
}

#[derive(Clone)]
pub(crate) struct Brand {
    pub(crate) name: String,
    pub(crate) icon: Option<Vec<u8>>,
    /// `0xrrggbb`.
    pub(crate) accent: Option<u32>,
    /// The manifest's `translucent`: false asks for opaque windows.
    pub(crate) translucent: bool,
}

impl Job {
    fn of(view: &JobView) -> Self {
        Self {
            host: view.origin.host_and_port(),
            insecure: view.origin.insecure,
            brand: view.branding.map(|branding| Brand {
                name: branding.manifest.name.clone(),
                icon: branding.icon.clone(),
                accent: branding.manifest.accent(),
                translucent: branding.manifest.translucent != Some(false),
            }),
            kind: view.kind,
            claimed: true,
            title: view.title.to_owned(),
            signer: view.signer.to_owned(),
            documents: view
                .documents
                .iter()
                .map(|document| document.title.clone())
                .collect(),
        }
    }

    /// The job a link asks for, before it's claimed: never branding, which
    /// comes with the claimed job.
    fn unclaimed(origin: &Origin, kind: Kind) -> Self {
        Self {
            host: origin.host_and_port(),
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
    pub(crate) fn is_batch(&self) -> bool {
        self.documents.len() > 1
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "requests travel boxed in Event::Ui"
)]
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
        kind: MessageKind,
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
        /// The chosen token's label, when several were plugged in.
        token: Option<String>,
        certificate: Option<String>,
        /// One per document, in order.
        digests: Option<Vec<String>>,
        pin_pad: bool,
        warning: Option<&'static str>,
        /// The PIN entered last was wrong.
        wrong_pin: bool,
        reply: mpsc::Sender<Option<Zeroizing<String>>>,
    },
    Confirm {
        certificate: String,
        /// One per document, in order.
        digests: Vec<String>,
        reply: mpsc::Sender<bool>,
    },
    Choose {
        certificates: Vec<CertificateSummary>,
        reply: mpsc::Sender<Option<usize>>,
    },
    ChooseToken {
        tokens: Vec<TokenSummary>,
        reply: mpsc::Sender<Option<usize>>,
    },
    /// Enrol through the system's certificate store: the job before the
    /// store is read.
    Enrol { reply: mpsc::Sender<bool> },
    /// Answered; the flow is working until its next step or prompt.
    Busy,
    /// The flow is at this step.
    Progress(Step),
}

/// The flow's [`Ui`] on the job's thread. It records each step in
/// `keyseal.log`, never the link or the PIN.
pub(crate) struct WindowUi {
    pub(crate) events: UnboundedSender<Event>,
    /// The signer cancelled the job or closed its window.
    pub(crate) cancelled: Arc<AtomicBool>,
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
        crate::log("Waiting for the signer.");
        self.ask(request)
    }
}

impl Ui for WindowUi {
    fn confirm_origin(&mut self, origin: &Origin) -> bool {
        self.ask_signer(|reply| Request::Trust {
            host: origin.host_and_port(),
            insecure: origin.insecure,
            reply,
        })
        .unwrap_or(false)
    }

    fn choose_certificate(
        &mut self,
        job: &JobView,
        certificates: &[CertificateSummary],
    ) -> Option<usize> {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(job),
            stage: Stage::Choose {
                certificates: certificates.to_vec(),
                reply,
            },
        })
        .flatten()
    }

    fn choose_token(&mut self, job: &JobView, tokens: &[TokenSummary]) -> Option<usize> {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(job),
            stage: Stage::ChooseToken {
                tokens: tokens.to_vec(),
                reply,
            },
        })
        .flatten()
    }

    fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>> {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(prompt.job),
            stage: Stage::Pin {
                token: prompt.token.clone(),
                certificate: prompt.certificate.clone(),
                digests: prompt.digests.clone(),
                pin_pad: prompt.pin_pad,
                // The flow fails a locked PIN instead of asking for it.
                warning: match prompt.pin_warning {
                    Some(PinWarning::FinalTry) => Some(strings::PIN_FINAL_TRY),
                    Some(PinWarning::CountLow) => Some(strings::PIN_COUNT_LOW),
                    Some(PinWarning::Locked) | None => None,
                },
                wrong_pin: prompt.wrong_pin,
                reply,
            },
        })
        .flatten()
    }

    fn confirm_digest(&mut self, confirm: &DigestConfirm) -> bool {
        self.ask_signer(|reply| Request::Job {
            job: Job::of(confirm.job),
            stage: Stage::Confirm {
                certificate: confirm.certificate.clone(),
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
            kind: MessageKind::Error,
            message: message.to_owned(),
            reply,
        });
    }

    fn show_info(&mut self, message: &str) {
        self.ask(|reply| Request::Message {
            kind: MessageKind::Info,
            message: message.to_owned(),
            reply,
        });
    }

    fn progress(&mut self, progress: Progress) -> bool {
        if self.cancelled.load(Ordering::Relaxed) {
            return false;
        }
        // Each step's time also ends the one before.
        crate::log(match progress.step {
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

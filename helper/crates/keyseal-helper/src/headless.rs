//! The headless prompter for `KEYSEAL_HEADLESS=1`: answers the flow from
//! the environment and prints what a window would show.

use keyseal_core::certificate::CertificateSummary;
use keyseal_core::flow::{DigestConfirm, JobView, PinPrompt, Ui};
use keyseal_core::origin::Origin;
use keyseal_core::protocol::Kind;
use keyseal_core::token::TokenSummary;
use zeroize::Zeroizing;

/// Answers the flow from the environment and prints what a window would show.
pub(crate) struct Headless {
    pub(crate) trust_origin: Option<String>,
    /// `KEYSEAL_PIN`, zeroised when used or dropped.
    pub(crate) pin: Option<Zeroizing<String>>,
}

fn describe(job: &JobView) {
    if job.origin.insecure {
        eprintln!("INSECURE DEVELOPMENT ORIGIN: plain HTTP, never trusted permanently.");
    }
    eprintln!("Origin: {}", job.origin);
    if let Some(branding) = job.branding {
        eprintln!("Integrator: {}", branding.manifest.name);
    }
    eprintln!("Title: {}", job.title);
    eprintln!("Signer: {}", job.signer);
    if job.documents.len() > 1 {
        eprintln!("Documents: {}", job.documents.len());
        for (index, document) in job.documents.iter().enumerate() {
            eprintln!("  {}. {}", index + 1, document.title);
        }
    }
}

/// Each document's digest, beside its title when the job has several.
fn describe_digests(job: &JobView, digests: &[String]) {
    match (job.documents, digests) {
        (_, [digest]) => eprintln!("Document digest: {digest}"),
        (documents, digests) => {
            eprintln!("Document digests:");
            for (document, digest) in documents.iter().zip(digests) {
                eprintln!("  {}: {digest}", document.title);
            }
        }
    }
}

impl Ui for Headless {
    fn confirm_origin(&mut self, origin: &Origin) -> bool {
        let origin = origin.as_string();
        if self.trust_origin.as_deref() == Some(origin.as_str()) {
            eprintln!("First contact with {origin}: trusted by KEYSEAL_HEADLESS_TRUST_ORIGIN.");
            return true;
        }
        eprintln!(
            "First contact with {origin}. A headless run trusts a new origin only when KEYSEAL_HEADLESS_TRUST_ORIGIN={origin}."
        );
        false
    }

    fn choose_certificate(
        &mut self,
        job: &JobView,
        certificates: &[CertificateSummary],
    ) -> Option<usize> {
        describe(job);
        eprintln!("Several certificates fit this job, and a headless run can't choose one:");
        for certificate in certificates {
            eprintln!(
                "  {}, issued by {}, valid until {}, serial ending {}",
                certificate.name,
                certificate.issuer,
                certificate.valid_until,
                certificate.serial_end
            );
        }
        None
    }

    fn choose_token(&mut self, _: &JobView, _: &[TokenSummary]) -> Option<usize> {
        None
    }

    fn can_choose_token(&self) -> bool {
        false
    }

    fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>> {
        describe(prompt.job);
        if let Some(token) = &prompt.token {
            eprintln!("Token: {token}");
        }
        if let Some(certificate) = &prompt.certificate {
            eprintln!("Certificate: {certificate}");
        }
        match (&prompt.digests, prompt.job.kind) {
            (Some(digests), _) => describe_digests(prompt.job, digests),
            (None, Kind::Sign) => {
                eprintln!("The document digests will be shown for confirmation before signing.")
            }
            (None, Kind::Enrol) => eprintln!(
                "Enrol the certificate on this token, proving its key is here. No document is signed."
            ),
        }
        if let Some(warning) = prompt.pin_warning {
            eprintln!("{}", warning.message());
        }
        if prompt.pin_pad {
            eprintln!("Enter the PIN on the token's PIN pad.");
            return Some(Zeroizing::default());
        }
        // The PIN is used once per job and never retried.
        let pin = self.pin.take();
        if pin.is_none() {
            eprintln!("KEYSEAL_PIN isn't set.");
        }
        pin
    }

    fn retries_pin(&self) -> bool {
        false
    }

    fn confirm_digest(&mut self, confirm: &DigestConfirm) -> bool {
        describe(confirm.job);
        eprintln!("Certificate: {}", confirm.certificate);
        describe_digests(confirm.job, &confirm.digests);
        eprintln!("Signing confirmed (headless).");
        true
    }

    fn confirm_enrol(&mut self, job: &JobView) -> bool {
        describe(job);
        eprintln!(
            "Enrolling a certificate from the system certificate store, proving its key is there (headless)."
        );
        true
    }

    fn show_error(&mut self, message: &str) {
        eprintln!("error: {message}");
    }

    fn show_info(&mut self, message: &str) {
        eprintln!("{message}");
    }
}

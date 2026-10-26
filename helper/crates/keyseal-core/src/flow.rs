//! One sign or enrol job from a `keyseal://` link, as one state machine for
//! every front end. The front end supplies a [`Ui`]; the flow decides what
//! is shown when.
//!
//! Sign jobs take one of two paths (section 12.1). When the token shows a
//! signing certificate before login, the helper posts it, validates the
//! answer and asks for the PIN in one view with the digests. When it shows
//! none, the PIN comes first, and the digests are confirmed after round 1,
//! before signing. On both paths every prepared PDF is downloaded and
//! checked against its digest before the digests are shown (section 8.4).
//! A job's documents are signed together: one PIN or confirmation, one
//! token session, and any failure stops the job before any is signed.
//!
//! When no PKCS#11 module reaches a token, Windows falls back to the
//! certificate store through CNG. Its certificates are visible without a
//! PIN, and the vendor's PIN dialog appears during signing, so the helper
//! asks for no PIN: the digest confirmation, after round 1, is the gate.

use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::cms::{self, KeyKind};
#[cfg(windows)]
use crate::cng::{Cng, SystemStore};
use crate::document;
use crate::manifest::{self, Branding};
use crate::modules::{self, Attempt};
use crate::origin::Origin;
use crate::protocol::{
    self, DocumentEntry, JobClient, JobDescription, Kind, PreparedSignature, ProtocolError,
};
use crate::token::{self, TokenBackend, TokenCertificate, TokenError};
use crate::trust::TrustStore;

const CANCELLED: &str = "Signing cancelled.";
const ENROLMENT_CANCELLED: &str = "Enrolment cancelled.";

impl From<TokenError> for String {
    fn from(error: TokenError) -> Self {
        error.0
    }
}

impl From<ProtocolError> for String {
    fn from(error: ProtocolError) -> Self {
        error.message
    }
}

/// Why a job didn't finish. `cancelled` is set when the user declined a
/// prompt; front ends report it without an error window.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub cancelled: bool,
}

impl Failure {
    fn cancelled(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            cancelled: true,
        }
    }
}

impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            cancelled: false,
        }
    }
}

impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}

impl From<TokenError> for Failure {
    fn from(error: TokenError) -> Self {
        error.0.into()
    }
}

impl From<ProtocolError> for Failure {
    fn from(error: ProtocolError) -> Self {
        error.message.into()
    }
}

pub struct Environment {
    /// `KEYSEAL_ALLOW_INSECURE_ORIGINS=1` (section 4.4).
    pub allow_insecure: bool,
    /// Holds the trust store and the manifest cache.
    pub config_dir: PathBuf,
}

/// What every job window shows. `origin.insecure` asks for the
/// insecure-origin banner; `branding` is only ever set for trusted origins.
pub struct JobView<'a> {
    pub origin: &'a Origin,
    pub branding: Option<&'a Branding>,
    pub kind: Kind,
    pub title: &'a str,
    pub signer: &'a str,
    /// A sign job's documents, in order; empty for enrol.
    pub documents: &'a [DocumentEntry],
}

pub struct PinPrompt<'a> {
    pub job: &'a JobView<'a>,
    /// Subject of the signing certificate, when known before login.
    pub certificate: Option<String>,
    /// Each document's messageDigest as lowercase hex, in the order of
    /// `job.documents`. `None` on a sign job means the PIN comes first and
    /// the digests will be shown for confirmation.
    pub digests: Option<Vec<String>>,
    /// The PIN is entered on the token's PIN pad; return any string.
    pub pin_pad: bool,
    pub pin_warning: Option<&'static str>,
}

pub struct DigestConfirm<'a> {
    pub job: &'a JobView<'a>,
    pub certificate: String,
    /// Each document's messageDigest, as in [`PinPrompt::digests`].
    pub digests: Vec<String>,
}

/// What the job is doing while the signer waits, in order. Enrol takes
/// Connecting, OpeningToken and CheckingCertificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Fetching the manifest and claiming the job.
    Connecting,
    OpeningToken,
    /// Posting the certificate for the server to check.
    CheckingCertificate,
    /// Downloading and checking every document (section 8.4).
    Downloading,
    Signing,
    /// Posting the signatures.
    Sending,
}

/// A step of a job on a trusted origin.
pub struct Progress<'a> {
    pub origin: &'a Origin,
    /// The link's kind.
    pub kind: Kind,
    /// The claimed job; `None` before the claim.
    pub job: Option<&'a JobView<'a>>,
    pub step: Step,
}

pub trait Ui {
    /// First contact with `origin` (section 5): show the origin only.
    fn confirm_origin(&mut self, origin: &Origin) -> bool;
    /// Several certificates fit the job; the index of the chosen subject.
    fn choose_certificate(&mut self, job: &JobView, subjects: &[String]) -> Option<usize>;
    /// The PIN, or `None` if the user cancels.
    fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>>;
    /// The second prompt of the login-first path: an explicit yes to sign
    /// every document.
    fn confirm_digest(&mut self, confirm: &DigestConfirm) -> bool;
    /// An enrol job about to read the certificate store through CNG: the
    /// job, shown before any certificate is read (section 12.2), and an
    /// explicit yes to go on.
    fn confirm_enrol(&mut self, job: &JobView) -> bool;
    fn show_error(&mut self, message: &str);
    /// Something the user should know that isn't a failure, such as an
    /// update they have to install themselves.
    fn show_info(&mut self, message: &str);
    /// The job reached `progress.step`; false when the signer cancelled.
    /// Only called once the origin is trusted. Doesn't wait for the signer.
    fn progress(&mut self, _progress: Progress) -> bool {
        true
    }
    /// The window the vendor's PIN dialog belongs to (CNG's
    /// `NCRYPT_WINDOW_HANDLE_PROPERTY`), as an `HWND`.
    fn window_handle(&self) -> Option<isize> {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Signed,
    Enrolled,
}

/// Called before the certificate store is read through CNG; an error stops
/// the job.
type BeforeCng<'a> = &'a mut dyn FnMut() -> Result<(), Failure>;

/// Opens where the job's key is.
type Open<'a> = &'a dyn Fn(BeforeCng) -> Result<Backend, Failure>;

/// Runs the job in `link`. Any failure is reported to the server once the
/// job is claimed, shown through `ui` unless the user cancelled, and
/// returned.
pub fn run(link: &str, ui: &mut dyn Ui, env: &Environment) -> Result<Outcome, Failure> {
    run_with(link, ui, env, &|before_cng| {
        open_backend(before_cng, &mut |_, _| {})
    })
}

fn run_with(
    link: &str,
    ui: &mut dyn Ui,
    env: &Environment,
    open: Open,
) -> Result<Outcome, Failure> {
    let result = run_link(link, ui, env, open);
    if let Err(failure) = &result
        && !failure.cancelled
    {
        ui.show_error(&failure.message);
    }
    result
}

fn run_link(
    link: &str,
    ui: &mut dyn Ui,
    env: &Environment,
    open: Open,
) -> Result<Outcome, Failure> {
    let link = protocol::parse_link(link, env.allow_insecure)?;
    let origin = &link.origin;
    let store = TrustStore::new(&env.config_dir);
    if !store.is_trusted(origin)? {
        if !ui.confirm_origin(origin) {
            return Err(Failure::cancelled(format!(
                "{origin} isn't trusted, so nothing was sent to it."
            )));
        }
        if !origin.insecure {
            store.trust(origin)?;
        }
    }
    let cancelled = match link.kind {
        Kind::Sign => CANCELLED,
        Kind::Enrol => ENROLMENT_CANCELLED,
    };
    let connecting = Progress {
        origin,
        kind: link.kind,
        job: None,
        step: Step::Connecting,
    };
    if !ui.progress(connecting) {
        return Err(Failure::cancelled(cancelled));
    }
    let branding = manifest::branding(origin, &env.config_dir.join("manifests"));
    if let Some(branding) = &branding
        && branding.manifest.needs_newer_helper()
    {
        crate::update::check_soon();
        return Err(Failure::from(format!(
            "{origin} needs KeySeal helper {} or later; this is {}. Update the helper, then try again.",
            branding
                .manifest
                .min_helper_version
                .as_deref()
                .unwrap_or_default(),
            crate::VERSION
        )));
    }

    let client = JobClient::new(&link);
    let job = client.claim()?;
    let view = JobView {
        origin,
        branding: branding.as_ref(),
        kind: job.kind,
        title: &job.title,
        signer: &job.signer,
        documents: if job.kind == Kind::Sign {
            &job.documents
        } else {
            &[]
        },
    };
    let result = if job.kind != link.kind {
        Err(Failure::from(format!(
            "The link asked for a {:?} job, but {origin} sent a {:?} job.",
            link.kind, job.kind
        )))
    } else if job.kind == Kind::Sign {
        sign(&client, &job, &view, ui, open)
    } else {
        enrol(&client, &job, &view, ui, open)
    };
    if let Err(failure) = &result {
        // Best effort: the helper shows the reason itself regardless.
        let _ = client.report_failure(&job.claim_nonce, &failure.message);
    }
    result
}

fn sign(
    client: &JobClient,
    job: &JobDescription,
    view: &JobView,
    ui: &mut dyn Ui,
    open: Open,
) -> Result<Outcome, Failure> {
    show_step(ui, view, Step::OpeningToken, CANCELLED)?;
    let backend = open(&mut || Ok(()))?;
    let token = backend.token();
    // Cancelling once the token is open logs out, as declining the digests
    // does.
    let reached =
        |ui: &mut dyn Ui, step| show_step(ui, view, step, CANCELLED).inspect_err(|_| token.close());
    let mut certificates = signing_certificates(token, false)?;
    let login_first = match &backend {
        Backend::Pkcs11(_) if certificates.is_empty() => {
            let prompt = PinPrompt {
                job: view,
                certificate: None,
                digests: None,
                pin_pad: token.pin_pad(),
                pin_warning: token.pin_warning(),
            };
            let pin = ui
                .prompt_pin(&prompt)
                .ok_or_else(|| Failure::cancelled(CANCELLED))?;
            token.login(pin)?;
            certificates = signing_certificates(token, true)?;
            true
        }
        _ => false,
    };
    let certificate = choose(ui, view, certificates, job, false)?;
    let chain = chain(token, &certificate)?;
    reached(ui, Step::CheckingCertificate)?;
    let prepared = client.prepare(&job.claim_nonce, &certificate.der, &chain)?;
    let digests = check_prepared(view.origin, job, &certificate, &prepared)?;
    reached(ui, Step::Downloading)?;
    check_documents(client, view.origin, job, &prepared, &digests)?;
    let digests: Vec<String> = digests.iter().map(hex::encode).collect();
    let subject = token::subject(&certificate.der);
    match &backend {
        Backend::Pkcs11(_) if !login_first => {
            let prompt = PinPrompt {
                job: view,
                certificate: Some(subject),
                digests: Some(digests),
                pin_pad: token.pin_pad(),
                pin_warning: token.pin_warning(),
            };
            let pin = ui
                .prompt_pin(&prompt)
                .ok_or_else(|| Failure::cancelled(CANCELLED))?;
            token.login(pin)?;
        }
        // The login-first path, and CNG before the vendor's PIN dialog.
        _ => {
            let confirm = DigestConfirm {
                job: view,
                certificate: subject,
                digests,
            };
            if !ui.confirm_digest(&confirm) {
                token.close();
                return Err(Failure::cancelled(CANCELLED));
            }
        }
    }
    reached(ui, Step::Signing)?;
    // Every document in the one session the PIN opened.
    let signatures = token.sign(
        &certificate.der,
        &prepared.to_sign,
        prepared.digest_algorithm,
        prepared.signature_algorithm,
        ui.window_handle(),
    )?;
    token.close();
    if signatures.len() != prepared.to_sign.len() {
        return Err("The token didn't sign every document.".into());
    }
    reached(ui, Step::Sending)?;
    client.submit_signatures(&job.claim_nonce, &signatures)?;
    Ok(Outcome::Signed)
}

/// Enrol logs in to see which certificates have a private key; the PIN
/// prompt shows the origin, title and signer first (section 12.2). CNG
/// needs no login, so the job is shown before the store is read, and the
/// certificate choice is always asked.
fn enrol(
    client: &JobClient,
    job: &JobDescription,
    view: &JobView,
    ui: &mut dyn Ui,
    open: Open,
) -> Result<Outcome, Failure> {
    show_step(ui, view, Step::OpeningToken, ENROLMENT_CANCELLED)?;
    let backend = open(&mut || {
        if ui.confirm_enrol(view) {
            Ok(())
        } else {
            Err(Failure::cancelled(ENROLMENT_CANCELLED))
        }
    })?;
    let token = backend.token();
    let certificate = match &backend {
        Backend::Pkcs11(_) => {
            let prompt = PinPrompt {
                job: view,
                certificate: None,
                digests: None,
                pin_pad: token.pin_pad(),
                pin_warning: token.pin_warning(),
            };
            let pin = ui
                .prompt_pin(&prompt)
                .ok_or_else(|| Failure::cancelled(ENROLMENT_CANCELLED))?;
            token.login(pin)?;
            choose(ui, view, signing_certificates(token, true)?, job, false)?
        }
        #[cfg(any(windows, test))]
        Backend::Cng(_) => choose(ui, view, signing_certificates(token, false)?, job, true)?,
    };
    let chain = chain(token, &certificate)?;
    token.close();
    show_step(ui, view, Step::CheckingCertificate, ENROLMENT_CANCELLED)?;
    client.enrol(&job.claim_nonce, &certificate.der, &chain)?;
    Ok(Outcome::Enrolled)
}

/// Shows `step` of the claimed job in `view`; a failure saying `cancelled`
/// when the signer cancelled.
fn show_step(ui: &mut dyn Ui, view: &JobView, step: Step, cancelled: &str) -> Result<(), Failure> {
    let progress = Progress {
        origin: view.origin,
        kind: view.kind,
        job: Some(view),
        step,
    };
    if ui.progress(progress) {
        Ok(())
    } else {
        Err(Failure::cancelled(cancelled))
    }
}

/// Where the job's key is.
pub enum Backend {
    /// A PKCS#11 token, in this process or in the token worker.
    Pkcs11(Box<dyn TokenBackend>),
    /// The certificate store through CNG.
    #[cfg(any(windows, test))]
    Cng(Box<dyn TokenBackend>),
}

impl Backend {
    pub fn token(&self) -> &dyn TokenBackend {
        match self {
            Self::Pkcs11(token) => &**token,
            #[cfg(any(windows, test))]
            Self::Cng(cng) => &**cng,
        }
    }
}

/// The error of a CNG attempt that finds no signing certificate on hardware.
const NO_CNG_CERTIFICATE: &str = "The certificate store holds no signing certificate on hardware.";

/// Opens the first of [`modules::attempts`] that reaches a token.
/// `before_cng` runs before the certificate store is read; `seen` hears
/// how each attempt went.
pub fn open_backend(
    before_cng: BeforeCng,
    seen: &mut dyn FnMut(&Attempt, Result<(), &str>),
) -> Result<Backend, Failure> {
    open_first(&modules::attempts()?, &open_attempt, before_cng, seen)
}

fn open_attempt(attempt: &Attempt, wait: Duration) -> Result<Backend, String> {
    match attempt {
        Attempt::Module(candidate) => Ok(Backend::Pkcs11(token::open(&candidate.path, wait)?)),
        #[cfg(windows)]
        Attempt::Cng => {
            let cng = Cng::new(SystemStore);
            if cng.certificates(false)?.is_empty() {
                return Err(NO_CNG_CERTIFICATE.into());
            }
            Ok(Backend::Cng(Box::new(cng)))
        }
        #[cfg(not(windows))]
        Attempt::Cng => Err(NO_CNG_CERTIFICATE.into()),
    }
}

/// Tries `attempts` in order and moves on when one fails: a module that
/// doesn't load or sees no token, or a store without a signing
/// certificate. Only the driver of a plugged-in token gets
/// [`token::SLOT_WAIT`] for its token to appear; the others are looked at
/// once. When all fail, the first failure that isn't "nothing there"; else
/// no token when a module loaded, else no driver.
fn open_first(
    attempts: &[Attempt],
    open: &dyn Fn(&Attempt, Duration) -> Result<Backend, String>,
    before_cng: BeforeCng,
    seen: &mut dyn FnMut(&Attempt, Result<(), &str>),
) -> Result<Backend, Failure> {
    let mut failure = None;
    let mut module_found = false;
    for attempt in attempts {
        if *attempt == Attempt::Cng {
            before_cng()?;
        } else {
            module_found = true;
        }
        let plugged_in = matches!(
            attempt,
            Attempt::Module(modules::Candidate {
                source: modules::Source::UsbMatch(_),
                ..
            })
        );
        let wait = if plugged_in {
            token::SLOT_WAIT
        } else {
            Duration::ZERO
        };
        match open(attempt, wait) {
            Ok(backend) => {
                seen(attempt, Ok(()));
                return Ok(backend);
            }
            Err(message) => {
                seen(attempt, Err(&message));
                if failure.is_none() && message != token::NO_TOKEN && message != NO_CNG_CERTIFICATE
                {
                    failure = Some(message);
                }
            }
        }
    }
    Err(Failure::from(failure.unwrap_or_else(|| {
        if module_found {
            token::NO_TOKEN.into()
        } else {
            format!("{} Install your token's driver.", modules::NO_DRIVER)
        }
    })))
}

/// Certificates the job may use: signing certificates, and after login
/// only those with a private key beside them.
fn signing_certificates(
    token: &dyn TokenBackend,
    logged_in: bool,
) -> Result<Vec<TokenCertificate>, String> {
    let mut found = token.certificates(logged_in)?;
    found.retain(|certificate| token::is_signing_certificate(&certificate.der));
    Ok(found)
}

/// The certificate to use: the expected one if the job names it, else the
/// only one, else the user's choice, among those that satisfy the job's
/// certificate policy (section 8.2). `always_ask` asks even
/// when one fits.
fn choose(
    ui: &mut dyn Ui,
    view: &JobView,
    mut certificates: Vec<TokenCertificate>,
    job: &JobDescription,
    always_ask: bool,
) -> Result<TokenCertificate, Failure> {
    if let Some(expected) = &job.expected_certificate_sha256 {
        certificates.retain(|c| &c.sha256 == expected);
        if certificates.is_empty() {
            return Err(
                "This token doesn't hold the certificate the job asks for. Plug in the right token, or enrol this one first."
                    .into(),
            );
        }
    }
    if let Some(policy) = &job.certificate_policy
        && !certificates.is_empty()
    {
        certificates.retain(|c| policy.accepts(&c.der));
        if certificates.is_empty() {
            return Err(format!(
                "None of the certificates on this token are accepted by {} for this job.",
                view.origin
            )
            .into());
        }
    }
    if certificates.is_empty() {
        return Err("No signing certificate was found on the token.".into());
    }
    if certificates.len() == 1 && !always_ask {
        return Ok(certificates.remove(0));
    }
    let subjects: Vec<String> = certificates
        .iter()
        .map(|c| token::subject(&c.der))
        .collect();
    let index = ui
        .choose_certificate(view, &subjects)
        .filter(|&index| index < certificates.len())
        .ok_or_else(|| Failure::cancelled(CANCELLED))?;
    Ok(certificates.remove(index))
}

/// The other certificates on the token, for the server to build the chain.
fn chain(token: &dyn TokenBackend, chosen: &TokenCertificate) -> Result<Vec<Vec<u8>>, String> {
    Ok(token
        .certificates(false)?
        .into_iter()
        .filter(|c| c.sha256 != chosen.sha256)
        .map(|c| c.der)
        .collect())
}

/// Section 8.4: every prepared PDF hashes to the messageDigest about to be
/// signed for it, and together they stay within the job's size limit.
fn check_documents(
    client: &JobClient,
    origin: &Origin,
    job: &JobDescription,
    prepared: &PreparedSignature,
    digests: &[Vec<u8>],
) -> Result<(), String> {
    let mut left = protocol::MAX_JOB_DOCUMENT_BYTES;
    for (index, digest) in digests.iter().enumerate() {
        let limit = left.min(protocol::MAX_DOCUMENT_BYTES);
        let pdf = client.download_document(index, &job.claim_nonce, limit)?;
        left -= pdf.len() as u64;
        document::check(&pdf, prepared.digest_algorithm, digest).map_err(|reason| {
            let document = match job.documents.as_slice() {
                [_] => "The document".to_owned(),
                documents => format!("The document \"{}\"", documents[index].title),
            };
            format!("{document} from {origin} and the digest it asks to sign disagree: {reason}.")
        })?;
    }
    Ok(())
}

/// Section 8.3's checks on round 1's answer; returns each document's
/// messageDigest, in order.
fn check_prepared(
    origin: &Origin,
    job: &JobDescription,
    certificate: &TokenCertificate,
    prepared: &PreparedSignature,
) -> Result<Vec<Vec<u8>>, String> {
    let refuse = |reason: String| {
        format!("{origin} asked to sign something this helper won't sign: {reason}.")
    };
    if prepared.to_sign.len() != job.documents.len() {
        return Err(refuse(format!(
            "round 1 answered for {} documents, but the job has {}",
            prepared.to_sign.len(),
            job.documents.len()
        )));
    }
    if let Some(expected) = job.digest_algorithm
        && expected != prepared.digest_algorithm
    {
        return Err(refuse(format!(
            "the job said {expected:?} but round 1 asked for {:?}",
            prepared.digest_algorithm
        )));
    }
    KeyKind::of_certificate(&certificate.der)?
        .check(prepared.digest_algorithm, prepared.signature_algorithm)
        .map_err(refuse)?;
    let certificate_sha256 = hex::decode(&certificate.sha256).map_err(|e| e.to_string())?;
    prepared
        .to_sign
        .iter()
        .zip(&job.documents)
        .map(|(to_sign, document)| {
            cms::check_signed_attributes(to_sign, prepared.digest_algorithm, &certificate_sha256)
                .map_err(|reason| match job.documents.len() {
                    1 => refuse(reason),
                    _ => refuse(format!("in \"{}\", {reason}", document.title)),
                })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use x509_parser::asn1_rs::oid;

    use super::*;
    use crate::cms::der_tlv;

    const TOKEN: &str = "q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk";
    const NONCE: &str = "Zx8m_Q2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RSA: &[u8] = include_bytes!("../tests/fixtures/rsa-non-repudiation.der");
    const P256: &[u8] = include_bytes!("../tests/fixtures/non-repudiation.der");

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Stage {
        Trust,
        Choose,
        Pin,
        Confirm,
        Enrol,
        Progress(Step),
    }

    /// Answers every prompt until `cancel_at`, which it cancels.
    struct CancellingUi {
        cancel_at: Stage,
        errors: Vec<String>,
        /// The digests each PIN prompt showed.
        pins: Vec<Option<Vec<String>>>,
        /// Each step shown, and whether it came with the claimed job.
        steps: Vec<(Step, bool)>,
    }

    impl CancellingUi {
        fn new(cancel_at: Stage) -> Self {
            Self {
                cancel_at,
                errors: Vec::new(),
                pins: Vec::new(),
                steps: Vec::new(),
            }
        }
    }

    impl Ui for CancellingUi {
        fn confirm_origin(&mut self, _: &Origin) -> bool {
            self.cancel_at != Stage::Trust
        }
        fn choose_certificate(&mut self, _: &JobView, _: &[String]) -> Option<usize> {
            (self.cancel_at != Stage::Choose).then_some(0)
        }
        fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>> {
            self.pins.push(prompt.digests.clone());
            (self.cancel_at != Stage::Pin).then(|| Zeroizing::new("1234".into()))
        }
        fn confirm_digest(&mut self, _: &DigestConfirm) -> bool {
            self.cancel_at != Stage::Confirm
        }
        fn confirm_enrol(&mut self, _: &JobView) -> bool {
            self.cancel_at != Stage::Enrol
        }
        fn show_error(&mut self, message: &str) {
            self.errors.push(message.to_owned());
        }
        fn show_info(&mut self, _: &str) {}
        fn progress(&mut self, progress: Progress) -> bool {
            self.steps.push((progress.step, progress.job.is_some()));
            self.cancel_at != Stage::Progress(progress.step)
        }
    }

    /// A token showing `public` before login and `private` after.
    struct FakeToken {
        public: Vec<&'static [u8]>,
        private: Vec<&'static [u8]>,
        logged_in: Cell<bool>,
        /// How many items each `sign` call got, shared with the test.
        signed: Arc<Mutex<Vec<usize>>>,
    }

    impl FakeToken {
        fn new(public: Vec<&'static [u8]>, private: Vec<&'static [u8]>) -> Self {
            Self {
                public,
                private,
                logged_in: Cell::new(false),
                signed: Arc::default(),
            }
        }
    }

    impl TokenBackend for FakeToken {
        fn pin_pad(&self) -> bool {
            false
        }
        fn pin_warning(&self) -> Option<&'static str> {
            None
        }
        fn certificates(&self, _: bool) -> Result<Vec<TokenCertificate>, TokenError> {
            let visible = if self.logged_in.get() {
                &self.private
            } else {
                &self.public
            };
            Ok(visible
                .iter()
                .map(|der| TokenCertificate {
                    der: der.to_vec(),
                    sha256: token::sha256_hex(der),
                    id: None,
                })
                .collect())
        }
        fn login(&self, _: Zeroizing<String>) -> Result<(), TokenError> {
            self.logged_in.set(true);
            Ok(())
        }
        fn sign(
            &self,
            _: &[u8],
            data: &[Vec<u8>],
            _: crate::cms::DigestAlgorithm,
            _: crate::cms::SignatureAlgorithm,
            _: Option<isize>,
        ) -> Result<Vec<Vec<u8>>, TokenError> {
            self.signed.lock().unwrap().push(data.len());
            Ok(data.iter().map(|_| vec![1]).collect())
        }
        fn close(&self) {}
    }

    /// The prepared PDF of document `index`, whose `/ByteRange` leaves out
    /// the `/Contents` placeholder, and the SHA-256 of the bytes it covers.
    fn prepared_pdf(index: usize) -> (Vec<u8>, Vec<u8>) {
        let mut pdf =
            format!("%PDF-1.7\n% document {index}\n1 0 obj\n<< /Type /Sig /Contents ").into_bytes();
        let a = pdf.len();
        pdf.extend(b"<");
        pdf.resize(pdf.len() + 64, b'0');
        pdf.extend(b">");
        let b = pdf.len();
        let end = b" >>\nendobj\n%%EOF\n";
        pdf.extend(format!("\n/ByteRange [0 {a} {b} {}]", 40 + end.len()).bytes());
        pdf.resize(b + 40, b' ');
        pdf.extend(end);
        let digest = Sha256::digest([&pdf[..a], &pdf[b..]].concat()).to_vec();
        (pdf, digest)
    }

    fn signed_attributes(certificate: &[u8], digest: &[u8]) -> Vec<u8> {
        let attribute = |oid_raw: &[u8], value: Vec<u8>| {
            der_tlv(
                0x30,
                &[der_tlv(0x06, oid_raw), der_tlv(0x31, &value)].concat(),
            )
        };
        let cert_id = der_tlv(0x30, &der_tlv(0x04, &Sha256::digest(certificate)));
        let mut attributes = [
            attribute(
                &oid!(raw 1.2.840.113549.1.9.3),
                der_tlv(0x06, &oid!(raw 1.2.840.113549.1.7.1)),
            ),
            attribute(&oid!(raw 1.2.840.113549.1.9.4), der_tlv(0x04, digest)),
            attribute(
                &oid!(raw 1.2.840.113549.1.9.16.2.47),
                der_tlv(0x30, &der_tlv(0x30, &cert_id)),
            ),
        ];
        attributes.sort();
        der_tlv(0x31, &attributes.concat())
    }

    /// Serves an RSA job of `kind` with no expected certificate and the
    /// certificate policy `policy`, if not null; returns the origin and
    /// every request line received.
    fn serve(kind: &'static str, policy: serde_json::Value) -> (String, Arc<Mutex<Vec<String>>>) {
        let served = serve_documents(kind, policy, 1, None);
        (served.origin, served.requests)
    }

    /// What a document of a served job gets wrong.
    #[derive(Clone, Copy, Debug)]
    enum Fault {
        /// Its `toSign` carries another document's digest.
        Digest,
        /// It has a byte after the end of its `/ByteRange`.
        ByteRange,
    }

    struct Served {
        origin: String,
        requests: Arc<Mutex<Vec<String>>>,
        /// How many signatures each round 2 carried.
        signatures: Arc<Mutex<Vec<usize>>>,
    }

    /// Serves a job of `kind` with `count` documents, `fault` breaking one
    /// of them, as [`serve`] does.
    fn serve_documents(
        kind: &'static str,
        policy: serde_json::Value,
        count: usize,
        fault: Option<(usize, Fault)>,
    ) -> Served {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let job_path = format!("/api/keyseal/v1/jobs/{TOKEN}");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let signatures = Arc::new(Mutex::new(Vec::new()));
        let signed = signatures.clone();
        let documents: Vec<serde_json::Value> = (0..count)
            .map(|index| {
                json!({
                    "title": format!("Document {}", index + 1),
                    "document": format!("{origin}{job_path}/documents/{index}"),
                })
            })
            .collect();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = header.split_once(':')
                        && key.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                let mut parts = line.split_whitespace();
                let request = format!("{} {}", parts.next().unwrap(), parts.next().unwrap());
                seen.lock().unwrap().push(request.clone());
                let document = |index: usize| {
                    let (mut pdf, digest) = prepared_pdf(index);
                    match fault {
                        Some((at, Fault::Digest)) if at == index => (pdf, prepared_pdf(99).1),
                        Some((at, Fault::ByteRange)) if at == index => {
                            pdf.push(b'\n');
                            (pdf, digest)
                        }
                        _ => (pdf, digest),
                    }
                };
                let served = request
                    .strip_prefix(&format!("GET {job_path}/documents/"))
                    .and_then(|index| index.parse::<usize>().ok())
                    .filter(|&index| index < count);
                let (status, body) = match request.strip_prefix("GET ") {
                    Some(path) if path == job_path => (
                        200,
                        json!({
                            "kind": kind,
                            "title": "Lease",
                            "signer": "Asha Rao",
                            "claimNonce": NONCE,
                            "documents": documents,
                            "certificatePolicy": policy,
                        })
                        .to_string()
                        .into_bytes(),
                    ),
                    Some(_) if served.is_some() => (200, document(served.unwrap()).0),
                    Some(_) => (404, b"{}".to_vec()),
                    None if request.ends_with("/certificate") => {
                        let documents: Vec<serde_json::Value> = (0..count)
                            .map(|index| {
                                let to_sign = signed_attributes(RSA, &document(index).1);
                                json!({ "toSign": STANDARD.encode(to_sign) })
                            })
                            .collect();
                        (
                            200,
                            json!({
                                "documents": documents,
                                "digestAlgorithm": "sha256",
                                "signatureAlgorithm": "rsa-pkcs1-v1_5",
                            })
                            .to_string()
                            .into_bytes(),
                        )
                    }
                    None if request.ends_with("/signature") => {
                        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        signed
                            .lock()
                            .unwrap()
                            .push(body["signatures"].as_array().unwrap().len());
                        (200, b"{}".to_vec())
                    }
                    None => (200, b"{}".to_vec()),
                };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(&body);
            }
        });
        Served {
            origin,
            requests,
            signatures,
        }
    }

    /// Each cancelled prompt or step ends the job quietly: no error shown
    /// and one failure report, or none before the job is claimed.
    #[test]
    fn cancelling_any_prompt_reports_one_failure_and_shows_nothing() {
        for (kind, cng, public, private, cancel_at, reports) in [
            ("sign", false, vec![], vec![], Stage::Trust, 0),
            ("sign", false, vec![RSA, P256], vec![], Stage::Choose, 1),
            ("sign", false, vec![RSA], vec![], Stage::Pin, 1),
            ("sign", false, vec![], vec![RSA], Stage::Pin, 1),
            ("sign", false, vec![], vec![RSA], Stage::Confirm, 1),
            ("enrol", false, vec![], vec![RSA, P256], Stage::Choose, 1),
            ("enrol", false, vec![], vec![RSA], Stage::Pin, 1),
            ("sign", true, vec![RSA], vec![], Stage::Confirm, 1),
            ("enrol", true, vec![RSA], vec![], Stage::Enrol, 1),
            ("enrol", true, vec![RSA], vec![], Stage::Choose, 1),
            (
                "sign",
                false,
                vec![RSA],
                vec![],
                Stage::Progress(Step::Connecting),
                0,
            ),
            (
                "sign",
                false,
                vec![RSA],
                vec![],
                Stage::Progress(Step::OpeningToken),
                1,
            ),
            (
                "sign",
                false,
                vec![RSA],
                vec![],
                Stage::Progress(Step::CheckingCertificate),
                1,
            ),
            (
                "sign",
                false,
                vec![RSA],
                vec![],
                Stage::Progress(Step::Downloading),
                1,
            ),
            (
                "sign",
                false,
                vec![RSA],
                vec![],
                Stage::Progress(Step::Signing),
                1,
            ),
            (
                "sign",
                false,
                vec![],
                vec![RSA],
                Stage::Progress(Step::Signing),
                1,
            ),
            (
                "sign",
                false,
                vec![RSA],
                vec![],
                Stage::Progress(Step::Sending),
                1,
            ),
            (
                "enrol",
                false,
                vec![],
                vec![RSA],
                Stage::Progress(Step::Connecting),
                0,
            ),
            (
                "enrol",
                false,
                vec![],
                vec![RSA],
                Stage::Progress(Step::OpeningToken),
                1,
            ),
            (
                "enrol",
                false,
                vec![],
                vec![RSA],
                Stage::Progress(Step::CheckingCertificate),
                1,
            ),
        ] {
            let case = format!("{kind} {cng} {public:?} {private:?} {cancel_at:?}");
            let (origin, requests) = serve(kind, serde_json::Value::Null);
            let config_dir =
                std::env::temp_dir().join(format!("keyseal-cancel-{}", std::process::id()));
            let env = Environment {
                allow_insecure: true,
                config_dir: config_dir.clone(),
            };
            let job: String = url::form_urlencoded::byte_serialize(
                format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
            )
            .collect();
            let mut ui = CancellingUi::new(cancel_at);
            let open = |before_cng: BeforeCng| {
                let token = Box::new(FakeToken::new(public.clone(), private.clone()));
                if !cng {
                    return Ok(Backend::Pkcs11(token));
                }
                before_cng()?;
                Ok(Backend::Cng(token))
            };
            let failure =
                run_with(&format!("keyseal://{kind}?job={job}"), &mut ui, &env, &open).unwrap_err();
            let _ = std::fs::remove_dir_all(&config_dir);
            assert!(failure.cancelled, "{case}: {}", failure.message);
            assert!(ui.errors.is_empty(), "{case}: {:?}", ui.errors);
            let requests = requests.lock().unwrap();
            let failures = requests.iter().filter(|r| r.ends_with("/failure")).count();
            assert_eq!(failures, reports, "{case}: {requests:?}");
            assert!(
                !requests.iter().any(|r| r.ends_with("/signature")),
                "{case}"
            );
            // Before the claim, nothing reaches the origin.
            if reports == 0 {
                assert!(requests.is_empty(), "{case}: {requests:?}");
            }
            // The enrolment goes to the server only after its step.
            if cancel_at == Stage::Progress(Step::CheckingCertificate) {
                assert!(
                    !requests.iter().any(|r| r.ends_with("/certificate")),
                    "{case}"
                );
            }
        }
    }

    /// Every step is shown in order, the first before the claim without the
    /// job and the rest with it, on both sign paths and for enrol.
    #[test]
    fn shows_each_step_in_order() {
        use Step::*;
        let sign = [
            Connecting,
            OpeningToken,
            CheckingCertificate,
            Downloading,
            Signing,
            Sending,
        ];
        for (kind, public, private, expected) in [
            ("sign", vec![RSA], vec![], &sign[..]),
            ("sign", vec![], vec![RSA], &sign[..]),
            (
                "enrol",
                vec![],
                vec![RSA],
                &[Connecting, OpeningToken, CheckingCertificate][..],
            ),
        ] {
            let (origin, _) = serve(kind, serde_json::Value::Null);
            let config_dir =
                std::env::temp_dir().join(format!("keyseal-steps-{}", std::process::id()));
            let env = Environment {
                allow_insecure: true,
                config_dir: config_dir.clone(),
            };
            let job: String = url::form_urlencoded::byte_serialize(
                format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
            )
            .collect();
            let mut ui = CancellingUi::new(Stage::Enrol);
            let open = |_: BeforeCng| {
                Ok(Backend::Pkcs11(Box::new(FakeToken::new(
                    public.clone(),
                    private.clone(),
                ))))
            };
            let result = run_with(&format!("keyseal://{kind}?job={job}"), &mut ui, &env, &open);
            let _ = std::fs::remove_dir_all(&config_dir);
            assert!(result.is_ok(), "{kind}: {:?}", result.err());
            let steps: Vec<Step> = ui.steps.iter().map(|(step, _)| *step).collect();
            assert_eq!(steps, expected, "{kind}");
            let with_job: Vec<bool> = ui.steps.iter().map(|(_, job)| *job).collect();
            assert!(!with_job[0], "{kind}");
            assert!(with_job[1..].iter().all(|&job| job), "{kind}");
        }
    }

    /// Each attempt fails over to the next: a module that doesn't load, one
    /// that sees no token, then CNG, which the enrol hook precedes.
    #[test]
    fn opens_the_first_attempt_that_reaches_a_token() {
        let module = |name: &str| {
            Attempt::Module(modules::Candidate {
                path: name.into(),
                source: modules::Source::Known,
            })
        };
        let (broken, empty, working) = (module("/broken"), module("/empty"), module("/working"));
        let token = || Box::new(FakeToken::new(vec![RSA], vec![]));
        let events = std::cell::RefCell::new(Vec::new());
        let open = |attempt: &Attempt, _: Duration| {
            events.borrow_mut().push(format!("open {attempt}"));
            match attempt {
                Attempt::Module(candidate) if candidate.path.ends_with("broken") => {
                    Err("Couldn't load the token driver".to_owned())
                }
                Attempt::Module(candidate) if candidate.path.ends_with("empty") => {
                    Err(token::NO_TOKEN.to_owned())
                }
                Attempt::Module(_) => Ok(Backend::Pkcs11(token())),
                Attempt::Cng => Ok(Backend::Cng(token())),
            }
        };
        let run = |attempts: &[Attempt], allow_cng: bool| {
            events.borrow_mut().clear();
            let result = open_first(
                attempts,
                &open,
                &mut || {
                    events.borrow_mut().push("before CNG".into());
                    if allow_cng {
                        Ok(())
                    } else {
                        Err(Failure::cancelled(CANCELLED))
                    }
                },
                &mut |attempt, outcome| {
                    events
                        .borrow_mut()
                        .push(format!("{attempt}: {}", outcome.err().unwrap_or("ok")))
                },
            );
            (result, events.borrow().clone())
        };

        let (result, seen) = run(&[broken.clone(), empty.clone(), Attempt::Cng], true);
        assert!(matches!(result, Ok(Backend::Cng(_))));
        assert_eq!(
            seen,
            [
                "open /broken [known drivers]",
                "/broken [known drivers]: Couldn't load the token driver",
                "open /empty [known drivers]",
                &format!("/empty [known drivers]: {}", token::NO_TOKEN),
                "before CNG",
                "open the Windows certificate store (CNG)",
                "the Windows certificate store (CNG): ok",
            ]
        );

        let (result, seen) = run(&[empty.clone(), working, Attempt::Cng], true);
        assert!(matches!(result, Ok(Backend::Pkcs11(_))));
        assert!(!seen.iter().any(|event| event.contains("CNG")), "{seen:?}");

        // The user declines before the store is read.
        let (result, seen) = run(&[empty.clone(), Attempt::Cng], false);
        assert!(result.is_err_and(|failure| failure.cancelled));
        assert_eq!(seen.last().map(String::as_str), Some("before CNG"));

        let failure = |attempts: &[Attempt]| run(attempts, true).0.err().unwrap().message;
        assert_eq!(
            failure(&[empty.clone(), broken]),
            "Couldn't load the token driver"
        );
        assert_eq!(failure(&[empty]), token::NO_TOKEN);
        assert!(failure(&[]).starts_with(modules::NO_DRIVER));
    }

    /// Of three drivers without a token, only the one of a plugged-in token
    /// waits for it, so the search takes one wait at most.
    #[test]
    fn waits_for_a_token_only_with_a_plugged_in_driver() {
        let module = |name: &str, source| {
            Attempt::Module(modules::Candidate {
                path: name.into(),
                source,
            })
        };
        let attempts = [
            module("/configured", modules::Source::Config),
            module("/plugged-in", modules::Source::UsbMatch("Token".into())),
            module("/known", modules::Source::Known),
        ];
        let waited = Cell::new(Duration::ZERO);
        let open = |_: &Attempt, wait: Duration| {
            waited.set(waited.get() + wait);
            Err(token::NO_TOKEN.to_owned())
        };
        let failure = open_first(&attempts, &open, &mut || Ok(()), &mut |_, _| {}).err();
        assert_eq!(failure.unwrap().message, token::NO_TOKEN);
        assert_eq!(waited.get(), token::SLOT_WAIT);
    }

    /// A certificate policy narrows the choice before the user sees it, and
    /// when no certificate satisfies it the job fails before round 1.
    #[test]
    fn filters_certificates_by_the_job_policy() {
        const POLICY: &[u8] = include_bytes!("../tests/fixtures/policy.der");
        let origin =
            Origin::of_url(&url::Url::parse("https://dash.example.org").unwrap(), false).unwrap();
        let view = JobView {
            origin: &origin,
            branding: None,
            kind: Kind::Enrol,
            title: "Enrolment",
            signer: "Asha Rao",
            documents: &[],
        };
        let job = serde_json::from_value::<JobDescription>(json!({
            "kind": "enrol",
            "title": "Enrolment",
            "signer": "Asha Rao",
            "claimNonce": NONCE,
            "certificatePolicy": { "policyOids": ["2.16.356.100.2.3"] },
        }))
        .unwrap();
        let certificates = |ders: &[&[u8]]| {
            ders.iter()
                .map(|der| TokenCertificate {
                    der: der.to_vec(),
                    sha256: token::sha256_hex(der),
                    id: None,
                })
                .collect::<Vec<_>>()
        };
        let mut ui = CancellingUi::new(Stage::Choose);
        let chosen = choose(
            &mut ui,
            &view,
            certificates(&[RSA, POLICY, P256]),
            &job,
            false,
        );
        assert_eq!(chosen.unwrap().der, POLICY);
        let failure = choose(&mut ui, &view, certificates(&[RSA, P256]), &job, false)
            .err()
            .unwrap();
        assert_eq!(
            failure.message,
            "None of the certificates on this token are accepted by https://dash.example.org for this job."
        );
        assert!(!failure.cancelled);
        let failure = choose(&mut ui, &view, Vec::new(), &job, false)
            .err()
            .unwrap();
        assert_eq!(
            failure.message,
            "No signing certificate was found on the token."
        );

        let (origin, requests) = serve("sign", json!({ "policyOids": ["2.16.356.100.2.3"] }));
        let config_dir =
            std::env::temp_dir().join(format!("keyseal-policy-{}", std::process::id()));
        let env = Environment {
            allow_insecure: true,
            config_dir: config_dir.clone(),
        };
        let link: String = url::form_urlencoded::byte_serialize(
            format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
        )
        .collect();
        let open = |_: BeforeCng| {
            Ok(Backend::Pkcs11(Box::new(FakeToken::new(
                vec![RSA, P256],
                vec![],
            ))))
        };
        let failure =
            run_with(&format!("keyseal://sign?job={link}"), &mut ui, &env, &open).unwrap_err();
        let _ = std::fs::remove_dir_all(&config_dir);
        assert!(
            failure
                .message
                .starts_with("None of the certificates on this token")
        );
        assert_eq!(ui.errors, [failure.message]);
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.iter().filter(|r| r.ends_with("/failure")).count(),
            1
        );
        assert!(!requests.iter().any(|r| r.ends_with("/certificate")));
    }

    /// Runs a sign link against `origin` with a token showing `public`
    /// before login and `private` after; returns the outcome, the UI and how
    /// many items each `sign` call got.
    fn run_sign(
        origin: &str,
        public: Vec<&'static [u8]>,
        private: Vec<&'static [u8]>,
        name: &str,
    ) -> (Result<Outcome, Failure>, CancellingUi, Vec<usize>) {
        let config_dir =
            std::env::temp_dir().join(format!("keyseal-{name}-{}", std::process::id()));
        let env = Environment {
            allow_insecure: true,
            config_dir: config_dir.clone(),
        };
        let link: String = url::form_urlencoded::byte_serialize(
            format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
        )
        .collect();
        let mut ui = CancellingUi::new(Stage::Enrol);
        let token = FakeToken::new(public, private);
        let signed = token.signed.clone();
        let token = std::cell::RefCell::new(Some(token));
        let open = |_: BeforeCng| {
            Ok(Backend::Pkcs11(Box::new(
                token.borrow_mut().take().expect("one token per job"),
            )))
        };
        let result = run_with(&format!("keyseal://sign?job={link}"), &mut ui, &env, &open);
        let _ = std::fs::remove_dir_all(&config_dir);
        let signed = signed.lock().unwrap().clone();
        (result, ui, signed)
    }

    /// Three documents take one PIN prompt showing three digests, one
    /// signing call for all of them, and one round 2 with three signatures;
    /// on the login-first path the confirmation covers them all.
    #[test]
    fn signs_a_batch_with_one_pin_and_one_session() {
        for (public, private) in [(vec![RSA], vec![]), (vec![], vec![RSA])] {
            let served = serve_documents("sign", serde_json::Value::Null, 3, None);
            let login_first = public.is_empty();
            let (result, ui, signed) = run_sign(&served.origin, public, private, "batch");
            assert_eq!(result.unwrap(), Outcome::Signed);
            assert_eq!(ui.pins.len(), 1);
            if !login_first {
                let digests = ui.pins[0].as_ref().unwrap();
                let expected: Vec<String> = (0..3)
                    .map(|index| hex::encode(prepared_pdf(index).1))
                    .collect();
                assert_eq!(digests, &expected);
            }
            assert_eq!(signed, [3]);
            assert_eq!(*served.signatures.lock().unwrap(), [3]);
            let requests = served.requests.lock().unwrap();
            for index in 0..3 {
                assert!(
                    requests
                        .iter()
                        .any(|r| r.ends_with(&format!("/documents/{index}"))),
                    "{requests:?}"
                );
            }
        }
    }

    /// One document whose digest or byte range is wrong stops the whole
    /// batch before the PIN: nothing is signed, and the failure names it.
    #[test]
    fn refuses_a_batch_when_one_document_is_wrong() {
        for fault in [Fault::Digest, Fault::ByteRange] {
            let served = serve_documents("sign", serde_json::Value::Null, 3, Some((1, fault)));
            let (result, ui, signed) = run_sign(&served.origin, vec![RSA], vec![], "batch-fault");
            let failure = result.unwrap_err();
            assert!(!failure.cancelled);
            assert!(
                failure
                    .message
                    .starts_with("The document \"Document 2\" from"),
                "{fault:?}: {}",
                failure.message
            );
            assert!(ui.pins.is_empty(), "{fault:?}");
            assert!(signed.is_empty(), "{fault:?}");
            let requests = served.requests.lock().unwrap();
            assert_eq!(
                requests.iter().filter(|r| r.ends_with("/failure")).count(),
                1
            );
            assert!(!requests.iter().any(|r| r.ends_with("/signature")));
        }
    }
}

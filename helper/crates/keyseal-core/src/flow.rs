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
//! When no PKCS#11 module reaches a token, the helper falls back to the
//! system's certificate store: CNG on Windows, CryptoTokenKit on macOS. Its
//! certificates are visible without a PIN, and the system's or vendor's PIN
//! dialog appears during signing, so the helper asks for no PIN: the digest
//! confirmation, after round 1, is the gate.

use std::path::PathBuf;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::cms::{self, DigestAlgorithm, KeyKind, SignatureAlgorithm};
#[cfg(windows)]
use crate::cng::CngStore;
use crate::document;
#[cfg(target_os = "macos")]
use crate::keychain::Keychain;
use crate::manifest::{self, Branding};
use crate::modules::{self, Attempt, Source};
use crate::origin::Origin;
use crate::protocol::{
    self, DocumentEntry, JobClient, JobDescription, KeyUsage, Kind, PreparedSignature,
    ProtocolError,
};
#[cfg(any(windows, target_os = "macos"))]
use crate::store::Store;
use crate::token::{
    self, CertificateSummary, Driver, LoginError, PinWarning, TokenBackend, TokenCertificate,
    TokenError, TokenInfo, TokenSummary,
};
use crate::trust::TrustStore;

const CANCELLED: &str = "Signing cancelled.";
const ENROLMENT_CANCELLED: &str = "Enrolment cancelled.";
/// The error of a run that can't ask which token to use.
pub const SEVERAL_TOKENS: &str = "More than one token is plugged in, and KeySeal can't ask which one to use without its windows. Unplug the tokens you aren't signing with, then try again.";
/// The error for a panic in the job; the front end logs the panic itself.
pub const INTERNAL_ERROR: &str = "KeySeal stopped because of a problem in KeySeal itself. Start again from the website. If it happens again, contact your support team.";

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
    /// The chosen token's label, when more than one was plugged in.
    pub token: Option<String>,
    /// Subject of the signing certificate, when known before login.
    pub certificate: Option<String>,
    /// Each document's messageDigest as lowercase hex, in the order of
    /// `job.documents`. `None` on a sign job means the PIN comes first and
    /// the digests will be shown for confirmation.
    pub digests: Option<Vec<String>>,
    /// The PIN is entered on the token's PIN pad; return any string.
    pub pin_pad: bool,
    /// What the token's flags say about the attempts left; never
    /// [`PinWarning::Locked`], which fails the job instead.
    pub pin_warning: Option<PinWarning>,
    /// The PIN entered last was wrong; the prompt asks again.
    pub wrong_pin: bool,
}

pub struct DigestConfirm<'a> {
    pub job: &'a JobView<'a>,
    pub certificate: String,
    /// Each document's messageDigest, as in [`PinPrompt::digests`].
    pub digests: Vec<String>,
}

/// What the job is doing while the signer waits, in order. Enrol takes
/// Connecting, OpeningToken, Signing (its proof) and CheckingCertificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// Fetching the manifest and claiming the job.
    Connecting,
    OpeningToken,
    /// Posting the certificate for the server to check.
    CheckingCertificate,
    /// Downloading and checking every document (section 8.4).
    Downloading,
    /// Signing the documents, or an enrol job's proof.
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
    /// Several certificates fit the job; the index of the chosen one.
    fn choose_certificate(
        &mut self,
        job: &JobView,
        certificates: &[CertificateSummary],
    ) -> Option<usize>;
    /// Several tokens are plugged in and the job doesn't settle which; the
    /// index of the chosen one.
    fn choose_token(&mut self, job: &JobView, tokens: &[TokenSummary]) -> Option<usize>;
    /// Whether [`choose_token`](Self::choose_token) can ask. A headless run
    /// can't, and fails the job instead.
    fn can_choose_token(&self) -> bool {
        true
    }
    /// The PIN, or `None` if the user cancels.
    fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>>;
    /// Whether a wrong PIN is asked for again. Headless runs have one PIN,
    /// and trying it again would only use up the token's attempts.
    fn retries_pin(&self) -> bool {
        true
    }
    /// The second prompt of the login-first path: an explicit yes to sign
    /// every document.
    fn confirm_digest(&mut self, confirm: &DigestConfirm) -> bool;
    /// An enrol job about to read the system's certificate store: the
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
    /// The window a Windows provider's PIN dialog belongs to (CNG's
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

/// Called before the system's certificate store is read; an error stops
/// the job.
type BeforeStore<'a> = &'a mut dyn FnMut() -> Result<(), Failure>;

/// Finds where the key is, for a job that asks for `KeyUsage`.
type Open<'a> = &'a dyn Fn(KeyUsage, BeforeStore) -> Result<Found, Failure>;

/// Runs the job in `link`. Any failure is shown through `ui` unless the
/// user cancelled, reported to the server once the job is claimed, and
/// returned. The report goes while the error shows; this returns once it
/// is sent or has timed out.
pub fn run(link: &str, ui: &mut dyn Ui, env: &Environment) -> Result<Outcome, Failure> {
    run_with(link, ui, env, &|usage, before_store| {
        open_backend(usage, before_store, &mut |_, _| {})
    })
}

fn run_with(
    link: &str,
    ui: &mut dyn Ui,
    env: &Environment,
    open: Open,
) -> Result<Outcome, Failure> {
    let mut report = None;
    let result = run_link(link, ui, env, open, &mut report);
    if let Err(failure) = &result
        && !failure.cancelled
    {
        ui.show_error(&failure.message);
    }
    if let Some(report) = report {
        let _ = report.join();
    }
    result
}

/// Runs the job; a failure after the claim starts its report in `report`.
fn run_link(
    link: &str,
    ui: &mut dyn Ui,
    env: &Environment,
    open: Open,
    report: &mut Option<std::thread::JoinHandle<()>>,
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
    } else {
        // A panic still fails the claimed job, so the server hears of it.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if job.kind == Kind::Sign {
                sign(&client, &job, &view, ui, open)
            } else {
                enrol(&client, &job, &view, ui, open)
            }
        }))
        .unwrap_or_else(|_| Err(INTERNAL_ERROR.into()))
    };
    if let Err(failure) = &result {
        // Best effort: the helper shows the reason itself regardless.
        let (nonce, message) = (job.claim_nonce.clone(), failure.message.clone());
        *report = Some(std::thread::spawn(move || {
            let _ = client.report_failure(&nonce, &message);
        }));
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
    let mut chosen = None;
    let backend = open(key_usage(job), &mut || Ok(()))?.open(|tokens| {
        let index = choose_token(ui, view, job, tokens, CANCELLED)?;
        chosen = Some(TokenSummary::of(&tokens[index], key_usage(job)).label);
        Ok(index)
    })?;
    let token = backend.token();
    // Cancelling once the token is open logs out, as declining the digests
    // does.
    let reached =
        |ui: &mut dyn Ui, step| show_step(ui, view, step, CANCELLED).inspect_err(|_| token.close());
    let mut certificates = signing_certificates(token, job, false)?;
    let login_first = match &backend {
        Backend::Pkcs11(_) if certificates.is_empty() => {
            log_in(ui, token, view, chosen.clone(), None, None, CANCELLED)?;
            certificates = signing_certificates(token, job, true)?;
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
            log_in(
                ui,
                token,
                view,
                chosen,
                Some(subject),
                Some(digests),
                CANCELLED,
            )?;
        }
        // The login-first path, and the certificate store before the
        // system's or vendor's PIN dialog.
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
/// prompt shows the origin, title and signer first (section 12.2). The
/// certificate store needs no login, so the job is shown before the store is read, and the
/// certificate choice is always asked. Either way the chosen certificate's
/// key then signs the proof (section 8.6): in the PIN's session, or behind
/// the system's or vendor's PIN dialog.
fn enrol(
    client: &JobClient,
    job: &JobDescription,
    view: &JobView,
    ui: &mut dyn Ui,
    open: Open,
) -> Result<Outcome, Failure> {
    show_step(ui, view, Step::OpeningToken, ENROLMENT_CANCELLED)?;
    let found = open(key_usage(job), &mut || {
        if ui.confirm_enrol(view) {
            Ok(())
        } else {
            Err(Failure::cancelled(ENROLMENT_CANCELLED))
        }
    })?;
    let mut chosen = None;
    let backend = found.open(|tokens| {
        let index = choose_token(ui, view, job, tokens, ENROLMENT_CANCELLED)?;
        chosen = Some(TokenSummary::of(&tokens[index], key_usage(job)).label);
        Ok(index)
    })?;
    let token = backend.token();
    let certificate = match &backend {
        Backend::Pkcs11(_) => {
            log_in(ui, token, view, chosen, None, None, ENROLMENT_CANCELLED)?;
            choose(
                ui,
                view,
                signing_certificates(token, job, true)?,
                job,
                false,
            )?
        }
        #[cfg(any(windows, target_os = "macos", test))]
        Backend::Store(_) => choose(
            ui,
            view,
            signing_certificates(token, job, false)?,
            job,
            true,
        )?,
    };
    let chain = chain(token, &certificate)?;
    show_step(ui, view, Step::Signing, ENROLMENT_CANCELLED).inspect_err(|_| token.close())?;
    let proof = prove(client, job, token, &certificate, ui.window_handle());
    token.close();
    let proof = proof?;
    show_step(ui, view, Step::CheckingCertificate, ENROLMENT_CANCELLED)?;
    client.enrol(&job.claim_nonce, &certificate.der, &chain, &proof)?;
    Ok(Outcome::Enrolled)
}

/// The enrol proof: `certificate`'s key signs the message the helper builds
/// (section 8.6), with the scheme and digest section 11.1 fixes for the key,
/// so nothing about it comes from the server but the job's nonce.
fn prove(
    client: &JobClient,
    job: &JobDescription,
    token: &dyn TokenBackend,
    certificate: &TokenCertificate,
    window: Option<isize>,
) -> Result<Vec<u8>, Failure> {
    let (digest, scheme) = match KeyKind::of_certificate(&certificate.der)? {
        KeyKind::Rsa => (DigestAlgorithm::Sha256, SignatureAlgorithm::RsaPkcs1v15),
        KeyKind::P256 | KeyKind::BrainpoolP256r1 => {
            (DigestAlgorithm::Sha256, SignatureAlgorithm::Ecdsa)
        }
        KeyKind::P384 | KeyKind::BrainpoolP384r1 => {
            (DigestAlgorithm::Sha384, SignatureAlgorithm::Ecdsa)
        }
    };
    let message = client.enrol_proof_message(&job.claim_nonce, &certificate.sha256);
    let signatures = token.sign(&certificate.der, &[message], digest, scheme, window)?;
    match <[Vec<u8>; 1]>::try_from(signatures) {
        Ok([proof]) => Ok(proof),
        Err(_) => Err("The token didn't sign the proof that the certificate is yours.".into()),
    }
}

/// Asks for the PIN and logs in. A wrong PIN is asked for again, in the
/// same session, until the signer enters the right one or cancels; the
/// token counts the attempts. The token's flags are read before each
/// prompt, and a locked PIN fails the job without one.
fn log_in(
    ui: &mut dyn Ui,
    token: &dyn TokenBackend,
    job: &JobView,
    token_label: Option<String>,
    certificate: Option<String>,
    digests: Option<Vec<String>>,
    cancelled: &str,
) -> Result<(), Failure> {
    let mut prompt = PinPrompt {
        job,
        token: token_label,
        certificate,
        digests,
        pin_pad: token.pin_pad(),
        pin_warning: None,
        wrong_pin: false,
    };
    loop {
        prompt.pin_warning = token.pin_warning();
        if prompt.pin_warning == Some(PinWarning::Locked) {
            return Err(token::PIN_LOCKED.into());
        }
        let pin = ui
            .prompt_pin(&prompt)
            .ok_or_else(|| Failure::cancelled(cancelled))?;
        match token.login(pin) {
            Ok(()) => return Ok(()),
            Err(LoginError::WrongPin) if ui.retries_pin() => prompt.wrong_pin = true,
            Err(LoginError::WrongPin) => return Err(token::WRONG_PIN.into()),
            Err(LoginError::Locked) => return Err(token::PIN_LOCKED.into()),
            Err(LoginError::Other(error)) => return Err(error.into()),
        }
    }
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
    /// The system's certificate store: CNG on Windows, CryptoTokenKit on
    /// macOS.
    #[cfg(any(windows, target_os = "macos", test))]
    Store(Box<dyn TokenBackend>),
}

impl Backend {
    pub fn token(&self) -> &dyn TokenBackend {
        match self {
            Self::Pkcs11(token) => &**token,
            #[cfg(any(windows, target_os = "macos", test))]
            Self::Store(store) => &**store,
        }
    }
}

/// The error of a certificate store attempt that finds no signing
/// certificate on a token.
pub(crate) const NO_STORE_CERTIFICATE: &str =
    "The certificate store holds no signing certificate on a token or smart card.";

/// Where the job's key may be: tokens the PKCS#11 drivers reached, one of
/// which is then opened, or the certificate store.
pub enum Found {
    Tokens(Tokens),
    Backend(Backend),
}

/// Tokens the PKCS#11 drivers reached, none opened yet.
pub struct Tokens {
    drivers: Vec<Box<dyn Driver>>,
    tokens: Vec<TokenInfo>,
    /// The index in `drivers` of each token's driver.
    driver_of: Vec<usize>,
}

impl Tokens {
    /// Adds `driver` and its `tokens`, leaving out a token an earlier driver
    /// listed: one with the same serial number, which is one token two
    /// drivers reach.
    fn add(&mut self, driver: Box<dyn Driver>, tokens: Vec<TokenInfo>) {
        let earlier: Vec<String> = self
            .tokens
            .iter()
            .map(|token| token.serial.trim().to_owned())
            .filter(|serial| !serial.is_empty())
            .collect();
        let new: Vec<TokenInfo> = tokens
            .into_iter()
            .filter(|token| !earlier.iter().any(|serial| serial == token.serial.trim()))
            .collect();
        if new.is_empty() {
            return;
        }
        for token in new {
            self.tokens.push(token);
            self.driver_of.push(self.drivers.len());
        }
        self.drivers.push(driver);
    }
}

impl Found {
    /// The backend: the certificate store, or the token `choose` picks when
    /// there are several, opened.
    pub fn open(
        self,
        choose: impl FnOnce(&[TokenInfo]) -> Result<usize, Failure>,
    ) -> Result<Backend, Failure> {
        let mut found = match self {
            Self::Tokens(found) => found,
            Self::Backend(backend) => return Ok(backend),
        };
        let index = match found.tokens.len() {
            1 => 0,
            _ => {
                // Read only now: a job with one token talks to it as it did
                // before there was a choice.
                for (token, &driver) in found.tokens.iter_mut().zip(&found.driver_of) {
                    token.certificates = found.drivers[driver].shown(token.slot);
                }
                choose(&found.tokens)?
            }
        };
        let slot = found.tokens[index].slot;
        let driver = found
            .drivers
            .into_iter()
            .nth(found.driver_of[index])
            .expect("every token has its driver");
        Ok(Backend::Pkcs11(driver.open(slot)?))
    }
}

/// What one attempt reached.
enum Reached {
    Tokens(Box<dyn Driver>, Vec<TokenInfo>),
    /// The certificate store.
    #[cfg(any(windows, target_os = "macos", test))]
    Backend(Backend),
}

/// Finds the tokens [`modules::attempts`] reach, as [`open_first`] says;
/// the certificate store counts only when it holds a certificate with
/// `usage`. `before_store` runs before the certificate store is read;
/// `seen` hears how each attempt went.
pub fn open_backend(
    usage: KeyUsage,
    before_store: BeforeStore,
    seen: &mut dyn FnMut(&Attempt, Result<(), &str>),
) -> Result<Found, Failure> {
    let open = |attempt: &Attempt, wait| open_attempt(attempt, wait, usage);
    open_first(&modules::attempts()?, &open, before_store, seen)
}

#[cfg_attr(not(any(windows, target_os = "macos")), allow(unused_variables))]
fn open_attempt(attempt: &Attempt, wait: Duration, usage: KeyUsage) -> Result<Reached, String> {
    match attempt {
        Attempt::Module(candidate) => {
            let (driver, tokens) = token::tokens(&candidate.path, wait)?;
            Ok(Reached::Tokens(driver, tokens))
        }
        #[cfg(any(windows, target_os = "macos"))]
        Attempt::Store => {
            #[cfg(windows)]
            let store = Store::new(CngStore, usage);
            #[cfg(target_os = "macos")]
            let store = Store::new(Keychain::tokens(), usage);
            if store.certificates(false)?.is_empty() {
                return Err(NO_STORE_CERTIFICATE.into());
            }
            Ok(Reached::Backend(Backend::Store(Box::new(store))))
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        Attempt::Store => Err(NO_STORE_CERTIFICATE.into()),
    }
}

/// Tries `attempts` in order and moves on when one fails: a module that
/// doesn't load or sees no token, or a store without a signing
/// certificate. The drivers of plugged-in tokens are all listed, every
/// token of each, since the signer may have plugged in several. Any other
/// attempt that reaches a token ends the search with every token of it:
/// the configured module because the signer chose that driver, and the
/// rest because drivers can hang or crash, so they aren't loaded once a
/// token is found. Only the driver of a plugged-in token gets
/// [`token::SLOT_WAIT`] for its token to appear; the others are looked at
/// once. When all fail, the first failure that isn't "nothing there"; else
/// no token when a module loaded, else no driver.
fn open_first(
    attempts: &[Attempt],
    open: &dyn Fn(&Attempt, Duration) -> Result<Reached, String>,
    before_store: BeforeStore,
    seen: &mut dyn FnMut(&Attempt, Result<(), &str>),
) -> Result<Found, Failure> {
    let mut failure = None;
    let mut module_found = false;
    let mut found = Tokens {
        drivers: Vec::new(),
        tokens: Vec::new(),
        driver_of: Vec::new(),
    };
    for attempt in attempts {
        let source = match attempt {
            Attempt::Module(candidate) => Some(&candidate.source),
            Attempt::Store => None,
        };
        let plugged_in = matches!(source, Some(Source::UsbMatch(_)));
        if !plugged_in && !found.tokens.is_empty() {
            break;
        }
        if source.is_none() {
            before_store()?;
        } else {
            module_found = true;
        }
        let wait = if plugged_in {
            token::SLOT_WAIT
        } else {
            Duration::ZERO
        };
        match open(attempt, wait) {
            #[cfg(any(windows, target_os = "macos", test))]
            Ok(Reached::Backend(backend)) => {
                seen(attempt, Ok(()));
                return Ok(Found::Backend(backend));
            }
            Ok(Reached::Tokens(driver, tokens)) => {
                seen(attempt, Ok(()));
                found.add(driver, tokens);
                if !plugged_in {
                    break;
                }
            }
            Err(message) => {
                seen(attempt, Err(&message));
                if failure.is_none()
                    && message != token::NO_TOKEN
                    && message != NO_STORE_CERTIFICATE
                {
                    failure = Some(message);
                }
            }
        }
    }
    if !found.tokens.is_empty() {
        return Ok(Found::Tokens(found));
    }
    Err(Failure::from(failure.unwrap_or_else(|| {
        if module_found {
            token::NO_TOKEN.into()
        } else {
            format!("{} Install your token's driver.", modules::NO_DRIVER)
        }
    })))
}

/// The token to use among several: the only one showing the certificate
/// the job expects, else the signer's choice.
fn choose_token(
    ui: &mut dyn Ui,
    view: &JobView,
    job: &JobDescription,
    tokens: &[TokenInfo],
    cancelled: &str,
) -> Result<usize, Failure> {
    if let Some(expected) = &job.expected_certificate_sha256 {
        let holders: Vec<usize> = (0..tokens.len())
            .filter(|&index| {
                tokens[index]
                    .certificates
                    .iter()
                    .any(|certificate| &certificate.sha256 == expected)
            })
            .collect();
        if let [index] = holders[..] {
            return Ok(index);
        }
    }
    if !ui.can_choose_token() {
        return Err(SEVERAL_TOKENS.into());
    }
    let summaries: Vec<TokenSummary> = tokens
        .iter()
        .map(|token| TokenSummary::of(token, key_usage(job)))
        .collect();
    ui.choose_token(view, &summaries)
        .filter(|&index| index < tokens.len())
        .ok_or_else(|| Failure::cancelled(cancelled))
}

/// The key usage the job's certificate policy asks for, nonRepudiation
/// without one (section 8.2).
fn key_usage(job: &JobDescription) -> KeyUsage {
    job.certificate_policy
        .as_ref()
        .and_then(|policy| policy.key_usage)
        .unwrap_or_default()
}

/// Certificates the job may use: signing certificates with the key usage
/// its certificate policy asks for (nonRepudiation without one), within
/// their validity period, and after login only those with a private key
/// beside them. When every one is outside its validity period, that is the
/// error, so a token showing only an expired certificate before login
/// fails without asking for the PIN.
fn signing_certificates(
    token: &dyn TokenBackend,
    job: &JobDescription,
    logged_in: bool,
) -> Result<Vec<TokenCertificate>, String> {
    let usage = key_usage(job);
    let mut found = token.certificates(logged_in)?;
    found.retain(|certificate| token::is_signing_certificate(&certificate.der, usage));
    let now = x509_parser::time::ASN1Time::now().timestamp();
    let outside = found
        .iter()
        .find_map(|certificate| token::outside_validity(&certificate.der, now));
    found.retain(|certificate| token::outside_validity(&certificate.der, now).is_none());
    match outside {
        Some(reason) if found.is_empty() => Err(reason),
        _ => Ok(found),
    }
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
    let summaries: Vec<CertificateSummary> = certificates
        .iter()
        .map(|c| CertificateSummary::of(&c.der))
        .collect();
    let index = ui
        .choose_certificate(view, &summaries)
        .filter(|&index| index < certificates.len())
        .ok_or_else(|| Failure::cancelled(CANCELLED))?;
    Ok(certificates.remove(index))
}

/// The chosen certificate's issuers among the other certificates on the
/// token, for the server to build the chain; a shared token's other
/// signers' certificates aren't sent.
fn chain(token: &dyn TokenBackend, chosen: &TokenCertificate) -> Result<Vec<Vec<u8>>, String> {
    let others = token
        .certificates(false)?
        .into_iter()
        .filter(|c| c.sha256 != chosen.sha256)
        .map(|c| c.der)
        .collect();
    Ok(token::issuers(&chosen.der, others))
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
    /// Valid from 1 January 2020 to 1 January 2021.
    const EXPIRED: &[u8] = include_bytes!("../tests/fixtures/expired.der");

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Stage {
        Trust,
        Choose,
        Token,
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
        /// With `cancel_at` [`Stage::Pin`], how many PIN prompts are
        /// answered before one is cancelled.
        pins_to_answer: usize,
        /// The warning and wrong-PIN flag each PIN prompt showed.
        pin_states: Vec<(Option<PinWarning>, bool)>,
        /// [`Ui::retries_pin`].
        retries_pin: bool,
        /// When the last error showed.
        error_shown: Option<std::time::Instant>,
        /// The tokens each token choice listed.
        token_choices: Vec<Vec<TokenSummary>>,
        /// The token each choice picks.
        token_answer: usize,
        /// The token label each PIN prompt showed.
        pin_tokens: Vec<Option<String>>,
    }

    impl CancellingUi {
        fn new(cancel_at: Stage) -> Self {
            Self {
                cancel_at,
                errors: Vec::new(),
                pins: Vec::new(),
                steps: Vec::new(),
                pins_to_answer: 0,
                pin_states: Vec::new(),
                retries_pin: true,
                error_shown: None,
                token_choices: Vec::new(),
                token_answer: 0,
                pin_tokens: Vec::new(),
            }
        }
    }

    impl Ui for CancellingUi {
        fn confirm_origin(&mut self, _: &Origin) -> bool {
            self.cancel_at != Stage::Trust
        }
        fn choose_certificate(&mut self, _: &JobView, _: &[CertificateSummary]) -> Option<usize> {
            (self.cancel_at != Stage::Choose).then_some(0)
        }
        fn choose_token(&mut self, _: &JobView, tokens: &[TokenSummary]) -> Option<usize> {
            self.token_choices.push(tokens.to_vec());
            (self.cancel_at != Stage::Token).then_some(self.token_answer)
        }
        fn can_choose_token(&self) -> bool {
            self.retries_pin
        }
        fn prompt_pin(&mut self, prompt: &PinPrompt) -> Option<Zeroizing<String>> {
            self.pin_tokens.push(prompt.token.clone());
            self.pins.push(prompt.digests.clone());
            self.pin_states.push((prompt.pin_warning, prompt.wrong_pin));
            (self.cancel_at != Stage::Pin || self.pins.len() <= self.pins_to_answer)
                .then(|| Zeroizing::new("1234".into()))
        }
        fn retries_pin(&self) -> bool {
            self.retries_pin
        }
        fn confirm_digest(&mut self, _: &DigestConfirm) -> bool {
            self.cancel_at != Stage::Confirm
        }
        fn confirm_enrol(&mut self, _: &JobView) -> bool {
            self.cancel_at != Stage::Enrol
        }
        fn show_error(&mut self, message: &str) {
            self.errors.push(message.to_owned());
            self.error_shown = Some(std::time::Instant::now());
        }
        fn show_info(&mut self, _: &str) {}
        fn progress(&mut self, progress: Progress) -> bool {
            self.steps.push((progress.step, progress.job.is_some()));
            self.cancel_at != Stage::Progress(progress.step)
        }
    }

    type SignCall = (Vec<Vec<u8>>, DigestAlgorithm, SignatureAlgorithm);

    /// A token showing `public` before login and `private` after.
    struct FakeToken {
        public: Vec<&'static [u8]>,
        private: Vec<&'static [u8]>,
        logged_in: Cell<bool>,
        /// How many items each `sign` call got, shared with the test.
        signed: Arc<Mutex<Vec<usize>>>,
        /// What each `sign` call got: its items, digest and scheme.
        sign_calls: Arc<Mutex<Vec<SignCall>>>,
        /// What each login answers, in order; then it succeeds.
        logins: std::cell::RefCell<std::collections::VecDeque<LoginError>>,
        /// How many logins were made, shared with the test.
        attempts: Arc<Mutex<usize>>,
        /// The token's flags after as many logins as the index; none after
        /// the last.
        warnings: Vec<Option<PinWarning>>,
    }

    impl FakeToken {
        fn new(public: Vec<&'static [u8]>, private: Vec<&'static [u8]>) -> Self {
            Self {
                public,
                private,
                logged_in: Cell::new(false),
                signed: Arc::default(),
                sign_calls: Arc::default(),
                logins: Default::default(),
                attempts: Arc::default(),
                warnings: Vec::new(),
            }
        }
    }

    impl TokenBackend for FakeToken {
        fn pin_pad(&self) -> bool {
            false
        }
        fn pin_warning(&self) -> Option<PinWarning> {
            let attempts = *self.attempts.lock().unwrap();
            self.warnings.get(attempts).copied().flatten()
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
        fn login(&self, _: Zeroizing<String>) -> Result<(), LoginError> {
            *self.attempts.lock().unwrap() += 1;
            if let Some(error) = self.logins.borrow_mut().pop_front() {
                return Err(error);
            }
            self.logged_in.set(true);
            Ok(())
        }
        fn sign(
            &self,
            _: &[u8],
            data: &[Vec<u8>],
            digest: DigestAlgorithm,
            scheme: SignatureAlgorithm,
            _: Option<isize>,
        ) -> Result<Vec<Vec<u8>>, TokenError> {
            self.signed.lock().unwrap().push(data.len());
            self.sign_calls
                .lock()
                .unwrap()
                .push((data.to_vec(), digest, scheme));
            Ok(data.iter().map(|_| vec![1]).collect())
        }
        fn close(&self) {}
    }

    /// A driver whose tokens are `tokens`, by slot.
    #[derive(Default)]
    struct FakeDriver {
        tokens: Vec<Option<FakeToken>>,
        /// The slots whose certificates were read, shared with the test.
        shown: Arc<Mutex<Vec<u64>>>,
    }

    impl Driver for FakeDriver {
        fn shown(&self, slot: u64) -> Vec<TokenCertificate> {
            self.shown.lock().unwrap().push(slot);
            self.tokens
                .get(slot as usize)
                .and_then(Option::as_ref)
                .and_then(|token| token.certificates(false).ok())
                .unwrap_or_default()
        }
        fn open(mut self: Box<Self>, slot: u64) -> Result<Box<dyn TokenBackend>, TokenError> {
            let token = self.tokens.get_mut(slot as usize).and_then(Option::take);
            Ok(Box::new(
                token.unwrap_or_else(|| FakeToken::new(vec![RSA], vec![])),
            ))
        }
    }

    /// A token in `slot` with the serial number `serial`, showing
    /// `certificates` before login.
    fn info(slot: u64, serial: &str, certificates: &[&[u8]]) -> TokenInfo {
        TokenInfo {
            slot,
            label: format!("Token {slot}"),
            manufacturer: "SoftHSM project".into(),
            model: "SoftHSM v2".into(),
            serial: serial.into(),
            certificates: certificates
                .iter()
                .map(|der| TokenCertificate {
                    der: der.to_vec(),
                    sha256: token::sha256_hex(der),
                    id: None,
                })
                .collect(),
        }
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
        /// The job's failure report takes [`SLOW_REPORT`] to answer.
        SlowReport,
        /// Its certificate is refused with 422, as a server refuses an
        /// enrol proof that doesn't verify.
        RefuseProof,
    }

    const SLOW_REPORT: Duration = Duration::from_secs(2);

    struct Served {
        origin: String,
        requests: Arc<Mutex<Vec<String>>>,
        /// How many signatures each round 2 carried.
        signatures: Arc<Mutex<Vec<usize>>>,
        /// The body of each `/certificate` request.
        certificates: Arc<Mutex<Vec<serde_json::Value>>>,
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
        let certificates = Arc::new(Mutex::new(Vec::new()));
        let posted = certificates.clone();
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
                    None if request.ends_with("/certificate")
                        && matches!(fault, Some((_, Fault::RefuseProof))) =>
                    {
                        let message = "The proof doesn't match the certificate.";
                        (422, json!({ "message": message }).to_string().into_bytes())
                    }
                    None if request.ends_with("/certificate") => {
                        posted
                            .lock()
                            .unwrap()
                            .push(serde_json::from_slice(&body).unwrap());
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
                    None if request.ends_with("/failure")
                        && matches!(fault, Some((_, Fault::SlowReport))) =>
                    {
                        std::thread::sleep(SLOW_REPORT);
                        (200, b"{}".to_vec())
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
            certificates,
        }
    }

    /// Each cancelled prompt or step ends the job quietly: no error shown
    /// and one failure report, or none before the job is claimed.
    #[test]
    fn cancelling_any_prompt_reports_one_failure_and_shows_nothing() {
        for (kind, in_store, public, private, cancel_at, reports) in [
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
                Stage::Progress(Step::Signing),
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
            let case = format!("{kind} {in_store} {public:?} {private:?} {cancel_at:?}");
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
            let open = |_: KeyUsage, before_store: BeforeStore| {
                let token = Box::new(FakeToken::new(public.clone(), private.clone()));
                if !in_store {
                    return Ok(Found::Backend(Backend::Pkcs11(token)));
                }
                before_store()?;
                Ok(Found::Backend(Backend::Store(token)))
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
            // A cancelled enrolment never reaches the server.
            if kind == "enrol" {
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
                &[Connecting, OpeningToken, Signing, CheckingCertificate][..],
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
            let open = |_: KeyUsage, _: BeforeStore| {
                Ok(Found::Backend(Backend::Pkcs11(Box::new(FakeToken::new(
                    public.clone(),
                    private.clone(),
                )))))
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
    /// that sees no token, then the certificate store, which the enrol hook
    /// precedes.
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
                Attempt::Module(_) => Ok(Reached::Tokens(
                    Box::new(FakeDriver::default()),
                    vec![info(0, "", &[])],
                )),
                Attempt::Store => Ok(Reached::Backend(Backend::Store(token()))),
            }
        };
        let run = |attempts: &[Attempt], allow_store: bool| {
            events.borrow_mut().clear();
            let result = open_first(
                attempts,
                &open,
                &mut || {
                    events.borrow_mut().push("before the store".into());
                    if allow_store {
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

        let (result, seen) = run(&[broken.clone(), empty.clone(), Attempt::Store], true);
        assert!(matches!(result, Ok(Found::Backend(Backend::Store(_)))));
        assert_eq!(
            seen,
            [
                "open /broken [known drivers]",
                "/broken [known drivers]: Couldn't load the token driver",
                "open /empty [known drivers]",
                &format!("/empty [known drivers]: {}", token::NO_TOKEN),
                "before the store",
                &format!("open {}", Attempt::Store),
                &format!("{}: ok", Attempt::Store),
            ]
        );

        let (result, seen) = run(&[empty.clone(), working, Attempt::Store], true);
        assert!(matches!(result, Ok(Found::Tokens(_))));
        let store = Attempt::Store.to_string();
        assert!(
            !seen
                .iter()
                .any(|event| event.contains(&store) || event == "before the store"),
            "{seen:?}"
        );

        // The user declines before the store is read.
        let (result, seen) = run(&[empty.clone(), Attempt::Store], false);
        assert!(result.is_err_and(|failure| failure.cancelled));
        assert_eq!(seen.last().map(String::as_str), Some("before the store"));

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
        let open = |_: KeyUsage, _: BeforeStore| {
            Ok(Found::Backend(Backend::Pkcs11(Box::new(FakeToken::new(
                vec![RSA, P256],
                vec![],
            )))))
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

    /// The backend is opened for the job's key usage, so the certificate
    /// store on Windows is skipped when it holds none the job accepts.
    #[test]
    fn opens_the_backend_for_the_job_key_usage() {
        for (policy, expected) in [
            (
                json!({ "keyUsage": "digitalSignature" }),
                KeyUsage::DigitalSignature,
            ),
            (
                json!({ "issuerCommonNames": ["Test CA"] }),
                KeyUsage::NonRepudiation,
            ),
        ] {
            let (origin, _requests) = serve("sign", policy);
            let config_dir = std::env::temp_dir()
                .join(format!("keyseal-usage-{}-{expected:?}", std::process::id()));
            let env = Environment {
                allow_insecure: true,
                config_dir: config_dir.clone(),
            };
            let link: String = url::form_urlencoded::byte_serialize(
                format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
            )
            .collect();
            let asked = Cell::new(None);
            let open = |usage: KeyUsage, _: BeforeStore| {
                asked.set(Some(usage));
                Err(Failure::from(token::NO_TOKEN.to_owned()))
            };
            let mut ui = CancellingUi::new(Stage::Choose);
            let _ = run_with(&format!("keyseal://sign?job={link}"), &mut ui, &env, &open);
            let _ = std::fs::remove_dir_all(&config_dir);
            assert_eq!(asked.get(), Some(expected));
        }
    }

    /// A certificate whose key usage has digitalSignature without
    /// nonRepudiation is offered only to a job whose policy asks for
    /// digitalSignature.
    #[test]
    fn filters_certificates_by_the_job_key_usage() {
        const DIGITAL_SIGNATURE: &[u8] = include_bytes!("../tests/fixtures/digital-signature.der");
        let token = FakeToken::new(vec![RSA, DIGITAL_SIGNATURE], vec![]);
        let offered = |policy: serde_json::Value| {
            let job = serde_json::from_value::<JobDescription>(json!({
                "kind": "enrol",
                "title": "Enrolment",
                "signer": "Asha Rao",
                "claimNonce": NONCE,
                "certificatePolicy": policy,
            }))
            .unwrap();
            signing_certificates(&token, &job, false)
                .unwrap()
                .into_iter()
                .map(|certificate| certificate.der)
                .collect::<Vec<_>>()
        };
        assert_eq!(offered(json!(null)), [RSA]);
        assert_eq!(offered(json!({ "keyUsage": "nonRepudiation" })), [RSA]);
        assert_eq!(
            offered(json!({ "keyUsage": "digitalSignature" })),
            [RSA, DIGITAL_SIGNATURE]
        );
    }

    /// Runs an enrol link against `served` with `token`, from a PKCS#11
    /// token or the certificate store.
    fn run_enrol(served: &Served, token: FakeToken, in_store: bool) -> Result<Outcome, Failure> {
        let config_dir = std::env::temp_dir().join(format!("keyseal-enrol-{}", std::process::id()));
        let env = Environment {
            allow_insecure: true,
            config_dir: config_dir.clone(),
        };
        let link: String = url::form_urlencoded::byte_serialize(
            format!("{}/api/keyseal/v1/jobs/{TOKEN}", served.origin).as_bytes(),
        )
        .collect();
        let token = std::cell::RefCell::new(Some(Box::new(token)));
        let open = |_: KeyUsage, before_store: BeforeStore| {
            let token = token.borrow_mut().take().expect("one token per job");
            if !in_store {
                return Ok(Backend::Pkcs11(token));
            }
            before_store()?;
            Ok(Backend::Store(token))
        };
        // Enrol never reaches this step, so nothing is cancelled.
        let mut ui = CancellingUi::new(Stage::Progress(Step::Sending));
        let result = run_with(&format!("keyseal://enrol?job={link}"), &mut ui, &env, &open);
        let _ = std::fs::remove_dir_all(&config_dir);
        result
    }

    /// Enrol signs one proof, the helper's own message binding the job URL,
    /// the claim nonce and the certificate, with the scheme the key type
    /// fixes, and posts it with the certificate.
    #[test]
    fn enrols_with_a_proof_of_the_key() {
        for (certificate, digest, scheme) in [
            (
                RSA,
                DigestAlgorithm::Sha256,
                SignatureAlgorithm::RsaPkcs1v15,
            ),
            (P256, DigestAlgorithm::Sha256, SignatureAlgorithm::Ecdsa),
        ] {
            for in_store in [false, true] {
                let served = serve_documents("enrol", serde_json::Value::Null, 1, None);
                let token = if in_store {
                    FakeToken::new(vec![certificate], vec![])
                } else {
                    FakeToken::new(vec![], vec![certificate])
                };
                let calls = token.sign_calls.clone();
                let result = run_enrol(&served, token, in_store);
                assert_eq!(result.unwrap(), Outcome::Enrolled, "{in_store}");
                let message = format!(
                    "KeySeal enrol proof v1\0{}/api/keyseal/v1/jobs/{TOKEN}\0{NONCE}\0{}",
                    served.origin,
                    token::sha256_hex(certificate)
                );
                assert_eq!(
                    *calls.lock().unwrap(),
                    [(vec![message.into_bytes()], digest, scheme)],
                    "{in_store}"
                );
                let posted = served.certificates.lock().unwrap();
                assert_eq!(posted.len(), 1);
                assert_eq!(posted[0]["certificate"], STANDARD.encode(certificate));
                assert_eq!(posted[0]["proof"], STANDARD.encode([1]));
            }
        }
    }

    /// A proof the server refuses fails the job with the server's message.
    #[test]
    fn a_refused_proof_fails_the_enrolment() {
        let served = serve_documents(
            "enrol",
            serde_json::Value::Null,
            1,
            Some((0, Fault::RefuseProof)),
        );
        let failure = run_enrol(&served, FakeToken::new(vec![], vec![RSA]), false).unwrap_err();
        assert!(!failure.cancelled);
        assert!(
            failure
                .message
                .contains("The proof doesn't match the certificate."),
            "{}",
            failure.message
        );
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
        run_token(
            origin,
            FakeToken::new(public, private),
            CancellingUi::new(Stage::Enrol),
            name,
        )
    }

    /// Runs a sign link against `origin` with `token` and `ui`, as
    /// [`run_sign`] does.
    fn run_token(
        origin: &str,
        token: FakeToken,
        mut ui: CancellingUi,
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
        let signed = token.signed.clone();
        let token = std::cell::RefCell::new(Some(token));
        let open = |_: KeyUsage, _: BeforeStore| {
            Ok(Found::Backend(Backend::Pkcs11(Box::new(
                token.borrow_mut().take().expect("one token per job"),
            ))))
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

    fn failures(served: &Served) -> usize {
        let requests = served.requests.lock().unwrap();
        requests.iter().filter(|r| r.ends_with("/failure")).count()
    }

    /// A token that answers its logins with `refusals`, then accepts the
    /// PIN; its flags after each login are `warnings`.
    fn refusing_token(
        public: Vec<&'static [u8]>,
        private: Vec<&'static [u8]>,
        refusals: impl IntoIterator<Item = LoginError>,
        warnings: Vec<Option<PinWarning>>,
    ) -> (FakeToken, Arc<Mutex<usize>>) {
        let mut token = FakeToken::new(public, private);
        token.logins.borrow_mut().extend(refusals);
        token.warnings = warnings;
        let attempts = token.attempts.clone();
        (token, attempts)
    }

    /// A wrong PIN asks again in the same session, with the token's flags
    /// read afresh: the right one then signs every document once, and
    /// nothing is reported as failed.
    #[test]
    fn asks_again_after_a_wrong_pin() {
        for (public, private) in [(vec![RSA], vec![]), (vec![], vec![RSA])] {
            let served = serve_documents("sign", serde_json::Value::Null, 3, None);
            let (token, attempts) = refusing_token(
                public,
                private,
                [LoginError::WrongPin, LoginError::WrongPin],
                vec![None, Some(PinWarning::CountLow), Some(PinWarning::FinalTry)],
            );
            let (result, ui, signed) = run_token(
                &served.origin,
                token,
                CancellingUi::new(Stage::Enrol),
                "wrong-pin",
            );
            assert_eq!(result.unwrap(), Outcome::Signed);
            assert_eq!(
                ui.pin_states,
                [
                    (None, false),
                    (Some(PinWarning::CountLow), true),
                    (Some(PinWarning::FinalTry), true),
                ]
            );
            // The digests stay on every prompt of the one-view path.
            assert!(ui.pins.windows(2).all(|pins| pins[0] == pins[1]));
            assert_eq!(*attempts.lock().unwrap(), 3);
            assert_eq!(signed, [3]);
            assert_eq!(*served.signatures.lock().unwrap(), [3]);
            assert!(ui.errors.is_empty(), "{:?}", ui.errors);
            assert_eq!(failures(&served), 0);
        }
    }

    /// A PIN the flags say is locked, before the first prompt or after a
    /// wrong PIN, or one the login says is locked, fails the job with the
    /// locked error, never asks again and is reported once.
    #[test]
    fn a_locked_pin_fails_the_job() {
        for (refusals, warnings, prompts) in [
            (vec![], vec![Some(PinWarning::Locked)], 0),
            (vec![LoginError::Locked], vec![], 1),
            (
                vec![LoginError::WrongPin],
                vec![Some(PinWarning::FinalTry), Some(PinWarning::Locked)],
                1,
            ),
        ] {
            let served = serve_documents("sign", serde_json::Value::Null, 1, None);
            let (token, attempts) = refusing_token(vec![RSA], vec![], refusals, warnings);
            let (result, ui, signed) = run_token(
                &served.origin,
                token,
                CancellingUi::new(Stage::Enrol),
                "locked-pin",
            );
            let failure = result.unwrap_err();
            assert!(!failure.cancelled);
            assert_eq!(failure.message, token::PIN_LOCKED);
            assert_eq!(ui.pins.len(), prompts);
            assert_eq!(*attempts.lock().unwrap(), prompts);
            assert!(signed.is_empty());
            assert_eq!(ui.errors, [token::PIN_LOCKED]);
            assert_eq!(failures(&served), 1);
        }
    }

    /// Cancelling the prompt after a wrong PIN reports one cancellation.
    #[test]
    fn cancelling_after_a_wrong_pin_reports_one_failure() {
        let served = serve_documents("sign", serde_json::Value::Null, 1, None);
        let (token, attempts) = refusing_token(vec![RSA], vec![], [LoginError::WrongPin], vec![]);
        let mut ui = CancellingUi::new(Stage::Pin);
        ui.pins_to_answer = 1;
        let (result, ui, signed) = run_token(&served.origin, token, ui, "cancel-retry");
        let failure = result.unwrap_err();
        assert!(failure.cancelled, "{}", failure.message);
        assert_eq!(failure.message, CANCELLED);
        assert_eq!(ui.pins.len(), 2);
        assert_eq!(*attempts.lock().unwrap(), 1);
        assert!(ui.errors.is_empty(), "{:?}", ui.errors);
        assert!(signed.is_empty());
        assert_eq!(failures(&served), 1);
    }

    /// Headless runs try their one PIN once: a wrong PIN fails the job.
    #[test]
    fn a_wrong_pin_is_not_retried_headless() {
        let served = serve_documents("sign", serde_json::Value::Null, 1, None);
        let (token, attempts) = refusing_token(vec![RSA], vec![], [LoginError::WrongPin], vec![]);
        let mut ui = CancellingUi::new(Stage::Enrol);
        ui.retries_pin = false;
        let (result, ui, signed) = run_token(&served.origin, token, ui, "headless-pin");
        let failure = result.unwrap_err();
        assert!(!failure.cancelled);
        assert_eq!(failure.message, token::WRONG_PIN);
        assert_eq!(ui.pins.len(), 1);
        assert_eq!(*attempts.lock().unwrap(), 1);
        assert!(signed.is_empty());
        assert_eq!(failures(&served), 1);
    }

    /// The error shows without waiting for the failure report, and the run
    /// ends only once the report has been answered.
    #[test]
    fn shows_the_error_before_the_report_is_answered() {
        let served = serve_documents(
            "sign",
            serde_json::Value::Null,
            1,
            Some((0, Fault::SlowReport)),
        );
        let start = std::time::Instant::now();
        let (result, ui, _) = run_token(
            &served.origin,
            FakeToken::new(vec![], vec![]),
            CancellingUi::new(Stage::Enrol),
            "slow-report",
        );
        assert!(!result.unwrap_err().cancelled);
        assert_eq!(ui.errors.len(), 1);
        assert!(ui.error_shown.unwrap() - start < SLOW_REPORT);
        assert!(start.elapsed() >= SLOW_REPORT);
        assert_eq!(failures(&served), 1);
    }

    /// A panic after the claim fails the job like any error: shown, and
    /// reported once.
    #[test]
    fn a_panic_in_the_job_is_shown_and_reported() {
        let served = serve_documents("sign", serde_json::Value::Null, 1, None);
        let config_dir = std::env::temp_dir().join(format!("keyseal-panic-{}", std::process::id()));
        let env = Environment {
            allow_insecure: true,
            config_dir: config_dir.clone(),
        };
        let link: String = url::form_urlencoded::byte_serialize(
            format!("{}/api/keyseal/v1/jobs/{TOKEN}", served.origin).as_bytes(),
        )
        .collect();
        let mut ui = CancellingUi::new(Stage::Enrol);
        let open = |_: KeyUsage, _: BeforeStore| -> Result<Found, Failure> { panic!("broken") };
        let result = run_with(&format!("keyseal://sign?job={link}"), &mut ui, &env, &open);
        let _ = std::fs::remove_dir_all(&config_dir);
        assert_eq!(result.unwrap_err().message, INTERNAL_ERROR);
        assert_eq!(ui.errors, [INTERNAL_ERROR]);
        assert_eq!(failures(&served), 1);
    }

    /// An expired certificate is never offered. Beside a valid one it is
    /// left out; alone it fails the job with its expiry date, before any
    /// PIN when the token shows it before login, and after the one PIN of
    /// the login-first path otherwise.
    #[test]
    fn expired_certificates_are_not_offered() {
        let served = serve_documents("sign", serde_json::Value::Null, 1, None);
        let (result, ui, signed) = run_sign(&served.origin, vec![EXPIRED, RSA], vec![], "mixed");
        assert_eq!(result.unwrap(), Outcome::Signed);
        assert_eq!(signed, [1]);
        assert!(ui.errors.is_empty(), "{:?}", ui.errors);

        let expired = token::outside_validity(EXPIRED, i64::MAX).unwrap();
        for (public, private, prompts) in [(vec![EXPIRED], vec![], 0), (vec![], vec![EXPIRED], 1)] {
            let served = serve_documents("sign", serde_json::Value::Null, 1, None);
            let (result, ui, signed) = run_sign(&served.origin, public, private, "expired");
            let failure = result.unwrap_err();
            assert!(!failure.cancelled);
            assert_eq!(failure.message, expired);
            assert!(failure.message.contains("expired on 1 January 2021"));
            assert_eq!(ui.pins.len(), prompts);
            assert_eq!(ui.errors, std::slice::from_ref(&expired));
            assert!(signed.is_empty());
            assert_eq!(failures(&served), 1);
        }
    }

    /// The drivers of plugged-in tokens are all listed; any other driver
    /// that reaches a token ends the search, with every token of it, and
    /// the configured module comes first. A token two drivers reach is
    /// listed once, through the earlier one.
    #[test]
    fn collects_tokens_from_plugged_in_drivers_and_the_first_other() {
        let module = |name: &str, source| {
            Attempt::Module(modules::Candidate {
                path: name.into(),
                source,
            })
        };
        let opened = std::cell::RefCell::new(Vec::new());
        let open = |attempt: &Attempt, _: Duration| {
            opened.borrow_mut().push(attempt.to_string());
            let serials: &[&str] = match attempt {
                Attempt::Module(candidate) => match candidate.path.to_str().unwrap() {
                    "/configured" => &["A"],
                    "/plugged-in" => &["A", "B"],
                    "/other-plugged-in" => &[" A ", "", ""],
                    "/two" => &["C", "D"],
                    "/three" => &["E"],
                    _ => &[],
                },
                Attempt::Store => &["store"],
            };
            if serials.is_empty() {
                return Err(token::NO_TOKEN.to_owned());
            }
            let tokens = (0..serials.len())
                .map(|slot| info(slot as u64, serials[slot], &[]))
                .collect();
            Ok(Reached::Tokens(Box::new(FakeDriver::default()), tokens))
        };
        let found = |attempts: &[Attempt]| {
            opened.borrow_mut().clear();
            match open_first(attempts, &open, &mut || Ok(()), &mut |_, _| {}) {
                Ok(Found::Tokens(found)) => {
                    let serials: Vec<String> =
                        found.tokens.iter().map(|t| t.serial.clone()).collect();
                    (serials, found.driver_of, opened.borrow().len())
                }
                _ => panic!("no tokens"),
            }
        };
        let plugged_in = |name: &str| module(name, modules::Source::UsbMatch("Token".into()));
        let known = |name: &str| module(name, modules::Source::Known);

        let (serials, drivers, tried) = found(&[
            module("/configured", modules::Source::Config),
            plugged_in("/plugged-in"),
            known("/two"),
            Attempt::Store,
        ]);
        assert_eq!(serials, ["A"]);
        assert_eq!(drivers, [0]);
        assert_eq!(tried, 1);

        let (serials, drivers, tried) = found(&[
            module("/empty", modules::Source::Config),
            plugged_in("/plugged-in"),
            plugged_in("/empty"),
            plugged_in("/other-plugged-in"),
            known("/two"),
            Attempt::Store,
        ]);
        assert_eq!(serials, ["A", "B", "", ""]);
        assert_eq!(drivers, [0, 0, 1, 1]);
        assert_eq!(tried, 4);

        let (serials, drivers, tried) = found(&[
            known("/empty"),
            known("/two"),
            known("/three"),
            Attempt::Store,
        ]);
        assert_eq!(serials, ["C", "D"]);
        assert_eq!(drivers, [0, 0]);
        assert_eq!(tried, 2);
    }

    /// Among several tokens, the only one showing the expected certificate
    /// is used without asking; otherwise the signer chooses, and a run that
    /// can't ask fails with a plain message.
    #[test]
    fn chooses_a_token_by_the_expected_certificate_or_asks() {
        let origin =
            Origin::of_url(&url::Url::parse("https://dash.example.org").unwrap(), false).unwrap();
        let view = JobView {
            origin: &origin,
            branding: None,
            kind: Kind::Sign,
            title: "Lease",
            signer: "Asha Rao",
            documents: &[],
        };
        let job = |expected: Option<&[u8]>| {
            serde_json::from_value::<JobDescription>(json!({
                "kind": "enrol",
                "title": "Enrolment",
                "signer": "Asha Rao",
                "claimNonce": NONCE,
                "expectedCertificateSha256": expected.map(token::sha256_hex),
            }))
            .unwrap()
        };
        let tokens = [
            info(0, "A", &[RSA]),
            info(1, "B", &[P256, RSA]),
            info(2, "C", &[]),
        ];
        let choose = |expected: Option<&[u8]>, ui: &mut CancellingUi| {
            choose_token(ui, &view, &job(expected), &tokens, CANCELLED)
        };

        let mut ui = CancellingUi::new(Stage::Enrol);
        assert_eq!(choose(Some(P256), &mut ui).unwrap(), 1);
        assert!(ui.token_choices.is_empty());

        ui.token_answer = 2;
        for expected in [Some(RSA), Some(EXPIRED), None] {
            assert_eq!(choose(expected, &mut ui).unwrap(), 2);
        }
        assert_eq!(ui.token_choices.len(), 3);
        let listed = &ui.token_choices[0];
        assert_eq!(listed[0].label, "Token 0");
        assert_eq!(listed[0].model, "SoftHSM project SoftHSM v2");
        assert_eq!(listed[0].serial, "A");
        assert_eq!(
            listed[1].names,
            [
                "signr test non-repudiation",
                "signr test RSA non-repudiation"
            ]
        );
        assert!(listed[2].names.is_empty());

        let mut ui = CancellingUi::new(Stage::Token);
        let failure = choose(None, &mut ui).unwrap_err();
        assert!(failure.cancelled);

        let mut headless = CancellingUi::new(Stage::Enrol);
        headless.retries_pin = false;
        let failure = choose(None, &mut headless).unwrap_err();
        assert!(!failure.cancelled);
        assert_eq!(failure.message, SEVERAL_TOKENS);
        assert_eq!(choose(Some(P256), &mut headless).unwrap(), 1);
    }

    /// A sign job with two tokens asks which to use before the PIN, signs
    /// with the chosen one, and names it in the PIN prompt; with one token
    /// nothing is asked.
    #[test]
    fn signs_with_the_token_the_signer_chooses() {
        for (count, answer) in [(2, 1), (1, 0)] {
            let served = serve_documents("sign", serde_json::Value::Null, 1, None);
            let tokens: Vec<FakeToken> = (0..count)
                .map(|_| FakeToken::new(vec![RSA], vec![]))
                .collect();
            let signed: Vec<_> = tokens.iter().map(|token| token.signed.clone()).collect();
            let shown = Arc::<Mutex<Vec<u64>>>::default();
            let driver = std::cell::RefCell::new(Some(FakeDriver {
                tokens: tokens.into_iter().map(Some).collect(),
                shown: shown.clone(),
            }));
            let open = |_: KeyUsage, _: BeforeStore| {
                Ok(Found::Tokens(Tokens {
                    drivers: vec![Box::new(driver.borrow_mut().take().unwrap())],
                    tokens: (0..count).map(|slot| info(slot, "", &[RSA])).collect(),
                    driver_of: vec![0; count as usize],
                }))
            };
            let config_dir =
                std::env::temp_dir().join(format!("keyseal-tokens-{}", std::process::id()));
            let env = Environment {
                allow_insecure: true,
                config_dir: config_dir.clone(),
            };
            let link: String = url::form_urlencoded::byte_serialize(
                format!("{}/api/keyseal/v1/jobs/{TOKEN}", served.origin).as_bytes(),
            )
            .collect();
            let mut ui = CancellingUi::new(Stage::Enrol);
            ui.token_answer = answer;
            let result = run_with(&format!("keyseal://sign?job={link}"), &mut ui, &env, &open);
            let _ = std::fs::remove_dir_all(&config_dir);
            assert_eq!(result.unwrap(), Outcome::Signed);
            let signed: Vec<Vec<usize>> = signed
                .iter()
                .map(|signed| signed.lock().unwrap().clone())
                .collect();
            if count == 2 {
                assert_eq!(ui.token_choices.len(), 1);
                assert_eq!(signed, [vec![], vec![1]]);
                assert_eq!(ui.pin_tokens, [Some("Token 1".to_owned())]);
                assert_eq!(*shown.lock().unwrap(), [0, 1]);
            } else {
                assert!(ui.token_choices.is_empty());
                assert_eq!(signed, [vec![1]]);
                assert_eq!(ui.pin_tokens, [None]);
                // One token is opened without being read first.
                assert!(shown.lock().unwrap().is_empty());
            }
        }
    }
}

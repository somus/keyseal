//! The user's token or smart card through PKCS#11, and the
//! [`TokenBackend`] seam the flow signs through. The PIN is kept, zeroised
//! when dropped, from login until the job's signatures are made, for keys
//! that need it for each signature; nothing from the token is written to
//! disk.

use std::cell::RefCell;
use std::path::Path;
use std::time::{Duration, Instant};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Function, Pkcs11};
use cryptoki::error::{Rv, RvError};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use cryptoki_sys::{CK_C_Sign, CK_ULONG, CKR_OK};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cms::{self, DigestAlgorithm, KeyKind, SignatureAlgorithm};
use crate::protocol::KeyUsage;
use crate::worker::{self, Backend, WorkerToken};

#[derive(Debug)]
pub struct TokenError(pub String);

/// The error when no token is plugged in, also as relayed by the worker.
pub const NO_TOKEN: &str = "No token or smart card is plugged in.";

/// The error when the token's PIN is locked.
pub const PIN_LOCKED: &str = "Your token's PIN is locked after too many wrong tries, so KeySeal can't use it. To unlock it, use the software that came with your token, or ask whoever issued the token.";

/// The error when the token refused the PIN and it isn't asked again.
pub const WRONG_PIN: &str = "The PIN is wrong, so the token refused it.";

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TokenError {}

impl From<String> for TokenError {
    fn from(message: String) -> Self {
        Self(message)
    }
}

/// Why a login failed.
#[derive(Debug)]
pub enum LoginError {
    /// CKR_PIN_INCORRECT, or CKR_PIN_INVALID or CKR_PIN_LEN_RANGE, a PIN the
    /// token can't take: the signer may try again.
    WrongPin,
    /// CKR_PIN_LOCKED: the token takes no PIN until it is unlocked.
    Locked,
    Other(TokenError),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPin => f.write_str(WRONG_PIN),
            Self::Locked => f.write_str(PIN_LOCKED),
            Self::Other(error) => error.fmt(f),
        }
    }
}

impl From<TokenError> for LoginError {
    fn from(error: TokenError) -> Self {
        Self::Other(error)
    }
}

pub(crate) fn err(context: &str, error: impl std::fmt::Display) -> TokenError {
    TokenError(format!("{context}: {error}"))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Whether a certificate can be offered for signing: a supported key
/// (section 11), not a CA, and a KeyUsage extension asserting what `usage`
/// asks for, as the server's certificate check requires.
pub fn is_signing_certificate(der: &[u8], usage: KeyUsage) -> bool {
    if KeyKind::of_certificate(der).is_err() {
        return false;
    }
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    let ca = matches!(certificate.basic_constraints(), Ok(Some(ext)) if ext.value.ca);
    let asserted = match certificate.key_usage() {
        Ok(Some(ext)) => match usage {
            KeyUsage::NonRepudiation => ext.value.non_repudiation(),
            KeyUsage::DigitalSignature => {
                ext.value.digital_signature() || ext.value.non_repudiation()
            }
        },
        _ => false,
    };
    !ca && asserted
}

/// Why a certificate can't sign at the Unix time `now`: it has expired or
/// isn't valid yet. `None` within its validity period, as the server's
/// certificate check requires.
pub fn outside_validity(der: &[u8], now: i64) -> Option<String> {
    let (_, certificate) = x509_parser::parse_x509_certificate(der).ok()?;
    let validity = certificate.validity();
    let date = |time: &x509_parser::time::ASN1Time| {
        let time = time.to_datetime();
        format!("{} {} {}", time.day(), time.month(), time.year())
    };
    if now > validity.not_after.timestamp() {
        Some(format!(
            "The certificate on your token expired on {}. Renew it with the company that issued it, then try again.",
            date(&validity.not_after)
        ))
    } else if now < validity.not_before.timestamp() {
        Some(format!(
            "The certificate on your token isn't valid until {}. Try again from that date.",
            date(&validity.not_before)
        ))
    } else {
        None
    }
}

/// The certificates among `others` that form the issuer chain of `der`,
/// its issuer first: each one's subject is the issuer name of the one
/// before and, when both carry key identifiers, its subject key identifier
/// is that one's authority key identifier. The chain ends at a self-issued
/// certificate or where no issuer is among `others`, so the rest of a
/// shared token's certificates are left out.
pub fn issuers(der: &[u8], mut others: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    use x509_parser::certificate::X509Certificate;
    use x509_parser::extensions::ParsedExtension;

    fn key_ids<'a>(certificate: &'a X509Certificate) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
        let (mut authority, mut subject) = (None, None);
        for extension in certificate.iter_extensions() {
            match extension.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    authority = aki.key_identifier.as_ref().map(|id| id.0);
                }
                ParsedExtension::SubjectKeyIdentifier(ski) => subject = Some(ski.0),
                _ => {}
            }
        }
        (authority, subject)
    }

    let mut chain = Vec::new();
    let mut current = der.to_vec();
    while let Ok((_, certificate)) = x509_parser::parse_x509_certificate(&current) {
        let issuer = certificate.issuer().as_raw();
        if certificate.subject().as_raw() == issuer {
            break;
        }
        let (authority, _) = key_ids(&certificate);
        let found = others.iter().position(|other| {
            x509_parser::parse_x509_certificate(other).is_ok_and(|(_, candidate)| {
                let (_, subject_key) = key_ids(&candidate);
                candidate.subject().as_raw() == issuer
                    && match (authority, subject_key) {
                        (Some(authority), Some(subject_key)) => authority == subject_key,
                        _ => true,
                    }
            })
        });
        let Some(index) = found else {
            break;
        };
        current = others.swap_remove(index);
        chain.push(current.clone());
    }
    chain
}

/// The certificate's subject, for display (section 12.1).
pub fn subject(der: &[u8]) -> String {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, certificate)| certificate.subject().to_string())
        .unwrap_or_else(|_| "unreadable certificate".into())
}

/// What the sign and enrol flow needs from where the job's key lives: a
/// PKCS#11 token, whose driver runs in this process or in the token worker,
/// or the system's certificate store (CNG on Windows, CryptoTokenKit on
/// macOS).
pub trait TokenBackend {
    /// The token has a PIN pad (protected authentication path).
    fn pin_pad(&self) -> bool;
    /// What the driver says about remaining PIN attempts, read when asked.
    fn pin_warning(&self) -> Option<PinWarning>;
    /// Every certificate the session can see: before login only public
    /// objects, after login private ones too. With `with_private_key`, only
    /// those with a private key beside them, which login makes visible.
    fn certificates(&self, with_private_key: bool) -> Result<Vec<TokenCertificate>, TokenError>;
    /// Logs in with `pin`, or through the PIN pad when the token has one.
    /// A PKCS#11 token keeps the PIN, zeroised when dropped, until
    /// [`sign`](Self::sign) or [`close`](Self::close), for a key that needs
    /// it again for each signature (CKA_ALWAYS_AUTHENTICATE).
    fn login(&self, pin: Zeroizing<String>) -> Result<(), LoginError>;
    /// The signature value over each item of `data`, in order, with the
    /// private key of `certificate` (DER), encoded as section 11.1 says. The
    /// key is found once and every item is signed in the same session (in
    /// the certificate store, through one key handle), so one login covers a job's documents.
    /// A PKCS#11 key with CKA_ALWAYS_AUTHENTICATE gets the kept PIN, or on a
    /// PIN pad the pad's prompt, before each signature; the PIN is dropped
    /// after the call.
    /// `window` is the `HWND` a CNG provider's PIN dialog belongs to; PKCS#11
    /// ignores it.
    fn sign(
        &self,
        certificate: &[u8],
        data: &[Vec<u8>],
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
        window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError>;
    /// Ends the session; for PKCS#11, logs out and drops the kept PIN.
    fn close(&self);
}

/// How long [`Module::open`] waits for a token to appear, for a driver of a
/// plugged-in token. The HyperSecu driver finds its token a second or two
/// after initialising, so an empty slot list right away doesn't mean no
/// token.
pub const SLOT_WAIT: Duration = Duration::from_secs(5);

/// Opens a session on the first token of the module at `path`, waiting up
/// to `wait` for one: in this process, or in the token worker for an
/// Intel-only macOS driver.
pub fn open(path: &Path, wait: Duration) -> Result<Box<dyn TokenBackend>, TokenError> {
    match worker::backend_for(path)? {
        Backend::InProcess => Ok(Box::new(Module::load(path)?.open(wait)?)),
        Backend::Worker => Ok(Box::new(WorkerToken::open(&worker::locate()?, path, wait)?)),
    }
}

/// A loaded and initialised PKCS#11 module.
pub struct Module {
    pkcs11: Pkcs11,
    /// The module's C_Sign, which [`Token::sign_raw`] calls itself.
    c_sign: CK_C_Sign,
}

impl Module {
    pub fn load(path: &Path) -> Result<Self, TokenError> {
        let pkcs11 = Pkcs11::new(path).map_err(|e| {
            err(
                &format!("Couldn't load the token driver at {}", path.display()),
                e,
            )
        })?;
        // Never finalised or unloaded: the HyperSecu driver hangs in dlclose.
        // So a later job in the same process finds the driver started, which
        // PKCS#11 reports as CKR_CRYPTOKI_ALREADY_INITIALIZED.
        match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(())
            | Err(cryptoki::error::Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
            Err(e) => return Err(err("Couldn't start the token driver", e)),
        }
        std::mem::forget(pkcs11.clone());
        Ok(Self {
            pkcs11,
            c_sign: c_sign(path),
        })
    }

    /// Opens a session on the first initialised token, listing the slots
    /// again until `wait` is over ([`SLOT_WAIT`]).
    pub fn open(&self, wait: Duration) -> Result<Token, TokenError> {
        let deadline = Instant::now() + wait;
        let slot = loop {
            let slots = self
                .pkcs11
                .get_slots_with_initialized_token()
                .map_err(|e| err("Couldn't list tokens", e))?;
            if let Some(slot) = slots.into_iter().next() {
                break slot;
            }
            if Instant::now() >= deadline {
                return Err(TokenError(NO_TOKEN.into()));
            }
            std::thread::sleep(Duration::from_millis(250));
        };
        let info = self
            .pkcs11
            .get_token_info(slot)
            .map_err(|e| err("Couldn't read the token", e))?;
        let session = self
            .pkcs11
            .open_ro_session(slot)
            .map_err(|e| err("Couldn't open the token", e))?;
        // Read once per session; a driver that can't list them is taken to
        // have every mechanism.
        let mechanisms = self.pkcs11.get_mechanism_list(slot).unwrap_or_default();
        Ok(Token {
            session,
            pkcs11: self.pkcs11.clone(),
            slot,
            pin_pad: info.protected_authentication_path(),
            mechanisms,
            c_sign: self.c_sign,
            pin: RefCell::new(None),
        })
    }
}

/// The C_Sign of the module at `path`, from its function list. cryptoki's
/// `Session::sign` makes C_SignInit and C_Sign in one call, and a
/// context-specific login has to come between them. The library is loaded
/// again, which finds the one already loaded, and never unloaded, as in
/// [`Module::load`].
fn c_sign(path: &Path) -> CK_C_Sign {
    // SAFETY: the same library cryptoki loaded and initialised; only its
    // function list is read.
    unsafe {
        let library = cryptoki_sys::Pkcs11::new(path).ok()?;
        let mut list = std::mem::MaybeUninit::uninit();
        let rv = library.C_GetFunctionList(list.as_mut_ptr());
        std::mem::forget(library);
        if rv != CKR_OK {
            return None;
        }
        // The module's static function list, alive while the library stays
        // loaded, which is for the rest of the process.
        let list = std::ptr::NonNull::new(list.assume_init())?;
        list.as_ref().C_Sign
    }
}

/// Whether an RSA PKCS#1 v1.5 signature with `digest` is made over a
/// DigestInfo hashed on the host with CKM_RSA_PKCS: when the slot's
/// `mechanisms` lack the combined hash-and-sign mechanism but have
/// CKM_RSA_PKCS. The signature is the same either way.
fn pkcs1_on_host(mechanisms: &[MechanismType], digest: DigestAlgorithm) -> bool {
    let combined = match digest {
        DigestAlgorithm::Sha256 => MechanismType::SHA256_RSA_PKCS,
        DigestAlgorithm::Sha384 => MechanismType::SHA384_RSA_PKCS,
    };
    !mechanisms.contains(&combined) && mechanisms.contains(&MechanismType::RSA_PKCS)
}

/// The mechanism and input of an RSA PKCS#1 v1.5 signature over `data`.
fn pkcs1(on_host: bool, data: &[u8], digest: DigestAlgorithm) -> (Mechanism<'static>, Vec<u8>) {
    if on_host {
        return (Mechanism::RsaPkcs, digest.digest_info(data));
    }
    let mechanism = match digest {
        DigestAlgorithm::Sha256 => Mechanism::Sha256RsaPkcs,
        DigestAlgorithm::Sha384 => Mechanism::Sha384RsaPkcs,
    };
    (mechanism, data.to_vec())
}

/// What the driver says about remaining PIN attempts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinWarning {
    Locked,
    FinalTry,
    CountLow,
}

impl PinWarning {
    pub fn message(self) -> &'static str {
        match self {
            Self::Locked => "The token's PIN is locked.",
            Self::FinalTry => "One PIN attempt is left before the token locks.",
            Self::CountLow => "A wrong PIN was entered recently; few attempts are left.",
        }
    }
}

/// A certificate the backend sees, with its PKCS#11 CKA_ID.
#[derive(Serialize, Deserialize)]
pub struct TokenCertificate {
    pub der: Vec<u8>,
    pub sha256: String,
    #[serde(skip)]
    pub(crate) id: Option<Vec<u8>>,
}

pub struct Token {
    session: Session,
    /// For the token's flags, which change with each login.
    pkcs11: Pkcs11,
    slot: Slot,
    /// The token has a PIN pad (protected authentication path).
    pub pin_pad: bool,
    /// The slot's mechanisms, read when the session opened.
    mechanisms: Vec<MechanismType>,
    c_sign: CK_C_Sign,
    /// The PIN from login until the job's signatures are made, for a key
    /// with CKA_ALWAYS_AUTHENTICATE. `AuthPin` zeroises it when dropped.
    pin: RefCell<Option<AuthPin>>,
}

impl Token {
    /// The private key beside `certificate` (same CKA_ID); visible only after login.
    fn private_key(
        &self,
        certificate: &TokenCertificate,
    ) -> Result<Option<ObjectHandle>, TokenError> {
        let Some(id) = &certificate.id else {
            return Ok(None);
        };
        let keys = self
            .session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Id(id.clone()),
            ])
            .map_err(|e| err("Couldn't find the key", e))?;
        Ok(keys.into_iter().next())
    }
}

impl TokenBackend for Token {
    fn pin_pad(&self) -> bool {
        self.pin_pad
    }

    fn pin_warning(&self) -> Option<PinWarning> {
        let info = self.pkcs11.get_token_info(self.slot).ok()?;
        if info.user_pin_locked() {
            Some(PinWarning::Locked)
        } else if info.user_pin_final_try() {
            Some(PinWarning::FinalTry)
        } else if info.user_pin_count_low() {
            Some(PinWarning::CountLow)
        } else {
            None
        }
    }

    fn certificates(&self, with_private_key: bool) -> Result<Vec<TokenCertificate>, TokenError> {
        let objects = self
            .session
            .find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])
            .map_err(|e| err("Couldn't read certificates", e))?;
        let mut found = Vec::new();
        for object in objects {
            let attributes = self
                .session
                .get_attributes(object, &[AttributeType::Value, AttributeType::Id])
                .map_err(|e| err("Couldn't read a certificate", e))?;
            let mut der = None;
            let mut id = None;
            for attribute in attributes {
                match attribute {
                    Attribute::Value(value) => der = Some(value),
                    Attribute::Id(value) => id = Some(value),
                    _ => {}
                }
            }
            let Some(der) = der else {
                continue;
            };
            let certificate = TokenCertificate {
                sha256: sha256_hex(&der),
                der,
                id,
            };
            if with_private_key && self.private_key(&certificate)?.is_none() {
                continue;
            }
            found.push(certificate);
        }
        Ok(found)
    }

    fn login(&self, pin: Zeroizing<String>) -> Result<(), LoginError> {
        use cryptoki::error::Error::Pkcs11;
        // Copied once into a buffer of exactly its length, which `AuthPin`
        // zeroises; `AuthPin::from(String)` would shrink the String and free
        // its old buffer without zeroising it.
        let pin = AuthPin::from(Box::<str>::from(pin.as_str()));
        self.session
            .login(UserType::User, (!self.pin_pad).then_some(&pin))
            .map_err(|e| match e {
                Pkcs11(RvError::PinIncorrect | RvError::PinInvalid | RvError::PinLenRange, _) => {
                    LoginError::WrongPin
                }
                Pkcs11(RvError::PinLocked, _) => LoginError::Locked,
                e => LoginError::Other(err("Couldn't log in to the token", e)),
            })?;
        if !self.pin_pad {
            *self.pin.borrow_mut() = Some(pin);
        }
        Ok(())
    }

    fn close(&self) {
        self.pin.take();
        let _ = self.session.logout();
    }

    fn sign(
        &self,
        certificate: &[u8],
        data: &[Vec<u8>],
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
        _window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError> {
        // Taken first, so the PIN is dropped when this call returns.
        let pin = self.pin.take();
        let kind = KeyKind::of_certificate(certificate)?;
        kind.check(digest, scheme)?;
        let sha256 = sha256_hex(certificate);
        let on_token = self
            .certificates(false)?
            .into_iter()
            .find(|c| c.sha256 == sha256)
            .ok_or_else(|| TokenError("This token doesn't hold the certificate.".into()))?;
        let key = self.private_key(&on_token)?.ok_or_else(|| {
            TokenError("The token holds no private key for the certificate.".into())
        })?;
        let mut key_type = None;
        let mut always_authenticate = false;
        for attribute in self
            .session
            .get_attributes(
                key,
                &[AttributeType::KeyType, AttributeType::AlwaysAuthenticate],
            )
            .map_err(|e| err("Couldn't read the key", e))?
        {
            match attribute {
                Attribute::KeyType(value) => key_type = Some(value),
                Attribute::AlwaysAuthenticate(value) => always_authenticate = value,
                _ => {}
            }
        }
        let key_type = key_type
            .ok_or_else(|| TokenError("The token didn't say what kind of key it holds.".into()))?;
        let reauthenticate = always_authenticate.then_some(pin.as_ref());
        data.iter()
            .map(|data| self.sign_one(key, kind, key_type, data, digest, scheme, reauthenticate))
            .collect()
    }
}

impl Token {
    /// One signature with `key`, whose type the token reported as `key_type`.
    /// `reauthenticate` is `Some` for a key with CKA_ALWAYS_AUTHENTICATE,
    /// holding the PIN kept from login, which is `None` on a PIN pad.
    #[expect(clippy::too_many_arguments, reason = "one signature's inputs")]
    fn sign_one(
        &self,
        key: ObjectHandle,
        kind: KeyKind,
        key_type: KeyType,
        data: &[u8],
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
        reauthenticate: Option<Option<&AuthPin>>,
    ) -> Result<Vec<u8>, TokenError> {
        let sign = |mechanism: &Mechanism, input: &[u8]| match reauthenticate {
            None => self
                .session
                .sign(mechanism, key, input)
                .map_err(|e| err("The token couldn't sign", e)),
            Some(pin) => self.sign_raw(mechanism, key, input, pin),
        };
        match (kind, key_type, scheme) {
            (KeyKind::Rsa, KeyType::RSA, SignatureAlgorithm::RsaPkcs1v15) => {
                let (mechanism, input) =
                    pkcs1(pkcs1_on_host(&self.mechanisms, digest), data, digest);
                sign(&mechanism, &input)
            }
            (KeyKind::Rsa, KeyType::RSA, SignatureAlgorithm::RsaPss) => {
                // CKM_RSA_PKCS_PSS signs a digest the helper computes; MGF1
                // uses the same digest and the salt is the digest's length.
                let (hash_alg, mgf) = match digest {
                    DigestAlgorithm::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
                    DigestAlgorithm::Sha384 => (MechanismType::SHA384, PkcsMgfType::MGF1_SHA384),
                };
                let params = PkcsPssParams {
                    hash_alg,
                    mgf,
                    s_len: (digest.size() as std::ffi::c_ulong).into(),
                };
                sign(&Mechanism::RsaPkcsPss(params), &digest.digest(data))
            }
            (
                KeyKind::P256 | KeyKind::P384 | KeyKind::BrainpoolP256r1 | KeyKind::BrainpoolP384r1,
                KeyType::EC,
                SignatureAlgorithm::Ecdsa,
            ) => {
                let raw = sign(&Mechanism::Ecdsa, &digest.digest(data))?;
                let len = kind.ecdsa_len().expect("an EC key");
                Ok(cms::ecdsa_signature(&raw, len)?)
            }
            _ => Err(TokenError(
                "The key on the token isn't the kind its certificate names.".into(),
            )),
        }
    }

    /// C_SignInit, the context-specific login a key with
    /// CKA_ALWAYS_AUTHENTICATE needs (with `pin`, or `None` for the PIN pad's
    /// prompt), then C_Sign, which asks the length before signing.
    fn sign_raw(
        &self,
        mechanism: &Mechanism,
        key: ObjectHandle,
        input: &[u8],
        pin: Option<&AuthPin>,
    ) -> Result<Vec<u8>, TokenError> {
        if !self.pin_pad && pin.is_none() {
            return Err(TokenError(
                "The key needs the PIN for each signature, and none was kept from login.".into(),
            ));
        }
        let c_sign = self
            .c_sign
            .ok_or_else(|| TokenError("The token driver has no C_Sign.".into()))?;
        self.session
            .sign_init(mechanism, key)
            .map_err(|e| err("The token couldn't sign", e))?;
        self.session
            .login(UserType::ContextSpecific, pin)
            .map_err(|e| err("The token refused the PIN for this signature", e))?;
        let check = |rv| {
            Rv::from(rv)
                .into_result(Function::Sign)
                .map_err(|e| err("The token couldn't sign", e))
        };
        let input_len =
            CK_ULONG::try_from(input.len()).map_err(|e| err("The token couldn't sign", e))?;
        let mut len: CK_ULONG = 0;
        // SAFETY: the session's handle with a sign operation started on it,
        // `input` for its length, and a null buffer to ask the length.
        check(unsafe {
            c_sign(
                self.session.handle(),
                input.as_ptr().cast_mut(),
                input_len,
                std::ptr::null_mut(),
                &mut len,
            )
        })?;
        let mut signature = vec![0; len as usize];
        // SAFETY: as above, with a buffer of the length the token gave.
        check(unsafe {
            c_sign(
                self.session.handle(),
                input.as_ptr().cast_mut(),
                input_len,
                signature.as_mut_ptr(),
                &mut len,
            )
        })?;
        signature.truncate(len as usize);
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_certificates_need_the_key_usage() {
        const NON_REPUDIATION: &[u8] = include_bytes!("../tests/fixtures/non-repudiation.der");
        const DIGITAL_SIGNATURE: &[u8] = include_bytes!("../tests/fixtures/digital-signature.der");
        const NO_KEY_USAGE: &[u8] = include_bytes!("../tests/fixtures/no-key-usage.der");
        assert!(is_signing_certificate(
            NON_REPUDIATION,
            KeyUsage::NonRepudiation
        ));
        assert!(!is_signing_certificate(
            DIGITAL_SIGNATURE,
            KeyUsage::NonRepudiation
        ));
        assert!(!is_signing_certificate(
            NO_KEY_USAGE,
            KeyUsage::NonRepudiation
        ));
        assert!(is_signing_certificate(
            NON_REPUDIATION,
            KeyUsage::DigitalSignature
        ));
        assert!(is_signing_certificate(
            DIGITAL_SIGNATURE,
            KeyUsage::DigitalSignature
        ));
        assert!(!is_signing_certificate(
            NO_KEY_USAGE,
            KeyUsage::DigitalSignature
        ));
    }

    #[test]
    fn certificates_sign_only_within_their_validity_period() {
        // Valid from 1 January 2020 to 1 January 2021.
        const EXPIRED: &[u8] = include_bytes!("../tests/fixtures/expired.der");
        assert_eq!(outside_validity(EXPIRED, 1_600_000_000), None);
        assert_eq!(
            outside_validity(EXPIRED, 1_700_000_000).as_deref(),
            Some(
                "The certificate on your token expired on 1 January 2021. Renew it with the company that issued it, then try again."
            )
        );
        assert_eq!(
            outside_validity(EXPIRED, 1_500_000_000).as_deref(),
            Some(
                "The certificate on your token isn't valid until 1 January 2020. Try again from that date."
            )
        );
    }

    /// CKM_RSA_PKCS over the DigestInfo hashed here gives the signature the
    /// combined mechanism gives. SoftHSM has both, so the inputs come from
    /// [`pkcs1`] directly. Runs when `KEYSEAL_SOFTHSM_MODULE` names
    /// libsofthsm2, with softhsm2-util and pkcs11-tool on the PATH. The test
    /// sets up a token, then runs itself in a process of its own with
    /// `SOFTHSM2_CONF` set, as the other tests' threads share this one's
    /// environment.
    #[test]
    fn signs_pkcs1_on_the_host_as_the_token_does() {
        use std::process::Command;
        const PIN: &str = "1234";
        let Ok(module) = std::env::var("KEYSEAL_SOFTHSM_MODULE") else {
            eprintln!("skipped: set KEYSEAL_SOFTHSM_MODULE to libsofthsm2 to run");
            return;
        };
        if std::env::var_os("KEYSEAL_PKCS1_TOKEN").is_none() {
            let dir = std::env::temp_dir().join(format!("keyseal-pkcs1-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("tokens")).unwrap();
            let conf = dir.join("softhsm2.conf");
            std::fs::write(
                &conf,
                format!("directories.tokendir = {}\n", dir.join("tokens").display()),
            )
            .unwrap();
            let run = |command: &mut Command| {
                let output = command.env("SOFTHSM2_CONF", &conf).output().unwrap();
                assert!(
                    output.status.success(),
                    "{command:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8_lossy(&output.stdout).into_owned()
            };
            run(Command::new("softhsm2-util").args([
                "--init-token",
                "--free",
                "--label",
                "pkcs1",
                "--pin",
                PIN,
                "--so-pin",
                "5678",
            ]));
            run(Command::new("pkcs11-tool")
                .args(["--module", &module, "--login", "--pin", PIN])
                .args([
                    "--keypairgen",
                    "--key-type",
                    "rsa:2048",
                    "--id",
                    "01",
                    "--usage-sign",
                ]));
            let child = run(Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "token::tests::signs_pkcs1_on_the_host_as_the_token_does",
                ])
                .env("KEYSEAL_PKCS1_TOKEN", "1"));
            assert!(child.contains("1 passed"), "{child}");
            std::fs::remove_dir_all(&dir).unwrap();
            return;
        }
        let token = Module::load(Path::new(&module))
            .unwrap()
            .open(Duration::ZERO)
            .unwrap();
        assert!(token.mechanisms.contains(&MechanismType::SHA384_RSA_PKCS));
        token.login(Zeroizing::new(PIN.into())).unwrap();
        let key = token
            .session
            .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY)])
            .unwrap()[0];
        for digest in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha384] {
            let sign = |on_host| {
                let (mechanism, input) = pkcs1(on_host, b"signed attributes", digest);
                token.session.sign(&mechanism, key, &input).unwrap()
            };
            assert_eq!(sign(true), sign(false), "{digest:?}");
        }
        token.close();
    }

    /// Any PKCS#11 token or smart card, not only India's DSC tokens.
    #[test]
    fn names_tokens_generically() {
        assert_eq!(NO_TOKEN, "No token or smart card is plugged in.");
        assert_eq!(
            crate::modules::NO_DRIVER,
            "No token or smart card driver was found."
        );
    }

    #[test]
    fn hashes_on_the_host_only_without_the_combined_mechanism() {
        use MechanismType as M;
        let all = [M::RSA_PKCS, M::SHA256_RSA_PKCS, M::SHA384_RSA_PKCS];
        let raw_only = [M::RSA_PKCS, M::ECDSA];
        for digest in [DigestAlgorithm::Sha256, DigestAlgorithm::Sha384] {
            assert!(!pkcs1_on_host(&all, digest));
            assert!(pkcs1_on_host(&raw_only, digest));
            // No list, or neither mechanism: the combined one, as before.
            assert!(!pkcs1_on_host(&[], digest));
            assert!(!pkcs1_on_host(&[M::ECDSA], digest));
        }
        assert!(pkcs1_on_host(
            &[M::RSA_PKCS, M::SHA256_RSA_PKCS],
            DigestAlgorithm::Sha384
        ));
        assert!(!pkcs1_on_host(
            &[M::RSA_PKCS, M::SHA256_RSA_PKCS],
            DigestAlgorithm::Sha256
        ));
        let (mechanism, input) = pkcs1(true, b"abc", DigestAlgorithm::Sha384);
        assert_eq!(mechanism.mechanism_type(), M::RSA_PKCS);
        assert_eq!(input, DigestAlgorithm::Sha384.digest_info(b"abc"));
        let (mechanism, input) = pkcs1(false, b"abc", DigestAlgorithm::Sha384);
        assert_eq!(mechanism.mechanism_type(), M::SHA384_RSA_PKCS);
        assert_eq!(input, b"abc");
    }

    // chain-*.der: a P-256 root, a sub CA it issued, a signer the sub CA
    // issued, and an impostor self-signed CA with the sub CA's name and
    // another key, made with `openssl x509 -req` and key identifiers.
    const ROOT: &[u8] = include_bytes!("../tests/fixtures/chain-root.der");
    const SUB: &[u8] = include_bytes!("../tests/fixtures/chain-sub.der");
    const SIGNER: &[u8] = include_bytes!("../tests/fixtures/chain-signer.der");
    const IMPOSTOR: &[u8] = include_bytes!("../tests/fixtures/chain-impostor.der");
    const OTHER: &[u8] = include_bytes!("../tests/fixtures/non-repudiation.der");

    #[test]
    fn issuers_follow_the_chain_and_leave_the_rest_out() {
        let others = [OTHER, ROOT, IMPOSTOR, SUB].map(<[u8]>::to_vec).to_vec();
        assert_eq!(issuers(SIGNER, others), [SUB, ROOT]);
    }

    #[test]
    fn issuers_need_the_issuer_on_the_token() {
        let others = [OTHER, ROOT, IMPOSTOR].map(<[u8]>::to_vec).to_vec();
        assert!(issuers(SIGNER, others).is_empty());
        let others = [ROOT, SIGNER].map(<[u8]>::to_vec).to_vec();
        assert_eq!(issuers(SUB, others), [ROOT]);
    }

    #[test]
    fn a_self_signed_certificate_has_no_issuers() {
        let others = [ROOT, SUB, SIGNER].map(<[u8]>::to_vec).to_vec();
        assert!(issuers(OTHER, others.clone()).is_empty());
        assert!(issuers(ROOT, others).is_empty());
    }
}

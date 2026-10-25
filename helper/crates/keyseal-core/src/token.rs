//! The user's DSC token through PKCS#11, and the [`TokenBackend`] seam the
//! flow signs through. The PIN is used to log in and dropped; nothing from
//! the token is written to disk.

use std::path::Path;
use std::time::{Duration, Instant};

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::RvError;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cms::{self, DigestAlgorithm, KeyKind, SignatureAlgorithm};
use crate::worker::{self, Backend, WorkerToken};

#[derive(Debug)]
pub struct TokenError(pub String);

/// The error when no token is plugged in, also as relayed by the worker.
pub const NO_TOKEN: &str = "No DSC token is plugged in.";

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

pub(crate) fn err(context: &str, error: impl std::fmt::Display) -> TokenError {
    TokenError(format!("{context}: {error}"))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Whether a certificate can be offered for signing: a supported key
/// (section 11), not a CA, and a key usage with nonRepudiation, which the
/// server's certificate check requires.
pub fn is_signing_certificate(der: &[u8]) -> bool {
    if KeyKind::of_certificate(der).is_err() {
        return false;
    }
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    let ca = matches!(certificate.basic_constraints(), Ok(Some(ext)) if ext.value.ca);
    let non_repudiation =
        matches!(certificate.key_usage(), Ok(Some(ext)) if ext.value.non_repudiation());
    !ca && non_repudiation
}

/// The certificate's subject, for display (section 12.1).
pub fn subject(der: &[u8]) -> String {
    x509_parser::parse_x509_certificate(der)
        .map(|(_, certificate)| certificate.subject().to_string())
        .unwrap_or_else(|_| "unreadable certificate".into())
}

/// What the sign and enrol flow needs from where the job's key lives: a
/// PKCS#11 token, whose driver runs in this process or in the token worker,
/// or on Windows the certificate store through CNG.
pub trait TokenBackend {
    /// The token has a PIN pad (protected authentication path).
    fn pin_pad(&self) -> bool;
    /// What the driver says about remaining PIN attempts.
    fn pin_warning(&self) -> Option<&'static str>;
    /// Every certificate the session can see: before login only public
    /// objects, after login private ones too. With `with_private_key`, only
    /// those with a private key beside them, which login makes visible.
    fn certificates(&self, with_private_key: bool) -> Result<Vec<TokenCertificate>, TokenError>;
    /// Logs in with `pin`, or through the PIN pad when the token has one.
    /// The PIN is dropped, and so zeroised, after the call.
    fn login(&self, pin: Zeroizing<String>) -> Result<(), TokenError>;
    /// The signature value over each item of `data`, in order, with the
    /// private key of `certificate` (DER), encoded as section 11.1 says. The
    /// key is found once and every item is signed in the same session (on
    /// CNG, through one key handle), so one login covers a job's documents.
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
    /// Ends the session; for PKCS#11, logs out.
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
        Ok(Self { pkcs11 })
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
        let pin_warning = if info.user_pin_locked() {
            Some(PinWarning::Locked)
        } else if info.user_pin_final_try() {
            Some(PinWarning::FinalTry)
        } else if info.user_pin_count_low() {
            Some(PinWarning::CountLow)
        } else {
            None
        };
        Ok(Token {
            session,
            pin_pad: info.protected_authentication_path(),
            pin_warning,
        })
    }
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
    /// The token has a PIN pad (protected authentication path).
    pub pin_pad: bool,
    /// What the driver says about remaining PIN attempts.
    pub pin_warning: Option<PinWarning>,
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

    fn pin_warning(&self) -> Option<&'static str> {
        self.pin_warning.map(PinWarning::message)
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

    fn login(&self, pin: Zeroizing<String>) -> Result<(), TokenError> {
        // Copied once into a buffer of exactly its length, which `AuthPin`
        // zeroises; `AuthPin::from(String)` would shrink the String and free
        // its old buffer without zeroising it.
        let pin = AuthPin::from(Box::<str>::from(pin.as_str()));
        let pin = if self.pin_pad { None } else { Some(&pin) };
        self.session
            .login(UserType::User, pin)
            .map_err(|e| err("The token refused the PIN", e))
    }

    fn close(&self) {
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
        let key_type = match self
            .session
            .get_attributes(key, &[AttributeType::KeyType])
            .map_err(|e| err("Couldn't read the key", e))?
            .first()
        {
            Some(Attribute::KeyType(key_type)) => *key_type,
            _ => {
                return Err(TokenError(
                    "The token didn't say what kind of key it holds.".into(),
                ));
            }
        };
        data.iter()
            .map(|data| self.sign_one(key, kind, key_type, data, digest, scheme))
            .collect()
    }
}

impl Token {
    /// One signature with `key`, whose type the token reported as `key_type`.
    fn sign_one(
        &self,
        key: ObjectHandle,
        kind: KeyKind,
        key_type: KeyType,
        data: &[u8],
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
    ) -> Result<Vec<u8>, TokenError> {
        let sign = |mechanism: &Mechanism, input: &[u8]| {
            self.session
                .sign(mechanism, key, input)
                .map_err(|e| err("The token couldn't sign", e))
        };
        match (kind, key_type, scheme) {
            (KeyKind::Rsa, KeyType::RSA, SignatureAlgorithm::RsaPkcs1v15) => {
                let mechanism = match digest {
                    DigestAlgorithm::Sha256 => Mechanism::Sha256RsaPkcs,
                    DigestAlgorithm::Sha384 => Mechanism::Sha384RsaPkcs,
                };
                sign(&mechanism, data)
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
            (KeyKind::P256 | KeyKind::P384, KeyType::EC, SignatureAlgorithm::Ecdsa) => {
                let raw = sign(&Mechanism::Ecdsa, &digest.digest(data))?;
                let len = if kind == KeyKind::P256 { 64 } else { 96 };
                Ok(cms::ecdsa_signature(&raw, len)?)
            }
            _ => Err(TokenError(
                "The key on the token isn't the kind its certificate names.".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_certificates_need_non_repudiation() {
        assert!(is_signing_certificate(include_bytes!(
            "../tests/fixtures/non-repudiation.der"
        )));
        assert!(!is_signing_certificate(include_bytes!(
            "../tests/fixtures/digital-signature.der"
        )));
        assert!(!is_signing_certificate(include_bytes!(
            "../tests/fixtures/no-key-usage.der"
        )));
    }
}

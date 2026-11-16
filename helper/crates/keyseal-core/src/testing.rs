//! Support for the unit tests: a temporary directory that cleans up after
//! itself, and a fake driver and token.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::cms::{DigestAlgorithm, SignatureAlgorithm};
use crate::token::{
    Driver, LoginError, PinWarning, TokenBackend, TokenCertificate, TokenError, TokenInfo,
};

pub(crate) const RSA: &[u8] = include_bytes!("../tests/fixtures/rsa-non-repudiation.der");

/// `keyseal-<name>-<pid>` in the system's temporary directory, created
/// empty and removed when dropped, also when the test panics.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("keyseal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) type SignCall = (Vec<Vec<u8>>, DigestAlgorithm, SignatureAlgorithm);

/// A token showing `public` before login and `private` after.
pub(crate) struct FakeToken {
    pub(crate) public: Vec<&'static [u8]>,
    pub(crate) private: Vec<&'static [u8]>,
    pub(crate) logged_in: Cell<bool>,
    /// How many items each `sign` call got, shared with the test.
    pub(crate) signed: Arc<Mutex<Vec<usize>>>,
    /// What each `sign` call got: its items, digest and scheme.
    pub(crate) sign_calls: Arc<Mutex<Vec<SignCall>>>,
    /// What each login answers, in order; then it succeeds.
    pub(crate) logins: std::cell::RefCell<std::collections::VecDeque<LoginError>>,
    /// How many logins were made, shared with the test.
    pub(crate) attempts: Arc<Mutex<usize>>,
    /// The token's flags after as many logins as the index; none after
    /// the last.
    pub(crate) warnings: Vec<Option<PinWarning>>,
}

impl FakeToken {
    pub(crate) fn new(public: Vec<&'static [u8]>, private: Vec<&'static [u8]>) -> Self {
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
                sha256: crate::sha256_hex(der),
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
pub(crate) struct FakeDriver {
    pub(crate) tokens: Vec<Option<FakeToken>>,
    /// The slots whose certificates were read, shared with the test.
    pub(crate) shown: Arc<Mutex<Vec<u64>>>,
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
pub(crate) fn info(slot: u64, serial: &str, certificates: &[&[u8]]) -> TokenInfo {
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
                sha256: crate::sha256_hex(der),
                id: None,
            })
            .collect(),
    }
}

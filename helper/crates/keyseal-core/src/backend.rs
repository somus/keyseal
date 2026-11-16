//! Where the job's key is: the PKCS#11 modules [`modules::attempts`] lists,
//! tried in order until one reaches a token, then on Windows and macOS the
//! system's certificate store. The flow, `keyseal doctor` and `keyseal list`
//! find tokens through [`open_backend`].

use std::time::Duration;

#[cfg(windows)]
use crate::cng::CngStore;
use crate::flow::Failure;
#[cfg(target_os = "macos")]
use crate::keychain::Keychain;
use crate::modules::{self, Attempt, Source};
use crate::protocol::KeyUsage;
#[cfg(any(windows, target_os = "macos"))]
use crate::store::Store;
use crate::token::{self, Driver, TokenBackend, TokenInfo};

/// Called before the system's certificate store is read; an error stops
/// the job.
pub(crate) type BeforeStore<'a> = &'a mut dyn FnMut() -> Result<(), Failure>;

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
    pub(crate) drivers: Vec<Box<dyn Driver>>,
    pub(crate) tokens: Vec<TokenInfo>,
    /// The index in `drivers` of each token's driver.
    pub(crate) driver_of: Vec<usize>,
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

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::testing::{FakeDriver, FakeToken, RSA, info};

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
                        Err(Failure {
                            message: "Signing cancelled.".into(),
                            cancelled: true,
                        })
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
}

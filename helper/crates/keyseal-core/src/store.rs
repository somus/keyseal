//! The system's certificate store, the last resort when no PKCS#11 module
//! reaches a token: on Windows the current user's store through CNG
//! ([`crate::cng`]), on macOS the keychain's CryptoTokenKit items
//! ([`crate::keychain`]). Only certificates whose private key is on a
//! token or smart card are offered. The system or the vendor shows its own
//! PIN dialog during signing, so the helper never sees the PIN (section
//! 12.1).
//!
//! The platform calls sit behind [`KeyStore`], so the filtering and the
//! signature encoding are tested on every platform.

use crate::cms::{self, DigestAlgorithm, KeyKind, SignatureAlgorithm};
use crate::protocol::KeyUsage;
use crate::token::{self, TokenBackend, TokenCertificate, TokenError};

/// A certificate in the store and where its private key is.
pub struct StoreCertificate {
    pub der: Vec<u8>,
    /// The private key is on a token or smart card: on Windows its
    /// provider is hardware or removable, on macOS CryptoTokenKit holds it.
    pub hardware_key: bool,
}

/// The padding the store applies. PKCS#1 v1.5 puts the digest's
/// OID in the DigestInfo; PSS uses MGF1 with the digest and a salt of the
/// digest's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Padding {
    Pkcs1(DigestAlgorithm),
    Pss(DigestAlgorithm),
    /// ECDSA, which returns r||s.
    None,
}

pub trait KeyStore {
    /// Every certificate in the store with a private key the helper can use.
    fn certificates(&self) -> Result<Vec<StoreCertificate>, TokenError>;
    /// Signs each of `hashes`, in order, with one handle to the private key
    /// of `certificate`; on Windows the provider's PIN dialog belongs to
    /// `window` when given.
    fn sign_hashes(
        &self,
        certificate: &[u8],
        hashes: &[Vec<u8>],
        padding: Padding,
        window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError>;
}

pub struct Store<S> {
    store: S,
    /// The key usage the job asks for, so a store with no certificate the
    /// job accepts reads as empty and the flow moves on.
    usage: KeyUsage,
}

impl<S: KeyStore> Store<S> {
    pub fn new(store: S, usage: KeyUsage) -> Self {
        Self { store, usage }
    }
}

impl<S: KeyStore> TokenBackend for Store<S> {
    /// The vendor's dialog asks for the PIN.
    fn pin_pad(&self) -> bool {
        false
    }

    fn pin_warning(&self) -> Option<&'static str> {
        None
    }

    /// Signing certificates with the job's key usage whose key is on a smart
    /// card or token; each has its private key, so `with_private_key`
    /// changes nothing.
    fn certificates(&self, _with_private_key: bool) -> Result<Vec<TokenCertificate>, TokenError> {
        Ok(self
            .store
            .certificates()?
            .into_iter()
            .filter(|c| c.hardware_key && token::is_signing_certificate(&c.der, self.usage))
            .map(|c| TokenCertificate {
                sha256: token::sha256_hex(&c.der),
                der: c.der,
                id: None,
            })
            .collect())
    }

    /// The vendor's dialog asks for the PIN during signing instead.
    fn login(&self, _pin: zeroize::Zeroizing<String>) -> Result<(), TokenError> {
        Ok(())
    }

    fn sign(
        &self,
        certificate: &[u8],
        data: &[Vec<u8>],
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
        window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError> {
        let kind = KeyKind::of_certificate(certificate)?;
        kind.check(digest, scheme)?;
        let padding = match scheme {
            SignatureAlgorithm::RsaPkcs1v15 => Padding::Pkcs1(digest),
            SignatureAlgorithm::RsaPss => Padding::Pss(digest),
            SignatureAlgorithm::Ecdsa => Padding::None,
        };
        let hashes: Vec<Vec<u8>> = data.iter().map(|data| digest.digest(data)).collect();
        self.store
            .sign_hashes(certificate, &hashes, padding, window)?
            .into_iter()
            .map(|signature| match kind.ecdsa_len() {
                None => Ok(signature),
                Some(len) => Ok(cms::ecdsa_signature(&signature, len)?),
            })
            .collect()
    }

    fn close(&self) {}
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const NON_REPUDIATION: &[u8] = include_bytes!("../tests/fixtures/non-repudiation.der");
    const RSA: &[u8] = include_bytes!("../tests/fixtures/rsa-non-repudiation.der");

    #[derive(Default)]
    struct FakeStore {
        certificates: Vec<(&'static [u8], bool)>,
        signature: Vec<u8>,
        /// Each call's hashes and padding: one call is one key handle.
        signed: RefCell<Vec<(Vec<Vec<u8>>, Padding)>>,
    }

    impl KeyStore for FakeStore {
        fn certificates(&self) -> Result<Vec<StoreCertificate>, TokenError> {
            Ok(self
                .certificates
                .iter()
                .map(|&(der, hardware_key)| StoreCertificate {
                    der: der.to_vec(),
                    hardware_key,
                })
                .collect())
        }

        fn sign_hashes(
            &self,
            _certificate: &[u8],
            hashes: &[Vec<u8>],
            padding: Padding,
            _window: Option<isize>,
        ) -> Result<Vec<Vec<u8>>, TokenError> {
            self.signed.borrow_mut().push((hashes.to_vec(), padding));
            Ok(vec![self.signature.clone(); hashes.len()])
        }
    }

    fn store(signature: Vec<u8>) -> Store<FakeStore> {
        Store::new(
            FakeStore {
                signature,
                ..FakeStore::default()
            },
            KeyUsage::default(),
        )
    }

    #[test]
    fn offers_signing_certificates_with_hardware_keys() {
        const DIGITAL_SIGNATURE: &[u8] = include_bytes!("../tests/fixtures/digital-signature.der");
        let store = || FakeStore {
            certificates: vec![
                (NON_REPUDIATION, true),
                (RSA, false),
                (DIGITAL_SIGNATURE, true),
                (include_bytes!("../tests/fixtures/no-key-usage.der"), true),
            ],
            ..FakeStore::default()
        };
        let offered = Store::new(store(), KeyUsage::NonRepudiation)
            .certificates(false)
            .unwrap();
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].der, NON_REPUDIATION);
        assert_eq!(offered[0].sha256, token::sha256_hex(NON_REPUDIATION));
        // A job whose policy accepts digitalSignature also sees that one.
        let offered = Store::new(store(), KeyUsage::DigitalSignature)
            .certificates(false)
            .unwrap();
        assert_eq!(offered.len(), 2);
        assert_eq!(offered[1].der, DIGITAL_SIGNATURE);
        // With only a digitalSignature certificate, a default job finds the
        // store empty, so the flow tries the next place.
        let only = FakeStore {
            certificates: vec![(DIGITAL_SIGNATURE, true)],
            ..FakeStore::default()
        };
        assert!(
            Store::new(only, KeyUsage::NonRepudiation)
                .certificates(false)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn ecdsa_r_s_becomes_der() {
        let store = store([[0x80; 32], [0x01; 32]].concat());
        let signature = store
            .sign(
                NON_REPUDIATION,
                &[b"attributes".to_vec()],
                DigestAlgorithm::Sha256,
                SignatureAlgorithm::Ecdsa,
                None,
            )
            .unwrap();
        let expected = [
            &[0x30, 0x45, 0x02, 0x21, 0x00][..],
            &[0x80; 32],
            &[0x02, 0x20],
            &[0x01; 32],
        ]
        .concat();
        assert_eq!(signature, [expected]);
        assert_eq!(
            *store.store.signed.borrow(),
            [(
                vec![DigestAlgorithm::Sha256.digest(b"attributes")],
                Padding::None
            )]
        );
    }

    #[test]
    fn ecdsa_of_the_wrong_length_is_refused() {
        let store = store(vec![1; 96]);
        assert!(
            store
                .sign(
                    NON_REPUDIATION,
                    &[b"attributes".to_vec()],
                    DigestAlgorithm::Sha256,
                    SignatureAlgorithm::Ecdsa,
                    None,
                )
                .is_err()
        );
    }

    #[test]
    fn rsa_pads_with_the_digest_and_returns_the_signature_as_is() {
        for (scheme, padding) in [
            (
                SignatureAlgorithm::RsaPkcs1v15,
                Padding::Pkcs1(DigestAlgorithm::Sha384),
            ),
            (
                SignatureAlgorithm::RsaPss,
                Padding::Pss(DigestAlgorithm::Sha384),
            ),
        ] {
            let store = store(vec![7; 256]);
            let signature = store
                .sign(
                    RSA,
                    &[b"attributes".to_vec()],
                    DigestAlgorithm::Sha384,
                    scheme,
                    None,
                )
                .unwrap();
            assert_eq!(signature, [vec![7; 256]]);
            assert_eq!(
                *store.store.signed.borrow(),
                [(vec![DigestAlgorithm::Sha384.digest(b"attributes")], padding)]
            );
        }
    }

    #[test]
    fn a_scheme_the_key_does_not_sign_never_reaches_the_store() {
        let store = store(vec![7; 256]);
        assert!(
            store
                .sign(
                    RSA,
                    &[b"attributes".to_vec()],
                    DigestAlgorithm::Sha256,
                    SignatureAlgorithm::Ecdsa,
                    None,
                )
                .is_err()
        );
        assert!(store.store.signed.borrow().is_empty());
    }

    /// A job's documents go to the store in one call, so through one key
    /// handle and one PIN dialog, each as its own hash, in order.
    #[test]
    fn signs_every_document_through_one_key_handle() {
        let store = store([[0x01; 32], [0x02; 32]].concat());
        let documents = [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];
        let signatures = store
            .sign(
                NON_REPUDIATION,
                &documents,
                DigestAlgorithm::Sha256,
                SignatureAlgorithm::Ecdsa,
                None,
            )
            .unwrap();
        assert_eq!(signatures.len(), 3);
        let signed = store.store.signed.borrow();
        assert_eq!(signed.len(), 1);
        assert_eq!(
            signed[0].0,
            documents
                .iter()
                .map(|data| DigestAlgorithm::Sha256.digest(data))
                .collect::<Vec<_>>()
        );
    }
}

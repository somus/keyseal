//! The Windows certificate store through CNG, the last resort when no
//! PKCS#11 module is installed. Certificates come from the current user's
//! `MY` store when their private key is in a hardware or removable key
//! storage provider, which is how smart card and token drivers register.
//! The vendor's provider shows its own PIN dialog during `NCryptSignHash`,
//! so the helper never sees the PIN (section 12.1). A job's documents are
//! signed through one key handle, so a provider that keeps the handle
//! authenticated, as the smart card providers do, asks once per job; one
//! that asks on every signature by its own policy asks once per document.
//!
//! The Windows calls sit behind [`KeyStore`], so the filtering and the
//! signature encoding are tested on every platform.

use crate::cms::{self, DigestAlgorithm, KeyKind, SignatureAlgorithm};
use crate::token::{self, TokenBackend, TokenCertificate, TokenError};

#[cfg(windows)]
pub use system::SystemStore;

/// A certificate in the store and where its private key is.
pub struct StoreCertificate {
    pub der: Vec<u8>,
    /// The key's provider is hardware or removable.
    pub hardware_key: bool,
}

/// The padding `NCryptSignHash` applies. PKCS#1 v1.5 puts the digest's
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
    /// Every certificate in the store whose private key CNG can open.
    fn certificates(&self) -> Result<Vec<StoreCertificate>, TokenError>;
    /// `NCryptSignHash` over each of `hashes`, in order, with one handle to
    /// the private key of `certificate`; the provider's PIN dialog belongs
    /// to `window` when given.
    fn sign_hashes(
        &self,
        certificate: &[u8],
        hashes: &[Vec<u8>],
        padding: Padding,
        window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError>;
}

pub struct Cng<S> {
    store: S,
}

impl<S: KeyStore> Cng<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }
}

impl<S: KeyStore> TokenBackend for Cng<S> {
    /// The vendor's dialog asks for the PIN.
    fn pin_pad(&self) -> bool {
        false
    }

    fn pin_warning(&self) -> Option<&'static str> {
        None
    }

    /// Signing certificates whose key is on a smart card or token; each
    /// has its private key, so `with_private_key` changes nothing.
    fn certificates(&self, _with_private_key: bool) -> Result<Vec<TokenCertificate>, TokenError> {
        Ok(self
            .store
            .certificates()?
            .into_iter()
            .filter(|c| c.hardware_key && token::is_signing_certificate(&c.der))
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
            .map(|signature| match kind {
                KeyKind::Rsa => Ok(signature),
                KeyKind::P256 => Ok(cms::ecdsa_signature(&signature, 64)?),
                KeyKind::P384 => Ok(cms::ecdsa_signature(&signature, 96)?),
            })
            .collect()
    }

    fn close(&self) {}
}

#[cfg(windows)]
mod system {
    use std::ffi::c_void;

    use windows::Win32::Security::Cryptography::{
        BCRYPT_PKCS1_PADDING_INFO, BCRYPT_PSS_PADDING_INFO, BCRYPT_SHA256_ALGORITHM,
        BCRYPT_SHA384_ALGORITHM, CERT_CONTEXT, CERT_OPEN_STORE_FLAGS, CERT_QUERY_ENCODING_TYPE,
        CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
        CERT_SYSTEM_STORE_CURRENT_USER, CRYPT_ACQUIRE_FLAGS, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
        CRYPT_ACQUIRE_SILENT_FLAG, CertCloseStore, CertEnumCertificatesInStore,
        CertFreeCertificateContext, CertOpenStore, CryptAcquireCertificatePrivateKey, HCERTSTORE,
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, NCRYPT_FLAGS, NCRYPT_HANDLE, NCRYPT_IMPL_HARDWARE_FLAG,
        NCRYPT_IMPL_REMOVABLE_FLAG, NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE,
        NCRYPT_PAD_PKCS1_FLAG, NCRYPT_PAD_PSS_FLAG, NCRYPT_PROV_HANDLE,
        NCRYPT_PROVIDER_HANDLE_PROPERTY, NCRYPT_WINDOW_HANDLE_PROPERTY, NCryptFreeObject,
        NCryptGetProperty, NCryptSetProperty, NCryptSignHash,
    };
    use windows::Win32::Security::OBJECT_SECURITY_INFORMATION;
    use windows::core::{BOOL, Owned, PCWSTR, w};

    use super::{KeyStore, Padding, StoreCertificate};
    use crate::cms::DigestAlgorithm;
    use crate::token::{TokenError, err};

    /// The current user's `MY` store.
    pub struct SystemStore;

    impl KeyStore for SystemStore {
        fn certificates(&self) -> Result<Vec<StoreCertificate>, TokenError> {
            let store = Store::open()?;
            let mut found = Vec::new();
            store.find(|context| {
                // Silent, so listing never raises a vendor dialog.
                let hardware_key = private_key(context, true).is_ok_and(|key| key.on_hardware());
                found.push(StoreCertificate {
                    der: encoded(context).to_vec(),
                    hardware_key,
                });
                None::<()>
            });
            Ok(found)
        }

        fn sign_hashes(
            &self,
            certificate: &[u8],
            hashes: &[Vec<u8>],
            padding: Padding,
            window: Option<isize>,
        ) -> Result<Vec<Vec<u8>>, TokenError> {
            let store = Store::open()?;
            let key = store
                .find(|context| {
                    (encoded(context) == certificate).then(|| private_key(context, false))
                })
                .ok_or_else(|| {
                    TokenError(
                        "The Windows certificate store no longer holds the certificate.".into(),
                    )
                })?
                .map_err(|e| err("Couldn't open the certificate's private key", e))?;
            if let Some(window) = window {
                unsafe {
                    NCryptSetProperty(
                        key.handle.into(),
                        NCRYPT_WINDOW_HANDLE_PROPERTY,
                        &window.to_ne_bytes(),
                        NCRYPT_FLAGS(0),
                    )
                }
                .map_err(|e| err("Couldn't attach the PIN dialog to the window", e))?;
            }
            let pkcs1;
            let pss;
            let (info, flags): (Option<*const c_void>, NCRYPT_FLAGS) = match padding {
                Padding::Pkcs1(digest) => {
                    pkcs1 = BCRYPT_PKCS1_PADDING_INFO {
                        pszAlgId: algorithm(digest),
                    };
                    (Some((&raw const pkcs1).cast()), NCRYPT_PAD_PKCS1_FLAG)
                }
                Padding::Pss(digest) => {
                    pss = BCRYPT_PSS_PADDING_INFO {
                        pszAlgId: algorithm(digest),
                        cbSalt: digest.size() as u32,
                    };
                    (Some((&raw const pss).cast()), NCRYPT_PAD_PSS_FLAG)
                }
                Padding::None => (None, NCRYPT_FLAGS(0)),
            };
            // The same handle for every hash: the vendor's PIN dialog
            // appears during the first call, and a provider that keeps the
            // handle authenticated doesn't ask again.
            hashes
                .iter()
                .map(|hash| {
                    // Room for RSA-8192.
                    let mut signature = vec![0; 1024];
                    let mut len = 0;
                    unsafe {
                        NCryptSignHash(
                            key.handle,
                            info,
                            hash,
                            Some(&mut signature),
                            &mut len,
                            flags,
                        )
                    }
                    .map_err(|e| err("The token couldn't sign", e))?;
                    signature.truncate(len as usize);
                    Ok(signature)
                })
                .collect()
        }
    }

    fn algorithm(digest: DigestAlgorithm) -> PCWSTR {
        match digest {
            DigestAlgorithm::Sha256 => BCRYPT_SHA256_ALGORITHM,
            DigestAlgorithm::Sha384 => BCRYPT_SHA384_ALGORITHM,
        }
    }

    fn encoded(context: &CERT_CONTEXT) -> &[u8] {
        unsafe { std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize) }
    }

    struct Store(HCERTSTORE);

    impl Store {
        fn open() -> Result<Self, TokenError> {
            let flags = CERT_OPEN_STORE_FLAGS(
                CERT_SYSTEM_STORE_CURRENT_USER
                    | CERT_STORE_OPEN_EXISTING_FLAG.0
                    | CERT_STORE_READONLY_FLAG.0,
            );
            let store = unsafe {
                CertOpenStore(
                    CERT_STORE_PROV_SYSTEM_W,
                    CERT_QUERY_ENCODING_TYPE(0),
                    None,
                    flags,
                    Some(w!("MY").as_ptr().cast()),
                )
            }
            .map_err(|e| err("Couldn't open the Windows certificate store", e))?;
            Ok(Self(store))
        }

        /// The first `Some` that `f` returns for a certificate in the store.
        fn find<T>(&self, mut f: impl FnMut(&CERT_CONTEXT) -> Option<T>) -> Option<T> {
            let mut previous = None;
            loop {
                // Frees the previous context; null after the last one.
                let context = unsafe { CertEnumCertificatesInStore(self.0, previous) };
                let current = unsafe { context.as_ref() }?;
                if let Some(found) = f(current) {
                    let _ = unsafe { CertFreeCertificateContext(Some(context)) };
                    return Some(found);
                }
                previous = Some(context.cast_const());
            }
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            let _ = unsafe { CertCloseStore(Some(self.0), 0) };
        }
    }

    struct Key {
        handle: NCRYPT_KEY_HANDLE,
        caller_frees: bool,
    }

    impl Key {
        /// Whether the key's provider is hardware or removable; the
        /// implementation type is a provider property.
        fn on_hardware(&self) -> bool {
            let mut provider = [0; size_of::<usize>()];
            if !property(
                self.handle.into(),
                NCRYPT_PROVIDER_HANDLE_PROPERTY,
                &mut provider,
            ) {
                return false;
            }
            let provider =
                unsafe { Owned::new(NCRYPT_PROV_HANDLE(usize::from_ne_bytes(provider))) };
            let mut impl_type = [0; 4];
            property(
                (*provider).into(),
                NCRYPT_IMPL_TYPE_PROPERTY,
                &mut impl_type,
            ) && u32::from_ne_bytes(impl_type)
                & (NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG)
                != 0
        }
    }

    impl Drop for Key {
        fn drop(&mut self) {
            if self.caller_frees {
                let _ = unsafe { NCryptFreeObject(self.handle.into()) };
            }
        }
    }

    /// The certificate's CNG key. Legacy CAPI-only keys are refused, since
    /// signing goes through `NCryptSignHash`.
    fn private_key(context: &CERT_CONTEXT, silent: bool) -> windows::core::Result<Key> {
        let mut flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG.0;
        if silent {
            flags |= CRYPT_ACQUIRE_SILENT_FLAG.0;
        }
        let mut handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut caller_frees = BOOL::default();
        unsafe {
            CryptAcquireCertificatePrivateKey(
                context,
                CRYPT_ACQUIRE_FLAGS(flags),
                None,
                &mut handle,
                None,
                Some(&mut caller_frees),
            )
        }?;
        Ok(Key {
            handle: NCRYPT_KEY_HANDLE(handle.0),
            caller_frees: caller_frees.as_bool(),
        })
    }

    /// Reads a fixed-size property of `handle` into `out`.
    fn property(handle: NCRYPT_HANDLE, name: PCWSTR, out: &mut [u8]) -> bool {
        let mut len = 0;
        unsafe {
            NCryptGetProperty(
                handle,
                name,
                Some(out),
                &mut len,
                OBJECT_SECURITY_INFORMATION(0),
            )
        }
        .is_ok()
            && len as usize == out.len()
    }
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

    fn cng(signature: Vec<u8>) -> Cng<FakeStore> {
        Cng::new(FakeStore {
            signature,
            ..FakeStore::default()
        })
    }

    #[test]
    fn offers_signing_certificates_with_hardware_keys() {
        let cng = Cng::new(FakeStore {
            certificates: vec![
                (NON_REPUDIATION, true),
                (RSA, false),
                (
                    include_bytes!("../tests/fixtures/digital-signature.der"),
                    true,
                ),
                (include_bytes!("../tests/fixtures/no-key-usage.der"), true),
            ],
            ..FakeStore::default()
        });
        let offered = cng.certificates(false).unwrap();
        assert_eq!(offered.len(), 1);
        assert_eq!(offered[0].der, NON_REPUDIATION);
        assert_eq!(offered[0].sha256, token::sha256_hex(NON_REPUDIATION));
    }

    #[test]
    fn ecdsa_r_s_becomes_der() {
        let cng = cng([[0x80; 32], [0x01; 32]].concat());
        let signature = cng
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
            *cng.store.signed.borrow(),
            [(
                vec![DigestAlgorithm::Sha256.digest(b"attributes")],
                Padding::None
            )]
        );
    }

    #[test]
    fn ecdsa_of_the_wrong_length_is_refused() {
        let cng = cng(vec![1; 96]);
        assert!(
            cng.sign(
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
            let cng = cng(vec![7; 256]);
            let signature = cng
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
                *cng.store.signed.borrow(),
                [(vec![DigestAlgorithm::Sha384.digest(b"attributes")], padding)]
            );
        }
    }

    #[test]
    fn a_scheme_the_key_does_not_sign_never_reaches_the_store() {
        let cng = cng(vec![7; 256]);
        assert!(
            cng.sign(
                RSA,
                &[b"attributes".to_vec()],
                DigestAlgorithm::Sha256,
                SignatureAlgorithm::Ecdsa,
                None,
            )
            .is_err()
        );
        assert!(cng.store.signed.borrow().is_empty());
    }

    /// A job's documents go to the store in one call, so through one key
    /// handle and one PIN dialog, each as its own hash, in order.
    #[test]
    fn signs_every_document_through_one_key_handle() {
        let cng = cng([[0x01; 32], [0x02; 32]].concat());
        let documents = [b"first".to_vec(), b"second".to_vec(), b"third".to_vec()];
        let signatures = cng
            .sign(
                NON_REPUDIATION,
                &documents,
                DigestAlgorithm::Sha256,
                SignatureAlgorithm::Ecdsa,
                None,
            )
            .unwrap();
        assert_eq!(signatures.len(), 3);
        let signed = cng.store.signed.borrow();
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

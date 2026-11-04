//! Windows: the current user's `MY` store through CNG. A certificate counts
//! when its private key is in a hardware or removable key storage
//! provider, which is how smart card and token drivers register. The
//! vendor's provider shows its own PIN dialog during `NCryptSignHash`, so
//! the helper never sees the PIN (section 12.1). A job's documents are
//! signed through one key handle, so a provider that keeps the handle
//! authenticated, as the smart card providers do, asks once per job; one
//! that asks on every signature by its own policy asks once per document.

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

use crate::cms::DigestAlgorithm;
use crate::store::{KeyStore, Padding, StoreCertificate};
use crate::token::{TokenError, err};

/// The current user's `MY` store.
pub struct CngStore;

impl KeyStore for CngStore {
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
            .find(|context| (encoded(context) == certificate).then(|| private_key(context, false)))
            .ok_or_else(|| {
                TokenError("The Windows certificate store no longer holds the certificate.".into())
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
        let provider = unsafe { Owned::new(NCRYPT_PROV_HANDLE(usize::from_ne_bytes(provider))) };
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

//! macOS: certificates on smart cards and tokens through CryptoTokenKit.
//! While a token is plugged in, CryptoTokenKit copies its certificates and
//! keys into the keychain, each marked with the token's ID
//! (`kSecAttrTokenID`). macOS's own driver covers PIV cards and YubiKeys;
//! other tokens need their vendor's CryptoTokenKit extension. Listing reads
//! no private key, so it raises no dialog; the system's PIN dialog appears
//! during `SecKeyCreateSignature`, so the helper never sees the PIN (section
//! 12.1). A job's documents are signed through one key reference; a key
//! whose token asks for the PIN on every signature, as a PIV signature key
//! does, asks once per document.

use core_foundation::base::TCFType;
use core_foundation::string::CFString;
use security_framework::identity::SecIdentity;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult};
use security_framework::key::{Algorithm, SecKey};
use security_framework_sys::base::errSecItemNotFound;
use security_framework_sys::item::{kSecAttrTokenID, kSecAttrTokenIDSecureEnclave};

use crate::cms::DigestAlgorithm;
use crate::store::{KeyStore, Padding, StoreCertificate};
use crate::token::{TokenError, err};

/// The keychain items CryptoTokenKit provides.
pub struct Keychain {
    scope: Scope,
}

enum Scope {
    /// `kSecAttrAccessGroupToken`: only items on a token.
    Tokens,
    /// File keychains instead, whose software keys count as on a token, so
    /// the tests run without one.
    #[cfg(test)]
    Files(Vec<security_framework::os::macos::keychain::SecKeychain>),
}

impl Keychain {
    pub fn tokens() -> Self {
        Self {
            scope: Scope::Tokens,
        }
    }

    fn identities(&self) -> Result<Vec<SecIdentity>, TokenError> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::identity())
            .load_refs(true)
            .limit(Limit::All);
        match &self.scope {
            Scope::Tokens => {
                search.access_group_token();
            }
            #[cfg(test)]
            Scope::Files(files) => {
                search.keychains(files);
            }
        }
        let results = match search.search() {
            Ok(results) => results,
            Err(error) if error.code() == errSecItemNotFound => return Ok(Vec::new()),
            Err(error) => return Err(err("Couldn't read the keychain", error)),
        };
        Ok(results
            .into_iter()
            .filter_map(|result| match result {
                SearchResult::Ref(Reference::Identity(identity)) => Some(identity),
                _ => None,
            })
            .collect())
    }

    /// Whether `key` is on a token: CryptoTokenKit gave it a token ID, and
    /// it isn't the Mac's own Secure Enclave.
    fn on_token(&self, key: &SecKey) -> bool {
        #[cfg(test)]
        if matches!(self.scope, Scope::Files(_)) {
            return true;
        }
        let attributes = key.attributes();
        let Some(token) = attributes.find(unsafe { kSecAttrTokenID }.cast()) else {
            return false;
        };
        let token = unsafe { CFString::wrap_under_get_rule((*token).cast()) };
        token != unsafe { CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave) }
    }
}

impl KeyStore for Keychain {
    fn certificates(&self) -> Result<Vec<StoreCertificate>, TokenError> {
        self.identities()?
            .into_iter()
            .map(|identity| {
                let der = identity
                    .certificate()
                    .map_err(|e| err("Couldn't read a keychain certificate", e))?
                    .to_der();
                let hardware_key = identity.private_key().is_ok_and(|key| self.on_token(&key));
                Ok(StoreCertificate { der, hardware_key })
            })
            .collect()
    }

    fn sign_hashes(
        &self,
        certificate: &[u8],
        hashes: &[Vec<u8>],
        padding: Padding,
        _window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError> {
        let identity = self
            .identities()?
            .into_iter()
            .find(|identity| {
                identity
                    .certificate()
                    .is_ok_and(|found| found.to_der() == certificate)
            })
            .ok_or_else(|| {
                TokenError(
                    "The keychain no longer holds the certificate. Plug the token back in.".into(),
                )
            })?;
        let key = identity
            .private_key()
            .map_err(|e| err("Couldn't open the certificate's private key", e))?;
        let algorithm = match padding {
            Padding::Pkcs1(DigestAlgorithm::Sha256) => Algorithm::RSASignatureDigestPKCS1v15SHA256,
            Padding::Pkcs1(DigestAlgorithm::Sha384) => Algorithm::RSASignatureDigestPKCS1v15SHA384,
            // Apple's PSS uses MGF1 with the digest and a salt of its length.
            Padding::Pss(DigestAlgorithm::Sha256) => Algorithm::RSASignatureDigestPSSSHA256,
            Padding::Pss(DigestAlgorithm::Sha384) => Algorithm::RSASignatureDigestPSSSHA384,
            // r||s over a digest; Apple's newer name for it,
            // kSecKeyAlgorithmECDSASignatureDigestRFC4754, isn't bound.
            Padding::None => Algorithm::ECDSASignatureRFC4754,
        };
        hashes
            .iter()
            .map(|hash| {
                key.create_signature(algorithm, hash)
                    .map_err(|e| err("The token couldn't sign", e))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use security_framework::import_export::Pkcs12ImportOptions;
    use security_framework::os::macos::keychain::CreateOptions;

    use super::*;
    use crate::cms::SignatureAlgorithm;
    use crate::protocol::KeyUsage;
    use crate::store::Store;
    use crate::token::{self, TokenBackend};

    const RSA: &[u8] = include_bytes!("../tests/fixtures/keychain-rsa.p12");
    const P256: &[u8] = include_bytes!("../tests/fixtures/keychain-p256.p12");

    /// A throwaway keychain holding the test identities, outside the
    /// user's search list; removed when the directory is.
    fn keychain(dir: &std::path::Path) -> Keychain {
        let file = CreateOptions::new()
            .password("keyseal")
            .create(dir.join("test.keychain"))
            .unwrap();
        for identity in [RSA, P256] {
            Pkcs12ImportOptions::new()
                .passphrase("keyseal")
                .keychain(file.clone())
                .import(identity)
                .unwrap();
        }
        Keychain {
            scope: Scope::Files(vec![file]),
        }
    }

    fn temp_dir(test: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keyseal-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Verifies `signature` over `hash` with the certificate's public key.
    /// The key is rebuilt from its bytes: macOS refuses PSS verification
    /// with the certificate's own key object (CSSMERR_CSP_KEY_USAGE_INCORRECT).
    fn verifies(certificate: &[u8], algorithm: Algorithm, hash: &[u8], signature: &[u8]) -> bool {
        use core_foundation::dictionary::CFDictionary;
        use security_framework_sys::item::{
            kSecAttrKeyClass, kSecAttrKeyClassPublic, kSecAttrKeyType,
        };
        use security_framework_sys::key::SecKeyCreateWithData;

        let key = security_framework::certificate::SecCertificate::from_der(certificate)
            .unwrap()
            .public_key()
            .unwrap();
        let attribute = |name| unsafe { CFString::wrap_under_get_rule(name) };
        let key_type = key
            .attributes()
            .find(unsafe { kSecAttrKeyType }.cast())
            .map(|t| *t)
            .unwrap();
        let attributes = CFDictionary::from_CFType_pairs(&[
            (
                attribute(unsafe { kSecAttrKeyType }),
                attribute(key_type.cast()),
            ),
            (
                attribute(unsafe { kSecAttrKeyClass }),
                attribute(unsafe { kSecAttrKeyClassPublic }),
            ),
        ]);
        let mut error = std::ptr::null_mut();
        let data = key.external_representation().unwrap();
        let raw = unsafe {
            SecKeyCreateWithData(
                data.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };
        assert!(error.is_null(), "SecKeyCreateWithData failed");
        unsafe { SecKey::wrap_under_create_rule(raw) }
            .verify_signature(algorithm, hash, signature)
            .unwrap_or(false)
    }

    #[test]
    fn signs_with_keychain_identities() {
        let dir = temp_dir("sign");
        let store = Store::new(keychain(&dir), KeyUsage::NonRepudiation);
        let offered = store.certificates(false).unwrap();
        assert_eq!(offered.len(), 2, "both test identities are offered");
        let subjects: Vec<String> = offered.iter().map(|c| token::subject(&c.der)).collect();
        let pick = |name: &str| {
            offered[subjects.iter().position(|s| s.contains(name)).unwrap()]
                .der
                .clone()
        };
        let (rsa, p256) = (pick("keychain-rsa"), pick("keychain-p256"));
        let documents = [b"first".to_vec(), b"second".to_vec()];

        for (scheme, digest, verify) in [
            (
                SignatureAlgorithm::RsaPkcs1v15,
                DigestAlgorithm::Sha256,
                Algorithm::RSASignatureDigestPKCS1v15SHA256,
            ),
            (
                SignatureAlgorithm::RsaPkcs1v15,
                DigestAlgorithm::Sha384,
                Algorithm::RSASignatureDigestPKCS1v15SHA384,
            ),
            (
                SignatureAlgorithm::RsaPss,
                DigestAlgorithm::Sha256,
                Algorithm::RSASignatureDigestPSSSHA256,
            ),
        ] {
            let signatures = store.sign(&rsa, &documents, digest, scheme, None).unwrap();
            assert_eq!(signatures.len(), 2);
            for (data, signature) in documents.iter().zip(&signatures) {
                assert!(
                    verifies(&rsa, verify, &digest.digest(data), signature),
                    "{scheme:?} {digest:?}"
                );
            }
        }

        // ECDSA comes back as DER, as the CMS signature needs.
        let signatures = store
            .sign(
                &p256,
                &documents,
                DigestAlgorithm::Sha256,
                SignatureAlgorithm::Ecdsa,
                None,
            )
            .unwrap();
        for (data, signature) in documents.iter().zip(&signatures) {
            assert_eq!(signature[0], 0x30, "a DER SEQUENCE");
            assert!(verifies(
                &p256,
                Algorithm::ECDSASignatureDigestX962SHA256,
                &DigestAlgorithm::Sha256.digest(data),
                signature
            ));
        }

        // A certificate the keychain doesn't hold.
        let other = include_bytes!("../tests/fixtures/non-repudiation.der");
        assert!(
            store
                .sign(
                    other,
                    &documents,
                    DigestAlgorithm::Sha256,
                    SignatureAlgorithm::Ecdsa,
                    None
                )
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A token CryptoTokenKit exposes, as the virtual PIV card that
    /// scripts/ci/virtual-piv.sh sets up in the macOS checks job: its
    /// signing certificate is found through the token access group and
    /// counts as on a token. Signing would need the system's PIN dialog.
    #[test]
    #[ignore = "needs a token in the keychain"]
    fn finds_a_token_in_the_keychain() {
        let offered = Store::new(Keychain::tokens(), KeyUsage::NonRepudiation)
            .certificates(false)
            .unwrap();
        let subjects: Vec<String> = offered.iter().map(|c| token::subject(&c.der)).collect();
        assert!(
            subjects
                .iter()
                .any(|s| s.contains("KeySeal Virtual PIV Signer")),
            "offered: {subjects:?}"
        );
    }

    /// Software keys in a real keychain search aren't on a token, so the
    /// store offers nothing for them.
    #[test]
    fn software_keys_are_not_on_a_token() {
        let dir = temp_dir("software");
        let keychain = keychain(&dir);
        for identity in keychain.identities().unwrap() {
            let key = identity.private_key().unwrap();
            assert!(!Keychain::tokens().on_token(&key));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Reading X.509 certificates: whether one can sign, its validity period,
//! its issuer chain among other certificates, its names for display, and
//! whether it meets a job's certificate policy (section 8.2).

use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::Tag;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES;
use x509_parser::time::ASN1Time;
use x509_parser::x509::AttributeTypeAndValue;

use crate::cms::KeyKind;
use crate::protocol::{CertificatePolicy, KeyUsage, plain};

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
    if now > validity.not_after.timestamp() {
        Some(format!(
            "The certificate on your token expired on {}. Renew it with the company that issued it, then try again.",
            day_month_year(&validity.not_after)
        ))
    } else if now < validity.not_before.timestamp() {
        Some(format!(
            "The certificate on your token isn't valid until {}. Try again from that date.",
            day_month_year(&validity.not_before)
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
pub(crate) fn issuers(der: &[u8], mut others: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
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
        .map(|(_, certificate)| plain(&certificate.subject().to_string()))
        .unwrap_or_else(|_| "unreadable certificate".into())
}

/// A certificate as the chooser lists it, so that a renewed certificate
/// can be told from the one it replaces.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSummary {
    /// The subject's common name, or the whole subject without a single one.
    pub name: String,
    /// The issuer's common name, or the whole issuer without a single one.
    pub issuer: String,
    /// The last day of the validity period, as "12 March 2027".
    pub valid_until: String,
    /// The serial number's last three bytes in uppercase hex, as "4F A1 9C".
    pub serial_end: String,
}

impl CertificateSummary {
    pub fn of(der: &[u8]) -> Self {
        let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
            return Self {
                name: subject(der),
                issuer: String::new(),
                valid_until: String::new(),
                serial_end: String::new(),
            };
        };
        let name = |name: &x509_parser::x509::X509Name| {
            plain(&only_attribute(name.iter_common_name()).unwrap_or_else(|| name.to_string()))
        };
        let serial = certificate.raw_serial();
        Self {
            name: name(certificate.subject()),
            issuer: name(certificate.issuer()),
            valid_until: day_month_year(&certificate.validity().not_after),
            serial_end: serial[serial.len().saturating_sub(3)..]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" "),
        }
    }
}

/// A certificate date as "12 March 2027".
fn day_month_year(time: &ASN1Time) -> String {
    let time = time.to_datetime();
    format!("{} {} {}", time.day(), time.month(), time.year())
}

/// Whether the DER certificate satisfies every member of `policy` present.
/// The issuer CN is read from the certificate's issuer name; the server's
/// chain check binds it to the CA that signed the certificate.
pub fn meets_policy(policy: &CertificatePolicy, der: &[u8]) -> bool {
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    if let Some(oids) = &policy.policy_oids {
        let found = match certificate.get_extension_unique(&OID_X509_EXT_CERTIFICATE_POLICIES) {
            Ok(Some(extension)) => match extension.parsed_extension() {
                ParsedExtension::CertificatePolicies(policies) => policies
                    .iter()
                    .map(|policy| policy.policy_id.to_id_string())
                    .collect(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        if !oids.iter().any(|oid| found.contains(oid)) {
            return false;
        }
    }
    if let Some(names) = &policy.issuer_common_names
        && !only_attribute(certificate.issuer().iter_common_name())
            .is_some_and(|name| names.contains(&name))
    {
        return false;
    }
    if let Some(organization) = &policy.subject_organization
        && only_attribute(certificate.subject().iter_organization()).as_ref() != Some(organization)
    {
        return false;
    }
    true
}

/// The string value of a name's only attribute of one type; `None` when it
/// has none, several, or one that isn't a string type.
fn only_attribute<'a>(
    mut values: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>,
) -> Option<String> {
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    directory_string(value)
}

/// A DirectoryString in any of its encodings. x509-parser's `as_str` reads
/// only the UTF-8 compatible ones, and some CAs still issue names as
/// BMPString or TeletexString, which the server's parser reads too.
fn directory_string(value: &AttributeTypeAndValue) -> Option<String> {
    let data = value.attr_value().data;
    match value.attr_value().tag() {
        Tag::NumericString
        | Tag::PrintableString
        | Tag::VisibleString
        | Tag::Utf8String
        | Tag::Ia5String => std::str::from_utf8(data).ok().map(str::to_owned),
        Tag::BmpString if data.len() % 2 == 0 => char::decode_utf16(
            data.as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_be_bytes(pair)),
        )
        .collect::<Result<String, _>>()
        .ok(),
        Tag::UniversalString if data.len() % 4 == 0 => data
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&quad| char::from_u32(u32::from_be_bytes(quad)))
            .collect(),
        // TeletexString, read as Latin-1 the way OpenSSL and Node do.
        Tag::T61String => Some(data.iter().map(|&byte| char::from(byte)).collect()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

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

    #[test]
    fn summarises_certificates_for_the_chooser() {
        assert_eq!(
            CertificateSummary::of(SIGNER),
            CertificateSummary {
                name: "Test Signer chain".into(),
                issuer: "KeySeal Chain Sub CA".into(),
                valid_until: "1 January 2036".into(),
                serial_end: "0B 05 43".into(),
            }
        );
        // Names in BMPString read as text.
        let bmp = CertificateSummary::of(include_bytes!("../tests/fixtures/bmp-names.der"));
        assert_eq!(bmp.name, "KeySeal BMP CA");
        assert_eq!(bmp.issuer, "KeySeal BMP CA");
        let other = CertificateSummary::of(OTHER);
        assert_eq!(other.valid_until, "28 September 2126");
        assert_eq!(other.serial_end, "48 C1 46");
        assert_eq!(
            CertificateSummary::of(b"not a certificate").name,
            "unreadable certificate"
        );
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

    /// `policy.der` is issued by "KeySeal Test Sub CA" to O "Acme, Inc."
    /// with policy OIDs 2.16.356.100.2.2 and 2.16.356.100.2.3;
    /// `non-repudiation.der` is self-signed with neither O nor policies.
    #[test]
    fn matches_certificate_policies() {
        const POLICY: &[u8] = include_bytes!("../tests/fixtures/policy.der");
        const PLAIN: &[u8] = include_bytes!("../tests/fixtures/non-repudiation.der");
        let accepts = |policy: serde_json::Value, der: &[u8]| {
            meets_policy(&serde_json::from_value(policy).unwrap(), der)
        };
        assert!(accepts(
            json!({ "policyOids": ["2.16.356.100.2.3"] }),
            POLICY
        ));
        assert!(accepts(
            json!({ "policyOids": ["1.2.3", "2.16.356.100.2.2"] }),
            POLICY
        ));
        assert!(!accepts(
            json!({ "policyOids": ["2.16.356.100.2.1"] }),
            POLICY
        ));
        assert!(!accepts(
            json!({ "policyOids": ["2.16.356.100.2.3"] }),
            PLAIN
        ));
        assert!(accepts(
            json!({ "issuerCommonNames": ["Other CA", "KeySeal Test Sub CA"] }),
            POLICY
        ));
        assert!(!accepts(
            json!({ "issuerCommonNames": ["keyseal test sub ca"] }),
            POLICY
        ));
        assert!(accepts(
            json!({ "issuerCommonNames": ["signr test non-repudiation"] }),
            PLAIN
        ));
        assert!(accepts(
            json!({ "subjectOrganization": "Acme, Inc." }),
            POLICY
        ));
        assert!(!accepts(json!({ "subjectOrganization": "Acme" }), POLICY));
        assert!(!accepts(json!({ "subjectOrganization": "Acme" }), PLAIN));
        // `bmp-names.der` names its issuer and organization as BMPString.
        const BMP: &[u8] = include_bytes!("../tests/fixtures/bmp-names.der");
        assert!(accepts(
            json!({ "issuerCommonNames": ["KeySeal BMP CA"], "subjectOrganization": "Acme BMP" }),
            BMP
        ));
        let all = json!({
            "policyOids": ["2.16.356.100.2.3"],
            "issuerCommonNames": ["KeySeal Test Sub CA"],
            "subjectOrganization": "Acme, Inc.",
        });
        assert!(accepts(all.clone(), POLICY));
        let mut wrong = all;
        wrong["subjectOrganization"] = json!("Acme Inc.");
        assert!(!accepts(wrong, POLICY));
        assert!(!accepts(
            json!({ "subjectOrganization": "Acme, Inc." }),
            b"not DER"
        ));
    }
}

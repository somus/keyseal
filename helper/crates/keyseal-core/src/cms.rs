//! The CMS pieces the helper handles itself: checking the SignedAttributes
//! the server asks the token to sign (section 10), the key, digest and
//! scheme pairings of section 11, and encoding ECDSA signatures.
//!
//! The token signs whatever bytes it is given, so before the digest is shown
//! the helper checks they are attributes for a plain document, signed with
//! the posted certificate, carrying the digest it shows the user.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::asn1_rs::{Any, Class, FromDer, Tag, oid};
use x509_parser::oid_registry::{OID_EC_P256, OID_NIST_EC_P384};
use x509_parser::public_key::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DigestAlgorithm {
    Sha256,
    Sha384,
}

impl DigestAlgorithm {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    pub fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum SignatureAlgorithm {
    #[serde(rename = "rsa-pkcs1-v1_5")]
    RsaPkcs1v15,
    #[serde(rename = "rsa-pss")]
    RsaPss,
    #[serde(rename = "ecdsa")]
    Ecdsa,
}

/// The keys section 11.1 supports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    Rsa,
    P256,
    P384,
}

impl KeyKind {
    /// The kind of key in a DER certificate's SubjectPublicKeyInfo.
    pub fn of_certificate(der: &[u8]) -> Result<Self, String> {
        let (_, certificate) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| format!("Couldn't read the certificate: {e}"))?;
        let spki = certificate.public_key();
        match spki.parsed() {
            Ok(PublicKey::RSA(_)) => Ok(Self::Rsa),
            Ok(PublicKey::EC(_)) => {
                // The curve is the SubjectPublicKeyInfo's algorithm parameter.
                let curve = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|p| p.as_oid().ok());
                match curve {
                    Some(oid) if oid == OID_EC_P256 => Ok(Self::P256),
                    Some(oid) if oid == OID_NIST_EC_P384 => Ok(Self::P384),
                    _ => Err("The certificate's EC key isn't on P-256 or P-384.".into()),
                }
            }
            _ => Err("The certificate's key is neither RSA nor EC.".into()),
        }
    }

    /// Checks `digest` and `signature` suit this key (section 11.1).
    pub fn check(
        self,
        digest: DigestAlgorithm,
        signature: SignatureAlgorithm,
    ) -> Result<(), String> {
        use {DigestAlgorithm as D, SignatureAlgorithm as S};
        match (self, signature, digest) {
            (Self::Rsa, S::RsaPkcs1v15 | S::RsaPss, _)
            | (Self::P256, S::Ecdsa, D::Sha256)
            | (Self::P384, S::Ecdsa, D::Sha384) => Ok(()),
            _ => Err(format!(
                "The server asked for {signature:?} with {digest:?}, which a {self:?} key doesn't sign."
            )),
        }
    }
}

const CONTENT_TYPE: &[u8] = &oid!(raw 1.2.840.113549.1.9.3);
const MESSAGE_DIGEST: &[u8] = &oid!(raw 1.2.840.113549.1.9.4);
const SIGNING_TIME: &[u8] = &oid!(raw 1.2.840.113549.1.9.5);
const SIGNING_CERTIFICATE_V2: &[u8] = &oid!(raw 1.2.840.113549.1.9.16.2.47);
const ALGORITHM_PROTECTION: &[u8] = &oid!(raw 1.2.840.113549.1.9.52);
const ID_DATA: &[u8] = &oid!(raw 1.2.840.113549.1.7.1);
const SHA256: &[u8] = &oid!(raw 2.16.840.1.101.3.4.2.1);

/// The next DER element of `input`, which must be the universal `tag`,
/// constructed only for SEQUENCE and SET, with a minimal length.
fn element(input: &[u8], tag: Tag) -> Result<(Any<'_>, &[u8]), String> {
    let (rest, any) = Any::from_der(input).map_err(|e| format!("not DER ({e})"))?;
    if any.class() != Class::Universal || any.tag() != tag {
        return Err(format!("expected {tag:?}, found {:?}", any.tag()));
    }
    // asn1-rs accepts non-minimal lengths and compares only the tag number.
    let constructed = if matches!(tag, Tag::Sequence | Tag::Set) {
        0x20
    } else {
        0
    };
    if der_tlv(tag.0 as u8 | constructed, any.data) != input[..input.len() - rest.len()] {
        return Err(format!("{tag:?} isn't DER encoded"));
    }
    Ok((any, rest))
}

/// `input` holding exactly one DER element, of the universal `tag`.
fn only(input: &[u8], tag: Tag) -> Result<Any<'_>, String> {
    let (any, rest) = element(input, tag)?;
    if !rest.is_empty() {
        return Err("unexpected trailing data".into());
    }
    Ok(any)
}

/// Checks `to_sign` is DER SignedAttributes for id-data content, with a
/// `digest`-sized messageDigest and a signing-certificate-v2 naming the
/// certificate whose DER has SHA-256 `certificate_sha256`. Returns the
/// messageDigest.
pub fn check_signed_attributes(
    to_sign: &[u8],
    digest: DigestAlgorithm,
    certificate_sha256: &[u8],
) -> Result<Vec<u8>, String> {
    let attributes = only(to_sign, Tag::Set)?;
    let mut content_type = None;
    let mut message_digest = None;
    let mut signing_certificate = None;
    let mut signing_time = None;
    let mut algorithm_protection = None;
    let mut previous: &[u8] = &[];
    let mut input = attributes.data;
    while !input.is_empty() {
        let (attribute, rest) = element(input, Tag::Sequence)?;
        // DER sorts SET OF by encoding; distinct complete TLVs are never
        // prefixes of each other, so plain byte order matches X.690's.
        let encoding = &input[..input.len() - rest.len()];
        if encoding < previous {
            return Err("the attributes aren't in DER order".into());
        }
        previous = encoding;
        input = rest;
        let (oid, values) = element(attribute.data, Tag::Oid)?;
        let values = only(values, Tag::Set)?;
        let slot = match oid.data {
            CONTENT_TYPE => &mut content_type,
            MESSAGE_DIGEST => &mut message_digest,
            SIGNING_CERTIFICATE_V2 => &mut signing_certificate,
            SIGNING_TIME => &mut signing_time,
            ALGORITHM_PROTECTION => &mut algorithm_protection,
            _ => {
                let name = oid.as_oid().map(|o| o.to_id_string()).unwrap_or_default();
                return Err(format!("unexpected attribute {name}"));
            }
        };
        if slot.replace(values.data).is_some() {
            return Err("an attribute appears twice".into());
        }
    }

    if let Some(values) = signing_time {
        // UTCTime YYMMDDHHMMSSZ or GeneralizedTime YYYYMMDDHHMMSSZ.
        let (time, digits) = only(values, Tag::UtcTime)
            .map(|t| (t.data, 12))
            .or_else(|_| only(values, Tag::GeneralizedTime).map(|t| (t.data, 14)))
            .map_err(|_| "signingTime isn't one time")?;
        if time.len() != digits + 1
            || !time[..digits].iter().all(u8::is_ascii_digit)
            || time[digits] != b'Z'
        {
            return Err("signingTime isn't a DER time".into());
        }
    }
    if let Some(values) = algorithm_protection {
        only(values, Tag::Sequence)
            .map_err(|e| format!("cmsAlgorithmProtection isn't one value: {e}"))?;
    }

    let content_type = content_type.ok_or("contentType is missing")?;
    if only(content_type, Tag::Oid)?.data != ID_DATA {
        return Err("contentType isn't id-data".into());
    }

    let message_digest = only(
        message_digest.ok_or("messageDigest is missing")?,
        Tag::OctetString,
    )?;
    if message_digest.data.len() != digest.size() {
        return Err(format!("messageDigest isn't a {digest:?} digest"));
    }

    // SigningCertificateV2 ::= SEQUENCE {
    //     certs SEQUENCE OF ESSCertIDv2, policies SEQUENCE OF PolicyInformation OPTIONAL }
    let signing_certificate = only(
        signing_certificate.ok_or("signing-certificate-v2 is missing")?,
        Tag::Sequence,
    )?;
    let (certs, policies) = element(signing_certificate.data, Tag::Sequence)?;
    if !policies.is_empty() {
        only(policies, Tag::Sequence)?;
    }
    let mut input = certs.data;
    let mut signer = None;
    while !input.is_empty() {
        let (cert_id, rest) = element(input, Tag::Sequence)?;
        // The first ESSCertIDv2 names the signing certificate.
        signer.get_or_insert(ess_cert_id_v2(cert_id.data)?);
        input = rest;
    }
    if signer != Some(certificate_sha256) {
        return Err("signing-certificate-v2 names another certificate".into());
    }

    Ok(message_digest.data.to_vec())
}

/// The certHash of the ESSCertIDv2 contents `fields`:
/// SEQUENCE { hashAlgorithm AlgorithmIdentifier DEFAULT sha256,
///   certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL }.
fn ess_cert_id_v2(mut fields: &[u8]) -> Result<&[u8], String> {
    if let Ok((algorithm, rest)) = element(fields, Tag::Sequence) {
        // AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL OPTIONAL }
        let (oid, parameters) = element(algorithm.data, Tag::Oid)?;
        if oid.data != SHA256 {
            return Err("signing-certificate-v2 doesn't use SHA-256".into());
        }
        if !parameters.is_empty() && !only(parameters, Tag::Null)?.data.is_empty() {
            return Err("signing-certificate-v2 has hash parameters".into());
        }
        fields = rest;
    }
    let (cert_hash, rest) = element(fields, Tag::OctetString)?;
    if !rest.is_empty() {
        // IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
        let issuer_serial = only(rest, Tag::Sequence)?;
        let (_, serial) = element(issuer_serial.data, Tag::Sequence)?;
        only(serial, Tag::Integer)?;
    }
    Ok(cert_hash.data)
}

pub fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - start) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
    out.extend_from_slice(content);
    out
}

fn der_unsigned(bytes: &[u8]) -> Vec<u8> {
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let mut value = bytes[start..].to_vec();
    if value.first().is_none_or(|&b| b & 0x80 != 0) {
        value.insert(0, 0);
    }
    der_tlv(0x02, &value)
}

/// CKM_ECDSA returns r||s, `len` bytes for the curve (64 for P-256, 96 for
/// P-384); CMS carries ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }.
pub fn ecdsa_signature(raw: &[u8], len: usize) -> Result<Vec<u8>, String> {
    if raw.len() != len {
        return Err(format!(
            "The token returned a {}-byte ECDSA signature where the key's curve gives {len} bytes.",
            raw.len()
        ));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    Ok(der_tlv(0x30, &[der_unsigned(r), der_unsigned(s)].concat()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERTIFICATE: &[u8] = b"certificate DER";

    // SignedAttributes from pyHanko through the signing service's
    // remote_sign.start, for test-PKI certificates with these DER SHA-256s.
    const PYHANKO_RSA_2048: &str = "3181c7301806092a864886f70d010903310b06092a864886f70d010701302f06092a864886f70d010904312204203377caaab79d57ab6793eea38d635ab2459187890853259f4bcc32ef6dcbf12c307a060b2a864886f70d010910022f316b3069306730650420fc0b4f11c16cd92070168a3758cf2bf76e29f986451c28693cbc6f1e06c7a1ae30413029a4273025310b300906035504061302494e3116301406035504030c0d546573742043434120526f6f7402140481f76e262eacddaaccac8c9d02d69973789852";
    const PYHANKO_RSA_2048_CERTIFICATE: &str =
        "fc0b4f11c16cd92070168a3758cf2bf76e29f986451c28693cbc6f1e06c7a1ae";
    const PYHANKO_P256: &str = "3181c7301806092a864886f70d010903310b06092a864886f70d010701302f06092a864886f70d010904312204203699e80a88bb4724bf78b46a008b323c38d4c9cc609abe46eadc229d50915e3b307a060b2a864886f70d010910022f316b3069306730650420b2a304324bcdc86c4718a56f6b9aa3a18d738f6ad8ae379f7def1094fd362bf830413029a4273025310b300906035504061302494e3116301406035504030c0d546573742043434120526f6f7402146b5b3811274a5308fb608e41dcfd097bf4d228ce";
    const PYHANKO_P256_CERTIFICATE: &str =
        "b2a304324bcdc86c4718a56f6b9aa3a18d738f6ad8ae379f7def1094fd362bf8";
    const PYHANKO_P384: &str = "3181d7301806092a864886f70d010903310b06092a864886f70d010701303f06092a864886f70d010904313204301294015f28c9203519942934b3442f6c1a7f08d88e682cf94880e9ff2e9f689439dd995180b602f0618b4783d45c23e4307a060b2a864886f70d010910022f316b3069306730650420fdd81d4c45cca1a34a4890176ebacd356413f671740e79fe5c4026e2dee95d8c30413029a4273025310b300906035504061302494e3116301406035504030c0d546573742043434120526f6f7402142256eed9eb6f8a8fc3c2eee7fde49fc29a9ddd37";
    const PYHANKO_P384_CERTIFICATE: &str =
        "fdd81d4c45cca1a34a4890176ebacd356413f671740e79fe5c4026e2dee95d8c";

    #[test]
    fn accepts_pyhanko_attributes() {
        for (to_sign, certificate, digest, message_digest) in [
            (
                PYHANKO_RSA_2048,
                PYHANKO_RSA_2048_CERTIFICATE,
                DigestAlgorithm::Sha256,
                "3377caaab79d57ab6793eea38d635ab2459187890853259f4bcc32ef6dcbf12c",
            ),
            (
                PYHANKO_P256,
                PYHANKO_P256_CERTIFICATE,
                DigestAlgorithm::Sha256,
                "3699e80a88bb4724bf78b46a008b323c38d4c9cc609abe46eadc229d50915e3b",
            ),
            (
                PYHANKO_P384,
                PYHANKO_P384_CERTIFICATE,
                DigestAlgorithm::Sha384,
                "1294015f28c9203519942934b3442f6c1a7f08d88e682cf94880e9ff2e9f689439dd995180b602f0618b4783d45c23e4",
            ),
        ] {
            let to_sign = hex::decode(to_sign).unwrap();
            let certificate = hex::decode(certificate).unwrap();
            assert_eq!(
                hex::encode(check_signed_attributes(&to_sign, digest, &certificate).unwrap()),
                message_digest
            );
        }
        let to_sign = hex::decode(PYHANKO_RSA_2048).unwrap();
        let other = hex::decode(PYHANKO_P256_CERTIFICATE).unwrap();
        assert!(check_signed_attributes(&to_sign, DigestAlgorithm::Sha256, &other).is_err());
        let to_sign = hex::decode(PYHANKO_P384).unwrap();
        let certificate = hex::decode(PYHANKO_P384_CERTIFICATE).unwrap();
        assert!(check_signed_attributes(&to_sign, DigestAlgorithm::Sha256, &certificate).is_err());
    }

    fn oid(raw: &[u8]) -> Vec<u8> {
        der_tlv(0x06, raw)
    }

    fn attribute(oid_raw: &[u8], value: Vec<u8>) -> Vec<u8> {
        der_tlv(0x30, &[oid(oid_raw), der_tlv(0x31, &value)].concat())
    }

    fn signing_certificate(hash_algorithm: Option<&[u8]>, cert_hash: &[u8]) -> Vec<u8> {
        let algorithm = hash_algorithm
            .map(|raw| der_tlv(0x30, &[oid(raw), vec![0x05, 0x00]].concat()))
            .unwrap_or_default();
        let cert_id = der_tlv(0x30, &[algorithm, der_tlv(0x04, cert_hash)].concat());
        attribute(
            SIGNING_CERTIFICATE_V2,
            der_tlv(0x30, &der_tlv(0x30, &cert_id)),
        )
    }

    /// The SET OF in DER order.
    fn signed_attributes(attributes: &[Vec<u8>]) -> Vec<u8> {
        let mut attributes = attributes.to_vec();
        attributes.sort();
        der_tlv(0x31, &attributes.concat())
    }

    fn valid(digest_len: usize) -> Vec<Vec<u8>> {
        vec![
            attribute(CONTENT_TYPE, oid(ID_DATA)),
            attribute(SIGNING_TIME, der_tlv(0x17, b"261022120000Z")),
            attribute(MESSAGE_DIGEST, der_tlv(0x04, &vec![0xab; digest_len])),
            attribute(ALGORITHM_PROTECTION, der_tlv(0x30, &[])),
            signing_certificate(None, &Sha256::digest(CERTIFICATE)),
        ]
    }

    fn check(attributes: &[Vec<u8>], digest: DigestAlgorithm) -> Result<Vec<u8>, String> {
        check_signed_attributes(
            &signed_attributes(attributes),
            digest,
            &Sha256::digest(CERTIFICATE),
        )
    }

    #[test]
    fn accepts_rsa_sha256_attributes() {
        assert_eq!(
            check(&valid(32), DigestAlgorithm::Sha256).unwrap(),
            vec![0xab; 32]
        );
    }

    #[test]
    fn accepts_ec_sha384_attributes_with_explicit_hash_algorithm() {
        let mut attributes = valid(48);
        attributes[4] = signing_certificate(Some(SHA256), &Sha256::digest(CERTIFICATE));
        assert_eq!(
            check(&attributes, DigestAlgorithm::Sha384).unwrap(),
            vec![0xab; 48]
        );
    }

    #[test]
    fn refuses_wrong_content_type() {
        let mut attributes = valid(32);
        attributes[0] = attribute(CONTENT_TYPE, oid(&oid!(raw 1.2.840.113549.1.7.2)));
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());
    }

    #[test]
    fn refuses_missing_message_digest() {
        let mut attributes = valid(32);
        attributes.remove(2);
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());
    }

    #[test]
    fn refuses_digest_length_mismatch() {
        assert!(check(&valid(32), DigestAlgorithm::Sha384).is_err());
        assert!(check(&valid(48), DigestAlgorithm::Sha256).is_err());
    }

    #[test]
    fn refuses_wrong_cert_hash() {
        let mut attributes = valid(32);
        attributes[4] = signing_certificate(None, &Sha256::digest(b"another certificate"));
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());
        attributes[4] = signing_certificate(
            Some(&oid!(raw 2.16.840.1.101.3.4.2.2)),
            &Sha256::digest(CERTIFICATE),
        );
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());
    }

    #[test]
    fn refuses_unexpected_or_repeated_attributes() {
        let mut attributes = valid(32);
        attributes.push(attribute(
            &oid!(raw 1.2.840.113549.1.9.15),
            der_tlv(0x30, &[]),
        ));
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());

        let mut attributes = valid(32);
        attributes.push(attribute(CONTENT_TYPE, oid(ID_DATA)));
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());
    }

    #[test]
    fn refuses_non_set_or_trailing_data() {
        let mut bytes = signed_attributes(&valid(32));
        bytes[0] = 0xa0;
        assert!(
            check_signed_attributes(
                &bytes,
                DigestAlgorithm::Sha256,
                &Sha256::digest(CERTIFICATE)
            )
            .is_err()
        );
        let mut bytes = signed_attributes(&valid(32));
        bytes.push(0);
        assert!(
            check_signed_attributes(
                &bytes,
                DigestAlgorithm::Sha256,
                &Sha256::digest(CERTIFICATE)
            )
            .is_err()
        );
    }

    fn error(attributes: &[u8]) -> String {
        check_signed_attributes(
            attributes,
            DigestAlgorithm::Sha256,
            &Sha256::digest(CERTIFICATE),
        )
        .unwrap_err()
    }

    #[test]
    fn refuses_non_minimal_lengths() {
        let bytes = signed_attributes(&valid(32));
        assert_eq!(bytes[1], 0x81);
        let long = [&[0x31, 0x82, 0x00, bytes[2]], &bytes[3..]].concat();
        assert_eq!(error(&long), "Tag(17) isn't DER encoded");

        let mut attributes = valid(32);
        attributes[2] = attribute(
            MESSAGE_DIGEST,
            [&[0x04, 0x81, 0x20], &[0xab; 32][..]].concat(),
        );
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "Tag(4) isn't DER encoded"
        );
    }

    #[test]
    fn refuses_constructed_octet_string() {
        let mut attributes = valid(32);
        attributes[2] = attribute(MESSAGE_DIGEST, der_tlv(0x24, &[0xab; 32]));
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "Tag(4) isn't DER encoded"
        );
    }

    #[test]
    fn refuses_attributes_out_of_der_order() {
        let mut attributes = valid(32);
        attributes.sort();
        attributes.reverse();
        assert_eq!(
            error(&der_tlv(0x31, &attributes.concat())),
            "the attributes aren't in DER order"
        );
    }

    #[test]
    fn refuses_repeated_or_empty_signing_time_and_protection() {
        let mut attributes = valid(32);
        attributes.push(attribute(SIGNING_TIME, der_tlv(0x17, b"261023120000Z")));
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "an attribute appears twice"
        );

        let mut attributes = valid(32);
        attributes.push(attribute(
            ALGORITHM_PROTECTION,
            der_tlv(0x30, &[0x05, 0x00]),
        ));
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "an attribute appears twice"
        );

        let mut attributes = valid(32);
        attributes[1] = attribute(SIGNING_TIME, vec![]);
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "signingTime isn't one time"
        );
        attributes[1] = attribute(
            SIGNING_TIME,
            [
                der_tlv(0x17, b"261022120000Z"),
                der_tlv(0x17, b"261023120000Z"),
            ]
            .concat(),
        );
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "signingTime isn't one time"
        );

        let mut attributes = valid(32);
        attributes[3] = attribute(ALGORITHM_PROTECTION, vec![]);
        assert!(error(&signed_attributes(&attributes)).starts_with("cmsAlgorithmProtection"));
    }

    fn signing_certificate_v2(certs: &[u8], trailing: &[u8]) -> Vec<u8> {
        attribute(
            SIGNING_CERTIFICATE_V2,
            der_tlv(0x30, &[der_tlv(0x30, certs), trailing.to_vec()].concat()),
        )
    }

    fn issuer_serial() -> Vec<u8> {
        let name = der_tlv(0xa4, &der_tlv(0x30, &[]));
        der_tlv(
            0x30,
            &[der_tlv(0x30, &name), der_tlv(0x02, &[0x01])].concat(),
        )
    }

    #[test]
    fn accepts_issuer_serial_and_policies() {
        let cert_hash = der_tlv(0x04, &Sha256::digest(CERTIFICATE));
        let mut attributes = valid(32);
        attributes[4] = signing_certificate_v2(
            &der_tlv(0x30, &[cert_hash, issuer_serial()].concat()),
            &der_tlv(0x30, &[]),
        );
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_ok());
    }

    #[test]
    fn refuses_malformed_signing_certificate() {
        let cert_hash = der_tlv(0x04, &Sha256::digest(CERTIFICATE));
        let mut attributes = valid(32);

        attributes[4] = signing_certificate_v2(
            &der_tlv(0x30, &[cert_hash.clone(), vec![0xde, 0xad]].concat()),
            &[],
        );
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());

        let serial = issuer_serial();
        let long = [&[0x30, 0x81, serial[1]], &serial[2..]].concat();
        attributes[4] =
            signing_certificate_v2(&der_tlv(0x30, &[cert_hash.clone(), long].concat()), &[]);
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "Tag(16) isn't DER encoded"
        );

        attributes[4] = signing_certificate_v2(
            &der_tlv(
                0x30,
                &[cert_hash.clone(), issuer_serial(), vec![0x05, 0x00]].concat(),
            ),
            &[],
        );
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());

        attributes[4] = signing_certificate_v2(&der_tlv(0x30, &cert_hash), &[0x00]);
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_err());
    }

    #[test]
    fn refuses_signing_time_that_isnt_a_time() {
        let mut attributes = valid(32);
        for time in [
            der_tlv(0x17, b"not a time!!Z"),
            der_tlv(0x17, b"2610221200Z"),
            der_tlv(0x17, b"261022120000+0000"),
            der_tlv(0x18, b"261022120000Z"),
        ] {
            attributes[1] = attribute(SIGNING_TIME, time);
            assert_eq!(
                error(&signed_attributes(&attributes)),
                "signingTime isn't a DER time"
            );
        }
        attributes[1] = attribute(SIGNING_TIME, der_tlv(0x18, b"20261022120000Z"));
        assert!(check(&attributes, DigestAlgorithm::Sha256).is_ok());
    }

    #[test]
    fn refuses_several_message_digests() {
        let mut attributes = valid(32);
        attributes[2] = attribute(
            MESSAGE_DIGEST,
            [der_tlv(0x04, &[0xab; 32]), der_tlv(0x04, &[0xcd; 32])].concat(),
        );
        assert_eq!(
            error(&signed_attributes(&attributes)),
            "unexpected trailing data"
        );
    }

    #[test]
    fn encodes_ecdsa_signatures() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80;
        raw[31] = 0x01;
        raw[33] = 0x7f;
        let mut expected = vec![0x30, 0x44, 0x02, 0x21, 0x00, 0x80];
        expected.extend_from_slice(&[0; 30]);
        expected.extend_from_slice(&[0x01, 0x02, 0x1f, 0x7f]);
        expected.extend_from_slice(&[0; 30]);
        assert_eq!(ecdsa_signature(&raw, 64).unwrap(), expected);
        assert_eq!(
            ecdsa_signature(&[0; 64], 64).unwrap(),
            [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
        assert_eq!(
            &ecdsa_signature(&[0xff; 96], 96).unwrap()[..5],
            [0x30, 0x66, 0x02, 0x31, 0x00]
        );
    }

    #[test]
    fn pairs_keys_digests_and_schemes() {
        use {DigestAlgorithm as D, KeyKind as K, SignatureAlgorithm as S};
        for (key, digest, signature) in [
            (K::Rsa, D::Sha256, S::RsaPkcs1v15),
            (K::Rsa, D::Sha384, S::RsaPkcs1v15),
            (K::Rsa, D::Sha256, S::RsaPss),
            (K::Rsa, D::Sha384, S::RsaPss),
            (K::P256, D::Sha256, S::Ecdsa),
            (K::P384, D::Sha384, S::Ecdsa),
        ] {
            assert!(
                key.check(digest, signature).is_ok(),
                "{key:?} {digest:?} {signature:?}"
            );
        }
        for (key, digest, signature) in [
            (K::Rsa, D::Sha256, S::Ecdsa),
            (K::P256, D::Sha384, S::Ecdsa),
            (K::P384, D::Sha256, S::Ecdsa),
            (K::P256, D::Sha256, S::RsaPkcs1v15),
            (K::P384, D::Sha384, S::RsaPss),
        ] {
            assert!(
                key.check(digest, signature).is_err(),
                "{key:?} {digest:?} {signature:?}"
            );
        }
    }

    #[test]
    fn parses_algorithm_names() {
        let parse = |name: &str| serde_json::from_value::<SignatureAlgorithm>(name.into());
        assert_eq!(
            parse("rsa-pkcs1-v1_5").unwrap(),
            SignatureAlgorithm::RsaPkcs1v15
        );
        assert_eq!(parse("rsa-pss").unwrap(), SignatureAlgorithm::RsaPss);
        assert_eq!(parse("ecdsa").unwrap(), SignatureAlgorithm::Ecdsa);
        assert!(parse("ed25519").is_err());
        let digest = |name: &str| serde_json::from_value::<DigestAlgorithm>(name.into());
        assert_eq!(digest("sha384").unwrap(), DigestAlgorithm::Sha384);
        assert!(digest("sha512").is_err());
    }

    #[test]
    fn refuses_ecdsa_signatures_of_the_wrong_length() {
        for (len, expected) in [(63, 64), (96, 64), (64, 96), (0, 64)] {
            assert_eq!(
                ecdsa_signature(&vec![1; len], expected).unwrap_err(),
                format!(
                    "The token returned a {len}-byte ECDSA signature where the key's curve gives {expected} bytes."
                )
            );
        }
    }
}

//! The `keyseal://` link (section 3) and the job endpoint client (section 8).

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use ureq::Agent;
use url::Url;
use x509_parser::der_parser::asn1_rs::Tag;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::OID_X509_EXT_CERTIFICATE_POLICIES;
use x509_parser::x509::AttributeTypeAndValue;

use crate::cms::{DigestAlgorithm, SignatureAlgorithm};
use crate::origin::Origin;

pub const VERSION_HEADER: &str = "X-KeySeal-Version";
const MAX_LINK_BYTES: usize = 2048;
/// Job endpoint requests wait this long. Round 1 and the server's finish
/// call the signing service, which the server waits up to 60 seconds for
/// (timestamping included), so the helper allows that plus overhead.
const JOB_TIMEOUT: Duration = Duration::from_secs(90);
/// Largest job endpoint response read, the request body limit of 8.1.
const MAX_RESPONSE_BYTES: u64 = 262_144;
/// Document download budget and size limits (section 8.4): each document,
/// and a job's documents together.
const DOCUMENT_TIMEOUT: Duration = Duration::from_secs(60);
pub const MAX_DOCUMENT_BYTES: u64 = 67_108_864;
pub const MAX_JOB_DOCUMENT_BYTES: u64 = 268_435_456;
/// A sign job's documents (section 8.2).
pub const MAX_DOCUMENTS: usize = 20;
const MAX_CHAIN: usize = 8;
const MAX_FAILURE_CHARS: usize = 500;
/// Limits of a certificate policy (section 8.2).
const MAX_POLICY_ENTRIES: usize = 16;
const MAX_OID_CHARS: usize = 128;
const MAX_NAME_CHARS: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Sign,
    Enrol,
}

#[derive(Clone, Debug)]
pub struct Link {
    pub kind: Kind,
    pub job_url: Url,
    pub origin: Origin,
}

/// `^[A-Za-z0-9_-]{20,128}$`, the token and claim nonce charset.
pub fn is_token(value: &str) -> bool {
    (20..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validates a link as section 3.3 requires, before any network request.
pub fn parse_link(link: &str, allow_insecure: bool) -> Result<Link, String> {
    if link.len() > MAX_LINK_BYTES {
        return Err("The KeySeal link is longer than 2048 bytes.".into());
    }
    let url = Url::parse(link).map_err(|e| format!("The KeySeal link isn't a URL: {e}"))?;
    if url.scheme() != "keyseal" {
        return Err("Not a keyseal:// link.".into());
    }
    let kind = match url.host_str() {
        Some("sign") => Kind::Sign,
        Some("enrol") => Kind::Enrol,
        _ => return Err("The KeySeal link's action must be sign or enrol.".into()),
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err("The KeySeal link has more than an action and a job.".into());
    }
    let jobs: Vec<String> = url
        .query_pairs()
        .filter(|(key, _)| key == "job")
        .map(|(_, value)| value.into_owned())
        .collect();
    let [job] = jobs.as_slice() else {
        return Err("The KeySeal link must carry exactly one job.".into());
    };
    let job_url = Url::parse(job).map_err(|e| format!("The job URL isn't a URL: {e}"))?;
    let origin = Origin::of_url(&job_url, allow_insecure)?;
    if !job_url.username().is_empty()
        || job_url.password().is_some()
        || job_url.query().is_some()
        || job_url.fragment().is_some()
    {
        return Err("The job URL can't carry a user, query or fragment.".into());
    }
    // <base>/v1/jobs/<token>, where <base> is empty or /segments.
    let segments: Vec<&str> = job_url.path().split('/').skip(1).collect();
    let valid = match segments.as_slice() {
        [.., "v1", "jobs", token] => {
            is_token(token) && segments.iter().all(|segment| !segment.is_empty())
        }
        _ => false,
    };
    if !valid {
        return Err("The job URL isn't a KeySeal v1 job URL.".into());
    }
    Ok(Link {
        kind,
        job_url,
        origin,
    })
}

/// Server text shown as plain text, without bidirectional or other
/// control characters (section 12.4).
pub fn plain(text: &str) -> String {
    text.chars()
        .filter(|&c| {
            !(c.is_control() && c != '\n'
                || matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}')
                || ('\u{202a}'..='\u{202e}').contains(&c)
                || ('\u{2066}'..='\u{2069}').contains(&c))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobDescription {
    pub kind: Kind,
    pub title: String,
    pub signer: String,
    pub claim_nonce: String,
    pub expected_certificate_sha256: Option<String>,
    pub certificate_policy: Option<CertificatePolicy>,
    pub digest_algorithm: Option<DigestAlgorithm>,
    /// Present on sign jobs, with 1 to 20 entries, once checked.
    #[serde(default)]
    pub documents: Vec<DocumentEntry>,
}

/// One document of a sign job (section 8.2).
#[derive(Debug, Deserialize)]
pub struct DocumentEntry {
    pub title: String,
    /// The job URL followed by `/documents/<index>`.
    pub document: String,
}

/// What a certificate must show for the job (section 8.2): every member
/// present must hold, and strings compare exactly.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePolicy {
    pub policy_oids: Option<Vec<String>>,
    pub issuer_common_names: Option<Vec<String>>,
    pub subject_organization: Option<String>,
}

impl CertificatePolicy {
    fn check(&self) -> Result<(), String> {
        let lists = [
            ("policyOids", &self.policy_oids, MAX_OID_CHARS),
            (
                "issuerCommonNames",
                &self.issuer_common_names,
                MAX_NAME_CHARS,
            ),
        ];
        for (name, list, max) in lists {
            if let Some(list) = list
                && !((1..=MAX_POLICY_ENTRIES).contains(&list.len())
                    && list
                        .iter()
                        .all(|value| (1..=max).contains(&value.chars().count())))
            {
                return Err(format!("its certificatePolicy has a malformed {name}"));
            }
        }
        if let Some(oids) = &self.policy_oids
            && !oids.iter().all(|oid| is_oid(oid))
        {
            return Err("its certificatePolicy has an OID that isn't dotted decimal".into());
        }
        if let Some(organization) = &self.subject_organization
            && !(1..=MAX_NAME_CHARS).contains(&organization.chars().count())
        {
            return Err("its certificatePolicy has a malformed subjectOrganization".into());
        }
        Ok(())
    }

    /// Whether the DER certificate satisfies every member present. The
    /// issuer CN is read from the certificate's issuer name; the server's
    /// chain check binds it to the CA that signed the certificate.
    pub fn accepts(&self, der: &[u8]) -> bool {
        let Ok((_, certificate)) = x509_parser::parse_x509_certificate(der) else {
            return false;
        };
        if let Some(oids) = &self.policy_oids {
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
        if let Some(names) = &self.issuer_common_names
            && !only(certificate.issuer().iter_common_name())
                .is_some_and(|name| names.contains(&name))
        {
            return false;
        }
        if let Some(organization) = &self.subject_organization
            && only(certificate.subject().iter_organization()).as_ref() != Some(organization)
        {
            return false;
        }
        true
    }
}

/// The string value of a name's only attribute of one type; `None` when it
/// has none, several, or one that isn't a string type.
fn only<'a>(mut values: impl Iterator<Item = &'a AttributeTypeAndValue<'a>>) -> Option<String> {
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

/// A dotted-decimal OID (section 8.2): a first arc of 0 to 2, then at least
/// one more, each without leading zeros.
fn is_oid(text: &str) -> bool {
    let mut arcs = text.split('.');
    matches!(arcs.next(), Some("0" | "1" | "2"))
        && arcs.clone().next().is_some()
        && arcs.all(|arc| {
            !arc.is_empty()
                && arc.bytes().all(|b| b.is_ascii_digit())
                && (arc == "0" || !arc.starts_with('0'))
        })
}

impl JobDescription {
    /// Section 8.2's checks, `job_url` being the URL the job was claimed at.
    fn check(mut self, job_url: &str) -> Result<Self, String> {
        self.title = plain(&self.title);
        self.signer = plain(&self.signer);
        for document in &mut self.documents {
            document.title = plain(&document.title);
        }
        let titles = self
            .documents
            .iter()
            .map(|d| ("a document title", &d.title));
        for (name, value) in [("title", &self.title), ("signer", &self.signer)]
            .into_iter()
            .chain(titles)
        {
            if !(1..=200).contains(&value.chars().count()) {
                return Err(format!("its {name} isn't 1 to 200 characters"));
            }
        }
        if !is_token(&self.claim_nonce) {
            return Err("its claimNonce is malformed".into());
        }
        // Required for sign jobs (8.2), and checked here so the login-first
        // path doesn't ask for the PIN before finding out.
        if self.kind == Kind::Sign {
            if !(1..=MAX_DOCUMENTS).contains(&self.documents.len()) {
                return Err(format!(
                    "it is a sign job without 1 to {MAX_DOCUMENTS} documents"
                ));
            }
            for (index, document) in self.documents.iter().enumerate() {
                if !same_url(&document.document, &format!("{job_url}/documents/{index}")) {
                    return Err(format!(
                        "the URL of its document {} isn't the job's",
                        index + 1
                    ));
                }
            }
        }
        if let Some(hash) = &self.expected_certificate_sha256
            && !(hash.len() == 64 && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err("its expectedCertificateSha256 isn't 64 lowercase hex".into());
        }
        if let Some(policy) = &self.certificate_policy {
            policy.check()?;
        }
        Ok(self)
    }
}

/// Whether `url` parses to `expected`, which compares them in the form the
/// URL parser normalises to.
fn same_url(url: &str, expected: &str) -> bool {
    matches!((Url::parse(url), Url::parse(expected)), (Ok(url), Ok(expected)) if url == expected)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedSignatureBody {
    digest_algorithm: DigestAlgorithm,
    signature_algorithm: SignatureAlgorithm,
    documents: Vec<PreparedDocumentBody>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreparedDocumentBody {
    to_sign: String,
}

/// Sign round 1's answer, each document's `toSign` decoded, in order.
#[derive(Debug)]
pub struct PreparedSignature {
    pub digest_algorithm: DigestAlgorithm,
    pub signature_algorithm: SignatureAlgorithm,
    pub to_sign: Vec<Vec<u8>>,
}

#[derive(Deserialize)]
struct Empty {}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ErrorBody {
    message: Option<String>,
    min_version: Option<String>,
}

/// A request that didn't succeed. `status` is the HTTP status when the
/// server answered; `message` is written for the user and names the origin.
#[derive(Debug)]
pub struct ProtocolError {
    pub status: Option<u16>,
    pub message: String,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProtocolError {}

/// What each status of section 8.8 means for the user.
fn meaning(status: u16) -> &'static str {
    match status {
        403 => "The server didn't accept the helper's request for the document.",
        404 => "The job doesn't exist or has expired.",
        409 => "The job was already claimed, or isn't ready for this step.",
        410 => "The job is already completed or failed.",
        413 => "The request was too large for the server.",
        422 => "The server refused the request.",
        426 => "This helper is too old for the server.",
        429 => "The server is busy. Try again in a moment.",
        _ => "The server gave an unexpected answer.",
    }
}

pub struct JobClient {
    agent: Agent,
    url: String,
    token: String,
    origin: Origin,
}

impl JobClient {
    pub fn new(link: &Link) -> Self {
        let token = link.job_url.path().rsplit('/').next().unwrap_or_default();
        Self {
            agent: link.origin.agent(JOB_TIMEOUT),
            url: link.job_url.as_str().to_owned(),
            token: token.to_owned(),
            origin: link.origin.clone(),
        }
    }

    /// Claims the job (8.2). When the answer carries a well-formed nonce but
    /// fails the helper's checks, the job is claimed, so the failure is
    /// reported before returning.
    pub fn claim(&self) -> Result<JobDescription, ProtocolError> {
        let sent = self
            .agent
            .get(&self.url)
            .header(VERSION_HEADER, crate::VERSION)
            .call();
        let value: serde_json::Value = self.reply(sent)?;
        let nonce = value
            .get("claimNonce")
            .and_then(|nonce| nonce.as_str())
            .filter(|nonce| is_token(nonce))
            .map(str::to_owned);
        let checked = serde_json::from_value::<JobDescription>(value)
            .map_err(|e| e.to_string())
            .and_then(|job| job.check(&self.url))
            .map_err(|e| ProtocolError {
                status: Some(200),
                message: format!("{} sent an invalid job: {e}.", self.origin),
            });
        if let (Err(error), Some(nonce)) = (&checked, nonce) {
            // Best effort: the caller shows the reason regardless.
            let _ = self.report_failure(&nonce, &error.message);
        }
        checked
    }

    /// Sign round 1 (8.3).
    pub fn prepare(
        &self,
        nonce: &str,
        certificate: &[u8],
        chain: &[Vec<u8>],
    ) -> Result<PreparedSignature, ProtocolError> {
        let body: PreparedSignatureBody =
            self.post("certificate", certificate_body(nonce, certificate, chain))?;
        let to_sign = body
            .documents
            .into_iter()
            .map(|document| STANDARD.decode(document.to_sign))
            .collect::<Result<_, _>>()
            .map_err(|e| ProtocolError {
                status: Some(200),
                message: format!("{} sent toSign that isn't base64: {e}.", self.origin),
            })?;
        Ok(PreparedSignature {
            digest_algorithm: body.digest_algorithm,
            signature_algorithm: body.signature_algorithm,
            to_sign,
        })
    }

    /// The single enrol round (8.6).
    pub fn enrol(
        &self,
        nonce: &str,
        certificate: &[u8],
        chain: &[Vec<u8>],
    ) -> Result<(), ProtocolError> {
        let Empty {} = self.post("certificate", certificate_body(nonce, certificate, chain))?;
        Ok(())
    }

    /// Sign round 2 (8.5): one signature per document, in order.
    pub fn submit_signatures(
        &self,
        nonce: &str,
        signatures: &[Vec<u8>],
    ) -> Result<(), ProtocolError> {
        let signatures: Vec<String> = signatures.iter().map(|s| STANDARD.encode(s)).collect();
        let body = json!({ "claimNonce": nonce, "signatures": signatures });
        let Empty {} = self.post("signature", body)?;
        Ok(())
    }

    /// The prepared PDF of the document at `index`, of at most `limit`
    /// bytes, from the job URL followed by `/documents/<index>` (8.4).
    pub fn download_document(
        &self,
        index: usize,
        nonce: &str,
        limit: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let sent = self
            .origin
            .agent(DOCUMENT_TIMEOUT)
            .get(format!("{}/documents/{index}", self.url))
            .header("Authorization", format!("Bearer {}", self.token))
            .header("X-KeySeal-Claim", nonce)
            .header(VERSION_HEADER, crate::VERSION)
            .call();
        self.read(sent, limit)
    }

    /// Failure report (8.7); `message` is trimmed and cut to 500 characters.
    pub fn report_failure(&self, nonce: &str, message: &str) -> Result<(), ProtocolError> {
        let message: String = message.trim().chars().take(MAX_FAILURE_CHARS).collect();
        let message = if message.is_empty() {
            "The helper stopped.".into()
        } else {
            message
        };
        let body = json!({ "claimNonce": nonce, "message": message });
        let Empty {} = self.post("failure", body)?;
        Ok(())
    }

    fn post<T: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: serde_json::Value,
    ) -> Result<T, ProtocolError> {
        let sent = self
            .agent
            .post(format!("{}/{endpoint}", self.url))
            .header(VERSION_HEADER, crate::VERSION)
            .send_json(body);
        self.reply(sent)
    }

    /// The JSON body of a `200`, or the error of section 8.8 attributed to the origin.
    fn reply<T: DeserializeOwned>(
        &self,
        sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    ) -> Result<T, ProtocolError> {
        let body = self.read(sent, MAX_RESPONSE_BYTES)?;
        serde_json::from_slice(&body).map_err(|e| ProtocolError {
            status: Some(200),
            message: format!("{} sent an invalid answer: {e}.", self.origin),
        })
    }

    /// The body of a `200` of at most `limit` bytes, or the error of section 8.8.
    fn read(
        &self,
        sent: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
        limit: u64,
    ) -> Result<Vec<u8>, ProtocolError> {
        let origin = &self.origin;
        let unreachable = |e: ureq::Error| ProtocolError {
            status: None,
            message: format!("Couldn't reach {origin}: {e}"),
        };
        let mut response = sent.map_err(unreachable)?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let body = response
            .body_mut()
            .with_config()
            .limit(limit)
            .read_to_vec()
            .map_err(|e| match e {
                ureq::Error::BodyExceedsLimit(_) => ProtocolError {
                    status: None,
                    message: format!("{origin} sent an answer larger than {limit} bytes."),
                },
                e => unreachable(e),
            })?;
        if status == 200 {
            return Ok(body);
        }
        let error: Option<ErrorBody> = serde_json::from_slice(&body).ok();
        let said = error
            .as_ref()
            .and_then(|e| e.message.as_deref())
            .map(|m| format!(" {origin} says: {}", plain(m)))
            .unwrap_or_default();
        let mut message = format!("{} ({origin}, status {status}){said}", meaning(status));
        if status == 426 {
            crate::update::check_soon();
            if let Some(version) = error.and_then(|e| e.min_version) {
                message.push_str(&format!(
                    " Version {} or later is needed; this is {}.",
                    plain(&version),
                    crate::VERSION
                ));
            }
        }
        if status == 429
            && let Some(seconds) = retry_after
        {
            message.push_str(&format!(" Retry after {} seconds.", plain(&seconds)));
        }
        Err(ProtocolError {
            status: Some(status),
            message,
        })
    }
}

fn certificate_body(nonce: &str, certificate: &[u8], chain: &[Vec<u8>]) -> serde_json::Value {
    let chain: Vec<String> = chain
        .iter()
        .take(MAX_CHAIN)
        .map(|der| STANDARD.encode(der))
        .collect();
    json!({
        "claimNonce": nonce,
        "certificate": STANDARD.encode(certificate),
        "chain": chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk";

    fn link(action: &str, job: &str) -> String {
        let job: String = url::form_urlencoded::byte_serialize(job.as_bytes()).collect();
        format!("keyseal://{action}?job={job}")
    }

    #[test]
    fn parses_sign_and_enrol_links() {
        let parsed = parse_link(
            &link(
                "sign",
                &format!("https://dash.example.org/api/keyseal/v1/jobs/{TOKEN}"),
            ),
            false,
        )
        .unwrap();
        assert_eq!(parsed.kind, Kind::Sign);
        assert_eq!(
            parsed.job_url.as_str(),
            format!("https://dash.example.org/api/keyseal/v1/jobs/{TOKEN}")
        );
        assert_eq!(parsed.origin.as_string(), "https://dash.example.org");

        let enrol = format!(
            "keyseal://enrol/?other=1&job={}",
            url::form_urlencoded::byte_serialize(
                format!("https://dash.example.org/v1/jobs/{TOKEN}").as_bytes()
            )
            .collect::<String>()
        );
        assert_eq!(parse_link(&enrol, false).unwrap().kind, Kind::Enrol);
        // The example from section 3.1.
        assert!(parse_link("keyseal://sign?job=https%3A%2F%2Fdash.example.org%2Fapi%2Fkeyseal%2Fv1%2Fjobs%2Fq3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk", false).is_ok());
    }

    #[test]
    fn refuses_bad_links() {
        let job = format!("https://dash.example.org/v1/jobs/{TOKEN}");
        let encoded: String = url::form_urlencoded::byte_serialize(job.as_bytes()).collect();
        for bad in [
            format!("https://dash.example.org/?job={encoded}"),
            format!("keyseal://delete?job={encoded}"),
            format!("keyseal://SIGN?job={encoded}"),
            format!("keyseal://sign/path?job={encoded}"),
            format!("keyseal://user@sign?job={encoded}"),
            format!("keyseal://sign:1?job={encoded}"),
            "keyseal://sign".into(),
            format!("keyseal://sign?job={encoded}&job={encoded}"),
            format!("keyseal://sign?job={encoded}{}", "a".repeat(2048)),
            link("sign", "not a url"),
            link("sign", &format!("http://dash.example.org/v1/jobs/{TOKEN}")),
            link("sign", &format!("https://192.0.2.1/v1/jobs/{TOKEN}")),
            link("sign", &format!("https://localhost/v1/jobs/{TOKEN}")),
            link(
                "sign",
                &format!("https://user@dash.example.org/v1/jobs/{TOKEN}"),
            ),
            link(
                "sign",
                &format!("https://dash.example.org/v1/jobs/{TOKEN}?x=1"),
            ),
            link(
                "sign",
                &format!("https://dash.example.org/v1/jobs/{TOKEN}#x"),
            ),
            link(
                "sign",
                &format!("https://dash.example.org/v1/jobs/{TOKEN}/"),
            ),
            link(
                "sign",
                &format!("https://dash.example.org//v1/jobs/{TOKEN}"),
            ),
            link("sign", &format!("https://dash.example.org/v2/jobs/{TOKEN}")),
            link("sign", &format!("https://dash.example.org/jobs/{TOKEN}")),
            link("sign", "https://dash.example.org/v1/jobs/short"),
            link(
                "sign",
                &format!("https://dash.example.org/v1/jobs/{TOKEN}.x"),
            ),
            link(
                "sign",
                &format!("https://dash.example.org/v1/jobs/{}", "a".repeat(129)),
            ),
        ] {
            assert!(parse_link(&bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn development_links_need_the_override() {
        let local = link("sign", &format!("http://127.0.0.1:8080/v1/jobs/{TOKEN}"));
        assert!(parse_link(&local, false).is_err());
        assert!(parse_link(&local, true).unwrap().origin.insecure);
    }

    #[test]
    fn strips_control_and_bidi_characters() {
        assert_eq!(plain("a\u{202e}b\u{2066}c\u{200f}d\te\nf\u{7}"), "abcde\nf");
    }

    #[test]
    fn checks_job_descriptions() {
        let job_url = format!("https://dash.example.org/v1/jobs/{TOKEN}");
        let documents = |count: usize| {
            (0..count)
                .map(|index| {
                    json!({
                        "title": format!("Document {index}"),
                        "document": format!("{job_url}/documents/{index}"),
                    })
                })
                .collect::<Vec<_>>()
        };
        let description = |extra: serde_json::Value| {
            let mut value = json!({
                "kind": "sign",
                "title": "Board resolution",
                "signer": "Asha Rao",
                "claimNonce": TOKEN,
                "documents": documents(1),
            });
            value
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::from_value::<JobDescription>(value)
                .unwrap()
                .check(&job_url)
        };
        assert!(description(json!({})).is_ok());
        assert!(
            description(json!({ "unknown": 1, "expectedCertificateSha256": "ab".repeat(32) }))
                .is_ok()
        );
        assert!(description(json!({ "kind": "enrol", "documents": [] })).is_ok());
        assert_eq!(
            description(json!({ "documents": documents(20) }))
                .unwrap()
                .documents
                .len(),
            20
        );
        for documents in [json!([]), json!(documents(21))] {
            assert!(description(json!({ "documents": documents })).is_err());
        }
        // Every URL is the job's own, at its own index.
        let mut swapped = documents(2);
        swapped.swap(0, 1);
        let mut elsewhere = documents(1);
        elsewhere[0]["document"] =
            json!(format!("https://dash.example.org/v1/jobs/{TOKEN}/document"));
        let mut untitled = documents(2);
        untitled[1]["title"] = json!("\u{202e}");
        for documents in [swapped, elsewhere, untitled] {
            assert!(description(json!({ "documents": documents })).is_err());
        }
        let mut bidi = documents(1);
        bidi[0]["title"] = json!("Lease\u{202e}");
        assert_eq!(
            description(json!({ "documents": bidi })).unwrap().documents[0].title,
            "Lease"
        );
        assert!(description(json!({ "title": "" })).is_err());
        assert!(description(json!({ "signer": "x".repeat(201) })).is_err());
        assert!(description(json!({ "claimNonce": "short" })).is_err());
        assert!(description(json!({ "expectedCertificateSha256": "AB".repeat(32) })).is_err());
        assert!(description(json!({ "title": "\u{202e}" })).is_err());
        assert!(
            description(json!({ "certificatePolicy": {
                "policyOids": ["2.16.356.100.2.3", "0.0"],
                "issuerCommonNames": ["x".repeat(200)],
                "subjectOrganization": "Acme, Inc.",
                "unknown": 1,
            } }))
            .is_ok()
        );
        for policy in [
            json!({ "policyOids": [] }),
            json!({ "policyOids": ["2.16.356.100.02.3"] }),
            json!({ "policyOids": ["3.1"] }),
            json!({ "policyOids": ["2"] }),
            json!({ "policyOids": ["2..1"] }),
            json!({ "policyOids": ["2.1."] }),
            json!({ "policyOids": [format!("2.{}", "1".repeat(127))] }),
            json!({ "policyOids": (0..17).map(|i| format!("2.{i}")).collect::<Vec<_>>() }),
            json!({ "issuerCommonNames": [""] }),
            json!({ "issuerCommonNames": ["x".repeat(201)] }),
            json!({ "subjectOrganization": "" }),
        ] {
            assert!(
                description(json!({ "certificatePolicy": policy })).is_err(),
                "{policy}"
            );
        }
    }

    /// `policy.der` is issued by "KeySeal Test Sub CA" to O "Acme, Inc."
    /// with policy OIDs 2.16.356.100.2.2 and 2.16.356.100.2.3;
    /// `non-repudiation.der` is self-signed with neither O nor policies.
    #[test]
    fn matches_certificate_policies() {
        const POLICY: &[u8] = include_bytes!("../tests/fixtures/policy.der");
        const PLAIN: &[u8] = include_bytes!("../tests/fixtures/non-repudiation.der");
        let accepts = |policy: serde_json::Value, der: &[u8]| {
            serde_json::from_value::<CertificatePolicy>(policy)
                .unwrap()
                .accepts(der)
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

//! The job client and the manifest fetch against a server in the test, on
//! a development origin (`http://127.0.0.1`).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use keyseal_core::cms::{DigestAlgorithm, SignatureAlgorithm};
use keyseal_core::protocol::{JobClient, Kind, MAX_DOCUMENT_BYTES, parse_link};
use serde_json::{Value, json};

const TOKEN: &str = "q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk";
const NONCE: &str = "Zx8m_Q2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Clone, Debug)]
struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

struct Reply {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

fn reply(status: u16, body: impl Into<Vec<u8>>) -> Reply {
    Reply {
        status,
        headers: vec![("Content-Type", "application/json".into())],
        body: body.into(),
    }
}

type Handler = dyn Fn(&Request) -> Reply + Send + Sync;

/// Serves `handler` on 127.0.0.1 for the rest of the test process; returns
/// the origin and every request received.
fn serve(handler: Box<Handler>) -> (String, Arc<Mutex<Vec<Request>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                continue;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap().to_owned();
            let path = parts.next().unwrap().to_owned();
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let line = line.trim_end();
                if line.is_empty() {
                    break;
                }
                let (key, value) = line.split_once(':').unwrap();
                headers.push((key.trim().to_owned(), value.trim().to_owned()));
            }
            let length = headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.parse().unwrap());
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            let request = Request {
                method,
                path,
                headers,
                body,
            };
            seen.lock().unwrap().push(request.clone());
            let reply = handler(&request);
            let mut head = format!(
                "HTTP/1.1 {} X\r\nContent-Length: {}\r\nConnection: close\r\n",
                reply.status,
                reply.body.len()
            );
            for (key, value) in &reply.headers {
                head.push_str(&format!("{key}: {value}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&reply.body);
        }
    });
    (origin, requests)
}

fn client(origin: &str) -> JobClient {
    let job: String = url::form_urlencoded::byte_serialize(
        format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
    )
    .collect();
    JobClient::new(&parse_link(&format!("keyseal://sign?job={job}"), true).unwrap())
}

/// A sign job with two documents on `origin`.
fn job_description(origin: &str) -> Value {
    let job_url = format!("{origin}/api/keyseal/v1/jobs/{TOKEN}");
    json!({
        "kind": "sign",
        "title": "Board resolution 2026/14",
        "signer": "Asha Rao",
        "claimNonce": NONCE,
        "expectedCertificateSha256": "ab".repeat(32),
        "certificatePolicy": {
            "policyOids": ["2.16.356.100.2.3"],
            "issuerCommonNames": ["KeySeal Test Sub CA"],
            "subjectOrganization": "Acme, Inc.",
        },
        "digestAlgorithm": "sha256",
        "documents": [
            { "title": "Resolution", "document": format!("{job_url}/documents/0") },
            // The URL may differ from the job URL in form only.
            {
                "title": "Minutes",
                "document": format!("{}/documents/1", job_url.replace("http://", "HTTP://")),
            },
        ],
        "futureMember": true,
    })
}

/// The origin `request` was sent to, from its `Host` header.
fn request_origin(request: &Request) -> String {
    format!("http://{}", request.header("Host").unwrap())
}

#[test]
fn runs_both_rounds_and_the_failure_report() {
    let (origin, requests) = serve(Box::new(|request| {
        match (request.method.as_str(), request.path.as_str()) {
            ("GET", path) if path.ends_with(TOKEN) => {
                reply(200, job_description(&request_origin(request)).to_string())
            }
            ("POST", path) if path.ends_with("/certificate") => reply(
                200,
                json!({
                    "digestAlgorithm": "sha384",
                    "signatureAlgorithm": "rsa-pss",
                    "documents": [{ "toSign": "MQA=" }, { "toSign": "MQMCAQE=" }],
                })
                .to_string(),
            ),
            ("POST", _) => reply(200, "{}"),
            _ => reply(404, "{}"),
        }
    }));
    let client = client(&origin);

    let job = client.claim().unwrap();
    assert_eq!(job.kind, Kind::Sign);
    assert_eq!(job.title, "Board resolution 2026/14");
    let titles: Vec<&str> = job.documents.iter().map(|d| d.title.as_str()).collect();
    assert_eq!(titles, ["Resolution", "Minutes"]);
    assert_eq!(job.claim_nonce, NONCE);
    assert_eq!(job.digest_algorithm, Some(DigestAlgorithm::Sha256));
    let policy = job.certificate_policy.unwrap();
    assert_eq!(
        policy.policy_oids.as_deref(),
        Some(&["2.16.356.100.2.3".to_owned()][..])
    );
    assert_eq!(
        policy.issuer_common_names.as_deref(),
        Some(&["KeySeal Test Sub CA".to_owned()][..])
    );
    assert_eq!(policy.subject_organization.as_deref(), Some("Acme, Inc."));
    assert!(policy.accepts(include_bytes!("fixtures/policy.der")));

    let prepared = client
        .prepare(NONCE, b"certificate", &[b"ca".to_vec()])
        .unwrap();
    assert_eq!(
        prepared.to_sign,
        [vec![0x31, 0x00], vec![0x31, 0x03, 0x02, 0x01, 0x01]]
    );
    assert_eq!(prepared.digest_algorithm, DigestAlgorithm::Sha384);
    assert_eq!(prepared.signature_algorithm, SignatureAlgorithm::RsaPss);
    client
        .submit_signatures(NONCE, &[b"signature".to_vec(), b"second".to_vec()])
        .unwrap();
    client.enrol(NONCE, b"certificate", &[]).unwrap();
    client
        .report_failure(NONCE, &format!("  {}  ", "x".repeat(600)))
        .unwrap();

    let requests = requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .all(|r| r.header("X-KeySeal-Version") == Some(keyseal_core::VERSION))
    );
    assert_eq!(requests[0].path, format!("/api/keyseal/v1/jobs/{TOKEN}"));
    assert_eq!(
        requests[1].json(),
        json!({ "claimNonce": NONCE, "certificate": "Y2VydGlmaWNhdGU=", "chain": ["Y2E="] })
    );
    assert_eq!(
        requests[1].header("Content-Type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(
        requests[2].path,
        format!("/api/keyseal/v1/jobs/{TOKEN}/signature")
    );
    assert_eq!(
        requests[2].json(),
        json!({ "claimNonce": NONCE, "signatures": ["c2lnbmF0dXJl", "c2Vjb25k"] })
    );
    assert_eq!(requests[3].json()["chain"], json!([]));
    assert_eq!(
        requests[4].path,
        format!("/api/keyseal/v1/jobs/{TOKEN}/failure")
    );
    assert_eq!(requests[4].json()["message"], "x".repeat(500));
}

#[test]
fn reports_every_error_status_with_the_server_message() {
    for (status, meaning) in [
        (404, "doesn't exist or has expired"),
        (409, "already claimed"),
        (410, "already completed or failed"),
        (413, "too large"),
        (422, "refused the request"),
        (426, "too old"),
        (429, "busy"),
        (500, "unexpected answer"),
    ] {
        let server = serve_status(status);
        let error = client(&server)
            .submit_signatures(NONCE, &[b"x".to_vec()])
            .unwrap_err();
        assert_eq!(error.status, Some(status));
        assert!(
            error.message.contains(meaning),
            "{status}: {}",
            error.message
        );
        assert!(error.message.contains(&server), "{}", error.message);
        let error = client(&server).claim().unwrap_err();
        assert_eq!(error.status, Some(status));
        match status {
            426 => assert!(
                error.message.contains("Version 9.0.0 or later is needed")
                    && error.message.contains("Update the signing helper"),
                "{}",
                error.message
            ),
            429 => assert!(
                error.message.contains("Retry after 7 seconds"),
                "{}",
                error.message
            ),
            _ => assert!(
                error
                    .message
                    .contains(&format!("says: Server says {status}")),
                "{}",
                error.message
            ),
        }
    }
}

#[test]
fn downloads_each_document_with_the_token_and_claim_nonce() {
    let (origin, requests) = serve(Box::new(|_| reply(200, "%PDF-1.7")));
    let job = client(&origin);
    assert_eq!(
        job.download_document(1, NONCE, MAX_DOCUMENT_BYTES).unwrap(),
        b"%PDF-1.7"
    );
    let request = requests.lock().unwrap()[0].clone();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        format!("/api/keyseal/v1/jobs/{TOKEN}/documents/1")
    );
    let bearer = format!("Bearer {TOKEN}");
    assert_eq!(request.header("Authorization"), Some(bearer.as_str()));
    assert_eq!(request.header("X-KeySeal-Claim"), Some(NONCE));
    assert!(request.header("X-KeySeal-Version").is_some());
    // What is left of the job's total limit caps a document too.
    let error = job.download_document(0, NONCE, 4).unwrap_err();
    assert!(error.message.contains("larger than 4 bytes"), "{error}");

    let (big, _) = serve(Box::new(|_| reply(200, vec![b'%'; 67_108_865])));
    let error = client(&big)
        .download_document(0, NONCE, MAX_DOCUMENT_BYTES)
        .unwrap_err();
    assert!(
        error.message.contains("larger than 67108864 bytes"),
        "{error}"
    );
    let (refused, _) = serve(Box::new(|_| {
        reply(403, json!({ "message": "Not yours." }).to_string())
    }));
    let error = client(&refused)
        .download_document(0, NONCE, MAX_DOCUMENT_BYTES)
        .unwrap_err();
    assert_eq!(error.status, Some(403));
    assert!(error.message.contains("Not yours."), "{error}");
}

/// A document URL other than the job URL followed by `/documents/<index>`
/// fails the claim, which is reported, and nothing is downloaded.
#[test]
fn refuses_a_job_whose_document_urls_are_not_its_own() {
    for document in [
        "http://localhost:1/api/keyseal/v1/jobs/{TOKEN}/documents/0",
        "{origin}/api/keyseal/v1/jobs/{TOKEN}/document",
        "{origin}/api/keyseal/v1/jobs/{TOKEN}/documents/1",
        "{origin}/api/keyseal/v1/jobs/{TOKEN}/documents/0?x=1",
        "{origin}/api/keyseal/v1/jobs/{TOKEN}/documents/0/",
        "not a url",
    ] {
        let (origin, requests) = serve(Box::new(move |request| match request.method.as_str() {
            "GET" => {
                let origin = request_origin(request);
                let mut description = job_description(&origin);
                description["documents"] = json!([{
                    "title": "Resolution",
                    "document": document.replace("{origin}", &origin).replace("{TOKEN}", TOKEN),
                }]);
                reply(200, description.to_string())
            }
            _ => reply(200, "{}"),
        }));
        let error = client(&origin).claim().unwrap_err();
        assert!(
            error
                .message
                .contains("the URL of its document 1 isn't the job's"),
            "{document}: {error}"
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2, "{document}");
        assert!(requests[1].path.ends_with("/failure"));
    }
}

/// A server answering every request with `status` and an error body.
fn serve_status(status: u16) -> String {
    serve(Box::new(move |_| {
        let mut reply = match status {
            426 => reply(
                426,
                json!({ "minVersion": "9.0.0", "message": "Update the signing helper, then try again." })
                    .to_string(),
            ),
            _ => reply(
                status,
                json!({ "message": format!("Server says \u{202e}{status}") }).to_string(),
            ),
        };
        if status == 429 {
            reply.headers.push(("Retry-After", "7".into()));
        }
        reply
    }))
    .0
}

#[test]
fn refuses_invalid_answers() {
    for (body, expected) in [
        ("not json", "invalid answer"),
        (
            r#"{"kind":"delete","title":"t","signer":"s","claimNonce":"x"}"#,
            "invalid job: unknown variant",
        ),
        (
            r#"{"kind":"sign","title":"t","signer":"s","claimNonce":"short"}"#,
            "invalid job: its claimNonce",
        ),
    ] {
        let (origin, _) = serve(Box::new(move |_| reply(200, body)));
        let error = client(&origin).claim().unwrap_err();
        assert_eq!(error.status, Some(200));
        assert!(error.message.contains(expected), "{}", error.message);
    }
    let (origin, _) = serve(Box::new(|_| {
        reply(200, format!("{{\"x\":\"{}\"}}", "a".repeat(300_000)))
    }));
    let error = client(&origin).claim().unwrap_err();
    assert_eq!(error.status, None);

    let (origin, _) = serve(Box::new(|_| reply(404, "not json")));
    let error = client(&origin).claim().unwrap_err();
    assert_eq!(error.status, Some(404));
    assert!(!error.message.contains("says"), "{}", error.message);
}

#[test]
fn reports_a_claimed_job_that_fails_the_checks() {
    for job in [
        json!({ "kind": "sign", "title": "\u{202e}", "signer": "s", "claimNonce": NONCE }),
        json!({ "kind": "delete", "title": "t", "signer": "s", "claimNonce": NONCE }),
        json!({ "kind": "enrol", "title": "t", "signer": "s", "claimNonce": NONCE,
                "certificatePolicy": { "policyOids": ["2.16.356.100.2.03"] } }),
    ] {
        let (origin, requests) = serve(Box::new(move |request| match request.method.as_str() {
            "GET" => reply(200, job.to_string()),
            _ => reply(200, "{}"),
        }));
        let error = client(&origin).claim().unwrap_err();
        assert!(error.message.contains("invalid job"), "{}", error.message);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[1].path,
            format!("/api/keyseal/v1/jobs/{TOKEN}/failure")
        );
        assert_eq!(
            requests[1].json(),
            json!({ "claimNonce": NONCE, "message": error.message })
        );
    }
}

#[test]
fn follows_same_origin_redirects_only() {
    let (origin, _) = serve(Box::new(|request| {
        if request.path.ends_with(TOKEN) {
            let mut moved = reply(302, "{}");
            moved.headers.push(("Location", "/moved".into()));
            moved
        } else {
            reply(200, job_description(&request_origin(request)).to_string())
        }
    }));
    assert_eq!(client(&origin).claim().unwrap().claim_nonce, NONCE);

    let (origin, requests) = serve(Box::new(|request| {
        let port = request
            .header("Host")
            .unwrap()
            .rsplit(':')
            .next()
            .unwrap()
            .to_owned();
        let mut moved = reply(302, "{}");
        moved
            .headers
            .push(("Location", format!("http://localhost:{port}/moved")));
        moved
    }));
    let error = client(&origin).claim().unwrap_err();
    assert_eq!(error.status, None);
    assert!(error.message.contains("outside"), "{}", error.message);
    assert_eq!(requests.lock().unwrap().len(), 1);
}

#[test]
fn reports_unreachable_servers() {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let error = client(&format!("http://127.0.0.1:{port}"))
        .claim()
        .unwrap_err();
    assert_eq!(error.status, None);
    assert!(
        error
            .message
            .starts_with("Couldn't reach http://127.0.0.1:"),
        "{}",
        error.message
    );
}

mod flow {
    use super::*;
    use keyseal_core::flow::{DigestConfirm, Environment, JobView, PinPrompt, Ui, run};
    use keyseal_core::origin::Origin;
    use zeroize::Zeroizing;

    /// Accepts the origin, records errors and fails the test on any prompt
    /// that needs a token.
    #[derive(Default)]
    struct TestUi {
        errors: Vec<String>,
    }

    impl Ui for TestUi {
        fn confirm_origin(&mut self, _: &Origin) -> bool {
            true
        }
        fn choose_certificate(&mut self, _: &JobView, _: &[String]) -> Option<usize> {
            panic!("no certificate choice expected")
        }
        fn prompt_pin(&mut self, _: &PinPrompt) -> Option<Zeroizing<String>> {
            panic!("no PIN prompt expected")
        }
        fn confirm_digest(&mut self, _: &DigestConfirm) -> bool {
            panic!("no digest confirmation expected")
        }
        fn confirm_enrol(&mut self, _: &JobView) -> bool {
            panic!("no enrol confirmation expected")
        }
        fn show_error(&mut self, message: &str) {
            self.errors.push(message.to_owned());
        }
        fn show_info(&mut self, _: &str) {
            panic!("no information expected")
        }
    }

    /// Runs the sign link for `origin`; returns the error and what the UI showed.
    fn run_job(origin: &str, name: &str) -> (String, Vec<String>) {
        let config_dir =
            std::env::temp_dir().join(format!("keyseal-flow-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&config_dir);
        let env = Environment {
            allow_insecure: true,
            config_dir: config_dir.clone(),
        };
        let job: String = url::form_urlencoded::byte_serialize(
            format!("{origin}/api/keyseal/v1/jobs/{TOKEN}").as_bytes(),
        )
        .collect();
        let mut ui = TestUi::default();
        let error = run(&format!("keyseal://sign?job={job}"), &mut ui, &env).unwrap_err();
        let _ = std::fs::remove_dir_all(&config_dir);
        (error.message, ui.errors)
    }

    fn job_requests(requests: &Mutex<Vec<Request>>) -> usize {
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.starts_with("/api/keyseal/v1/jobs/"))
            .count()
    }

    #[test]
    fn shows_the_upgrade_message_without_retrying() {
        let (origin, requests) = serve(Box::new(|request| {
            if request.path == "/.well-known/keyseal.json" {
                return reply(404, "{}");
            }
            reply(
                426,
                json!({ "minVersion": "9.0.0", "message": "Update the signing helper, then try again." })
                    .to_string(),
            )
        }));
        let (error, shown) = run_job(&origin, "upgrade");
        assert!(
            error.contains("Update the signing helper, then try again.")
                && error.contains("Version 9.0.0 or later is needed"),
            "{error}"
        );
        assert_eq!(shown, [error]);
        assert_eq!(job_requests(&requests), 1);
    }

    #[test]
    fn does_not_claim_when_the_manifest_needs_a_newer_helper() {
        let (origin, requests) = serve(Box::new(|request| {
            if request.path == "/.well-known/keyseal.json" {
                return reply(
                    200,
                    json!({ "protocol": 1, "name": "Example", "minHelperVersion": "99.0.0" })
                        .to_string(),
                );
            }
            reply(200, job_description(&request_origin(request)).to_string())
        }));
        let (error, shown) = run_job(&origin, "min-version");
        assert!(error.contains("needs KeySeal helper 99.0.0"), "{error}");
        assert_eq!(shown, [error]);
        assert_eq!(job_requests(&requests), 0);
    }
}

mod manifest {
    use super::*;
    use keyseal_core::manifest::branding;
    use keyseal_core::origin::Origin;

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nicon";

    fn origin(origin: &str) -> Origin {
        Origin::of_url(&url::Url::parse(origin).unwrap(), true).unwrap()
    }

    fn cache_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keyseal-manifest-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn fetches_branding_and_falls_back_to_the_cache() {
        let available = Arc::new(Mutex::new(true));
        let switch = available.clone();
        let (base, requests) = serve(Box::new(move |request| {
            if !*switch.lock().unwrap() {
                return reply(404, "{}");
            }
            let port = request
                .header("Host")
                .unwrap()
                .rsplit(':')
                .next()
                .unwrap()
                .to_owned();
            match request.path.as_str() {
                "/.well-known/keyseal.json" => reply(
                    200,
                    json!({
                        "protocol": 1,
                        "name": "Example Trust",
                        "icon": format!("http://127.0.0.1:{port}/icon.png"),
                        "accentColor": "#1f6feb",
                    })
                    .to_string(),
                ),
                "/icon.png" => reply(200, PNG),
                _ => reply(404, "{}"),
            }
        }));
        let cache = cache_dir("fallback");
        let fetched = branding(&origin(&base), &cache).unwrap();
        assert_eq!(fetched.manifest.name, "Example Trust");
        assert_eq!(fetched.icon.as_deref(), Some(PNG));
        assert!(
            requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r.header("X-KeySeal-Version") == Some(keyseal_core::VERSION))
        );

        *available.lock().unwrap() = false;
        let cached = branding(&origin(&base), &cache).unwrap();
        assert_eq!(cached.manifest, fetched.manifest);
        assert_eq!(cached.icon.as_deref(), Some(PNG));
        assert!(branding(&origin(&base), &cache_dir("empty")).is_none());
        let _ = std::fs::remove_dir_all(&cache);
    }

    #[test]
    fn ignores_foreign_large_or_non_png_icons() {
        for (icon_path, icon) in [
            ("http://localhost:{port}/icon.png", PNG.to_vec()),
            ("http://127.0.0.1:{port}/icon.png", b"GIF89a".to_vec()),
            (
                "http://127.0.0.1:{port}/icon.png",
                [PNG, &vec![0; 262_144][..]].concat(),
            ),
        ] {
            let icon = icon.clone();
            let (base, _) = serve(Box::new(move |request| {
                let port = request
                    .header("Host")
                    .unwrap()
                    .rsplit(':')
                    .next()
                    .unwrap()
                    .to_owned();
                match request.path.as_str() {
                    "/.well-known/keyseal.json" => reply(
                        200,
                        json!({ "protocol": 1, "name": "Example", "icon": icon_path.replace("{port}", &port) })
                            .to_string(),
                    ),
                    _ => reply(200, icon.clone()),
                }
            }));
            let fetched = branding(&origin(&base), &cache_dir("icons")).unwrap();
            assert_eq!(fetched.manifest.name, "Example");
            assert!(fetched.icon.is_none(), "{icon_path}");
        }
    }

    #[test]
    fn ignores_large_or_slow_manifests() {
        let (base, _) = serve(Box::new(|_| {
            reply(
                200,
                format!(
                    r#"{{"protocol":1,"name":"x","pad":"{}"}}"#,
                    "a".repeat(16_384)
                ),
            )
        }));
        assert!(branding(&origin(&base), &cache_dir("large")).is_none());

        let (base, _) = serve(Box::new(|_| {
            std::thread::sleep(Duration::from_secs(4));
            reply(200, r#"{"protocol":1,"name":"x"}"#)
        }));
        let started = Instant::now();
        assert!(branding(&origin(&base), &cache_dir("slow")).is_none());
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }
}

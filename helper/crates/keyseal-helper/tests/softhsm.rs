//! End to end against SoftHSM: `keyseal run`, headless, completes two-round
//! jobs served here with RSA-2048 (PKCS#1 v1.5 and PSS), P-256 and P-384
//! keys, on a token whose certificates are public (one prompt) and one
//! whose certificates are private (PIN first, then the digest confirm),
//! and signs a batch of three documents after one login on both. It
//! refuses tampered SignedAttributes before the PIN, wrong pairings of key
//! and algorithm, documents that don't hash to the digest, a batch with one
//! such document, and untrusted origins, and enrols a certificate.
//! Runs when `KEYSEAL_SOFTHSM_MODULE` names libsofthsm2, and needs
//! softhsm2-util, pkcs11-tool (OpenSC) and openssl on the PATH.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256, Sha384};
use x509_parser::asn1_rs::oid;

const PIN: &str = "1234";
const WRONG_PIN: &str = "0000";
const TOKEN: &str = "q3Jm0f_2vX9kLr8aTq1bNw4uYc7eHs5dPz6iGo0tRk";
const NONCE: &str = "Zx8m_Q2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() >= 0x80 {
        out.push(0x81);
    }
    out.push(content.len() as u8);
    out.extend_from_slice(content);
    out
}

fn attribute(oid_raw: &[u8], value: Vec<u8>) -> Vec<u8> {
    der_tlv(
        0x30,
        &[der_tlv(0x06, oid_raw), der_tlv(0x31, &value)].concat(),
    )
}

/// Document `index` prepared as the signing service serves it: a signature
/// dictionary whose `/ByteRange` leaves out only the `/Contents`
/// placeholder, and the bytes that range covers.
fn prepared_pdf(index: usize) -> (Vec<u8>, Vec<u8>) {
    let mut pdf =
        format!("%PDF-1.7\n% document {index}\n1 0 obj\n<< /Type /Sig /Contents ").into_bytes();
    let a = pdf.len();
    pdf.extend(b"<");
    pdf.resize(pdf.len() + 64, b'0');
    pdf.extend(b">");
    let b = pdf.len();
    let end = b" >>\nendobj\n%%EOF\n";
    pdf.extend(format!("\n/ByteRange [0 {a} {b} {}]", 40 + end.len()).bytes());
    pdf.resize(b + 40, b' ');
    pdf.extend(end);
    let signed = [&pdf[..a], &pdf[b..]].concat();
    (pdf, signed)
}

/// The messageDigest the server puts in document `index`'s `toSign`: the
/// digest of its prepared PDF, or a filler when the job asks for a wrong
/// length.
fn message_digest(job: &Job, index: usize) -> Vec<u8> {
    let (_, signed) = prepared_pdf(index);
    match (job.digest_algorithm, job.digest_len) {
        ("sha256", 32) => Sha256::digest(signed).to_vec(),
        ("sha384", 48) => Sha384::digest(signed).to_vec(),
        (_, len) => vec![0xab; len],
    }
}

/// SignedAttributes as the signing service builds them for `certificate`,
/// with `digest` as messageDigest, plus `extra`.
fn signed_attributes(certificate: &[u8], digest: &[u8], extra: Option<Vec<u8>>) -> Vec<u8> {
    let cert_id = der_tlv(0x30, &der_tlv(0x04, &Sha256::digest(certificate)));
    let mut attributes = vec![
        attribute(
            &oid!(raw 1.2.840.113549.1.9.3),
            der_tlv(0x06, &oid!(raw 1.2.840.113549.1.7.1)),
        ),
        attribute(&oid!(raw 1.2.840.113549.1.9.4), der_tlv(0x04, digest)),
        attribute(
            &oid!(raw 1.2.840.113549.1.9.16.2.47),
            der_tlv(0x30, &der_tlv(0x30, &cert_id)),
        ),
    ];
    attributes.extend(extra);
    attributes.sort();
    der_tlv(0x31, &attributes.concat())
}

/// What the test server is asked to serve.
#[derive(Clone)]
struct Job {
    link_kind: &'static str,
    kind: &'static str,
    expected: Option<Vec<u8>>,
    job_digest: Option<&'static str>,
    digest_algorithm: &'static str,
    signature_algorithm: &'static str,
    digest_len: usize,
    extra: Option<Vec<u8>>,
    /// How many documents the job description lists; 0 for none at all.
    documents: usize,
    /// This served document differs from the one its `toSign` was made for.
    tampered: Option<usize>,
}

impl Job {
    fn sign(certificate: &[u8], digest: &'static str, signature: &'static str) -> Self {
        Self {
            link_kind: "sign",
            kind: "sign",
            expected: Some(certificate.to_vec()),
            job_digest: Some(digest),
            digest_algorithm: digest,
            signature_algorithm: signature,
            digest_len: if digest == "sha384" { 48 } else { 32 },
            extra: None,
            documents: 1,
            tampered: None,
        }
    }

    /// A sign job of `count` documents.
    fn batch(certificate: &[u8], count: usize) -> Self {
        Self {
            documents: count,
            ..Self::sign(certificate, "sha256", "rsa-pkcs1-v1_5")
        }
    }
}

/// What the helper sent.
#[derive(Debug, Default)]
struct Posted {
    requests: Vec<String>,
    certificate: Option<Vec<u8>>,
    chain: Vec<Vec<u8>>,
    /// Each document's `toSign`, in order.
    to_sign: Vec<Vec<u8>>,
    signatures: Option<Vec<Vec<u8>>>,
    failure: Option<String>,
    /// The `Authorization` and `X-KeySeal-Claim` of the last document download.
    document: Option<(Option<String>, Option<String>)>,
}

fn base64(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}

/// Serves `job` with the two rounds of the protocol until a `STOP` line arrives.
fn serve(listener: TcpListener, job: Job) -> Posted {
    let mut posted = Posted::default();
    let job_path = format!("/api/keyseal/v1/jobs/{TOKEN}");
    let origin = format!("http://{}", listener.local_addr().unwrap());
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        if request.trim() == "STOP" {
            return posted;
        }
        let mut length = 0;
        let mut version = None;
        let mut authorization = None;
        let mut claim = None;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            let (key, value) = line.split_once(':').unwrap();
            match key.to_ascii_lowercase().as_str() {
                "content-length" => length = value.trim().parse().unwrap(),
                "x-keyseal-version" => version = Some(value.trim().to_owned()),
                "authorization" => authorization = Some(value.trim().to_owned()),
                "x-keyseal-claim" => claim = Some(value.trim().to_owned()),
                _ => {}
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        let mut parts = request.split_whitespace();
        let (method, path) = (parts.next().unwrap(), parts.next().unwrap());
        posted.requests.push(format!("{method} {path}"));
        let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let endpoint = path.strip_prefix(&job_path);
        let download = endpoint
            .and_then(|endpoint| endpoint.strip_prefix("/documents/"))
            .and_then(|index| index.parse::<usize>().ok())
            .filter(|&index| index < job.documents);
        if let ("GET", Some(index)) = (method, download) {
            let (mut pdf, _) = prepared_pdf(index);
            if job.tampered == Some(index) {
                pdf[3] = b'X';
            }
            let owner = authorization.as_deref() == Some(&format!("Bearer {TOKEN}"))
                && claim.as_deref() == Some(NONCE);
            posted.document = Some((authorization, claim));
            let (status, body) = if owner {
                (200, pdf)
            } else {
                (403, b"{}".to_vec())
            };
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/pdf\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            continue;
        }
        let (status, reply) = if version.is_none() {
            (
                426,
                json!({ "minVersion": "0.1.0", "message": "No version." }),
            )
        } else if method == "POST" && body["claimNonce"] != NONCE {
            (409, json!({ "message": "Wrong claim nonce." }))
        } else {
            match (method, endpoint) {
                ("GET", Some("")) => {
                    let mut description = json!({
                        "kind": job.kind,
                        "title": "Board resolution 2026/14",
                        "signer": "Asha Rao",
                        "claimNonce": NONCE,
                    });
                    if let Some(expected) = &job.expected {
                        description["expectedCertificateSha256"] =
                            hex::encode(Sha256::digest(expected)).into();
                    }
                    if let Some(digest) = job.job_digest {
                        description["digestAlgorithm"] = digest.into();
                    }
                    if job.kind == "sign" {
                        description["documents"] = (0..job.documents)
                            .map(|index| {
                                json!({
                                    "title": format!("Document {}", index + 1),
                                    "document": format!("{origin}{job_path}/documents/{index}"),
                                })
                            })
                            .collect();
                    }
                    (200, description)
                }
                ("POST", Some("/certificate")) => {
                    let certificate = base64(&body["certificate"]);
                    posted.chain = body["chain"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(base64)
                        .collect();
                    if job.kind == "enrol" {
                        posted.certificate = Some(certificate);
                        (200, json!({}))
                    } else {
                        posted.to_sign = (0..job.documents)
                            .map(|index| {
                                signed_attributes(
                                    &certificate,
                                    &message_digest(&job, index),
                                    job.extra.clone(),
                                )
                            })
                            .collect();
                        posted.certificate = Some(certificate);
                        let documents: Vec<Value> = posted
                            .to_sign
                            .iter()
                            .map(|to_sign| json!({ "toSign": STANDARD.encode(to_sign) }))
                            .collect();
                        (
                            200,
                            json!({
                                "digestAlgorithm": job.digest_algorithm,
                                "signatureAlgorithm": job.signature_algorithm,
                                "documents": documents,
                            }),
                        )
                    }
                }
                ("POST", Some("/signature")) => {
                    posted.signatures = Some(
                        body["signatures"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(base64)
                            .collect(),
                    );
                    (200, json!({}))
                }
                ("POST", Some("/failure")) => {
                    posted.failure = Some(body["message"].as_str().unwrap().to_owned());
                    (200, json!({}))
                }
                _ => (404, json!({ "message": "Not found." })),
            }
        };
        let reply = reply.to_string();
        write!(
            stream,
            "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
    }
    unreachable!()
}

struct Setup {
    dir: PathBuf,
    module: String,
}

impl Setup {
    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.dir.join(name)).unwrap()
    }

    /// Runs `keyseal run` on `job` against the token in `conf`, trusting the
    /// test origin when `trust` is set.
    fn run_job(&self, conf: &str, job: Job, pin: &str, trust: bool) -> (Output, Posted) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}");
        let link_kind = job.link_kind;
        let server = std::thread::spawn(move || serve(listener, job));
        let job_url: String = url_encode(&format!("{origin}/api/keyseal/v1/jobs/{TOKEN}"));
        let mut command = Command::new(env!("CARGO_BIN_EXE_keyseal"));
        command
            .args(["run", &format!("keyseal://{link_kind}?job={job_url}")])
            .env("SOFTHSM2_CONF", self.dir.join(conf))
            .env("KEYSEAL_PKCS11_MODULE", &self.module)
            .env("KEYSEAL_CONFIG_DIR", self.dir.join("config"))
            .env("KEYSEAL_HEADLESS", "1")
            .env("KEYSEAL_ALLOW_INSECURE_ORIGINS", "1")
            .env("KEYSEAL_PIN", pin)
            .env_remove("KEYSEAL_HEADLESS_TRUST_ORIGIN");
        if trust {
            command.env("KEYSEAL_HEADLESS_TRUST_ORIGIN", &origin);
        }
        let output = command.output().unwrap();
        TcpStream::connect(address)
            .unwrap()
            .write_all(b"STOP\r\n")
            .unwrap();
        (output, server.join().unwrap())
    }

    /// Checks `signature` over `to_sign` with the certificate in `name.der`.
    fn verify(&self, name: &str, digest: &str, scheme: &str, to_sign: &[u8], signature: &[u8]) {
        std::fs::write(self.dir.join("to-sign"), to_sign).unwrap();
        std::fs::write(self.dir.join("signature"), signature).unwrap();
        let public_key = run(Command::new("openssl").current_dir(&self.dir).args([
            "x509",
            "-inform",
            "DER",
            "-in",
            &format!("{name}.der"),
            "-pubkey",
            "-noout",
        ]));
        std::fs::write(self.dir.join("public.pem"), public_key.stdout).unwrap();
        let mut command = Command::new("openssl");
        command.current_dir(&self.dir).args([
            "dgst",
            &format!("-{digest}"),
            "-verify",
            "public.pem",
        ]);
        if scheme == "rsa-pss" {
            let salt = if digest == "sha384" { "48" } else { "32" };
            command.args([
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                &format!("rsa_pss_saltlen:{salt}"),
                "-sigopt",
                &format!("rsa_mgf1_md:{digest}"),
            ]);
        }
        run(command.args(["-signature", "signature", "to-sign"]));
    }
}

fn url_encode(text: &str) -> String {
    text.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A SoftHSM token in `<name>/` with its own config file `<name>.conf`.
fn init_token(dir: &Path, name: &str) -> String {
    std::fs::create_dir_all(dir.join(name)).unwrap();
    let conf = format!("{name}.conf");
    std::fs::write(
        dir.join(&conf),
        format!("directories.tokendir = {}\n", dir.join(name).display()),
    )
    .unwrap();
    run(Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", dir.join(&conf))
        .args([
            "--init-token",
            "--free",
            "--label",
            name,
            "--pin",
            PIN,
            "--so-pin",
            "5678",
        ]));
    conf
}

/// A self-signed certificate `name.der` and its key; an end-entity
/// signing certificate unless `ca`.
fn make_certificate(dir: &Path, name: &str, newkey: &[&str], ca: bool) {
    let extensions: &[&str] = if ca {
        &[]
    } else {
        &[
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature,nonRepudiation",
        ]
    };
    run(Command::new("openssl")
        .current_dir(dir)
        .args(["req", "-x509", "-nodes", "-days", "1"])
        .args(["-subj", &format!("/CN=Test {name}")])
        .args(newkey)
        .args(extensions)
        .args(["-keyout", &format!("{name}.pem")])
        .args(["-outform", "DER", "-out", &format!("{name}.der")]));
    run(Command::new("openssl").current_dir(dir).args([
        "pkey",
        "-in",
        &format!("{name}.pem"),
        "-outform",
        "DER",
        "-out",
        &format!("{name}.key"),
    ]));
}

/// Writes `name`'s certificate (and key, unless `cert_only`) to the token.
fn write_objects(
    setup: &Setup,
    conf: &str,
    name: &str,
    id: &str,
    cert_only: bool,
    private_cert: bool,
) {
    let mut objects = vec![(format!("{name}.der"), "cert")];
    if !cert_only {
        objects.push((format!("{name}.key"), "privkey"));
    }
    for (file, kind) in objects {
        let mut command = Command::new("pkcs11-tool");
        command
            .current_dir(&setup.dir)
            .env("SOFTHSM2_CONF", setup.dir.join(conf))
            .args(["--module", &setup.module, "--login", "--pin", PIN])
            .args([
                "--write-object",
                &file,
                "--type",
                kind,
                "--id",
                id,
                "--label",
                name,
            ]);
        if kind == "privkey" {
            command.arg("--usage-sign");
        }
        if kind == "cert" && private_cert {
            command.arg("--private");
        }
        run(&mut command);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn runs_jobs_on_softhsm() {
    let Ok(module) = std::env::var("KEYSEAL_SOFTHSM_MODULE") else {
        eprintln!("skipped: set KEYSEAL_SOFTHSM_MODULE to libsofthsm2 to run");
        return;
    };
    let dir = std::env::temp_dir().join(format!("keyseal-softhsm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let setup = Setup { dir, module };

    // "public": certificates readable before login, plus a CA certificate
    // without a key. "private": the certificate is a private object.
    let public = init_token(&setup.dir, "public");
    let private = init_token(&setup.dir, "private");
    make_certificate(&setup.dir, "rsa", &["-newkey", "rsa:2048"], false);
    make_certificate(
        &setup.dir,
        "p256",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
        false,
    );
    make_certificate(
        &setup.dir,
        "p384",
        &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"],
        false,
    );
    make_certificate(&setup.dir, "ca", &["-newkey", "rsa:2048"], true);
    make_certificate(&setup.dir, "hidden", &["-newkey", "rsa:2048"], false);
    write_objects(&setup, &public, "rsa", "01", false, false);
    write_objects(&setup, &public, "p256", "02", false, false);
    write_objects(&setup, &public, "p384", "03", false, false);
    write_objects(&setup, &public, "ca", "09", true, false);
    write_objects(&setup, &private, "hidden", "01", false, true);

    // Certificates visible before login: one view with the digest, then the PIN.
    for (name, digest, scheme) in [
        ("rsa", "sha256", "rsa-pkcs1-v1_5"),
        ("rsa", "sha384", "rsa-pkcs1-v1_5"),
        ("rsa", "sha256", "rsa-pss"),
        ("rsa", "sha384", "rsa-pss"),
        ("p256", "sha256", "ecdsa"),
        ("p384", "sha384", "ecdsa"),
    ] {
        let certificate = setup.read(&format!("{name}.der"));
        let job = Job::sign(&certificate, digest, scheme);
        let expected_digest = hex::encode(message_digest(&job, 0));
        let (output, posted) = setup.run_job(&public, job, PIN, true);
        let log = stderr(&output);
        assert!(output.status.success(), "{name} {scheme}: {log}");
        assert!(
            log.contains(&format!("Certificate: CN=Test {name}")),
            "{log}"
        );
        assert!(
            log.contains(&format!("Document digest: {expected_digest}")),
            "{log}"
        );
        assert!(!log.contains("will be shown for confirmation"), "{log}");
        assert_eq!(posted.certificate.as_deref(), Some(&certificate[..]));
        assert!(posted.chain.contains(&setup.read("ca.der")));
        assert!(!posted.chain.contains(&certificate));
        assert!(posted.failure.is_none());
        let signatures = posted.signatures.as_ref().unwrap();
        assert_eq!(signatures.len(), 1);
        setup.verify(name, digest, scheme, &posted.to_sign[0], &signatures[0]);
        assert_eq!(
            posted.requests,
            [
                "GET /.well-known/keyseal.json".to_owned(),
                format!("GET /api/keyseal/v1/jobs/{TOKEN}"),
                format!("POST /api/keyseal/v1/jobs/{TOKEN}/certificate"),
                format!("GET /api/keyseal/v1/jobs/{TOKEN}/documents/0"),
                format!("POST /api/keyseal/v1/jobs/{TOKEN}/signature"),
            ]
        );
        assert_eq!(
            posted.document,
            Some((Some(format!("Bearer {TOKEN}")), Some(NONCE.to_owned())))
        );
    }

    // No certificate before login: the PIN first, then the digest confirm.
    let hidden = setup.read("hidden.der");
    let (output, posted) = setup.run_job(
        &private,
        Job::sign(&hidden, "sha256", "rsa-pkcs1-v1_5"),
        PIN,
        true,
    );
    let log = stderr(&output);
    assert!(output.status.success(), "{log}");
    let pin_prompt = log.find("will be shown for confirmation").expect(&log);
    let confirm = log.find("Signing confirmed").expect(&log);
    assert!(
        pin_prompt < log.find("Document digest").unwrap()
            && log.find("Document digest").unwrap() < confirm
    );
    setup.verify(
        "hidden",
        "sha256",
        "rsa-pkcs1-v1_5",
        &posted.to_sign[0],
        &posted.signatures.unwrap()[0],
    );

    // A batch: one PIN, every document's digest beside its title, and one
    // signature per document from the one session, on both paths.
    let rsa = setup.read("rsa.der");
    for (conf, name, certificate) in [(&public, "rsa", &rsa), (&private, "hidden", &hidden)] {
        let (output, posted) = setup.run_job(conf, Job::batch(certificate, 3), PIN, true);
        let log = stderr(&output);
        assert!(output.status.success(), "{name}: {log}");
        assert!(log.contains("Documents: 3\n  1. Document 1\n"), "{log}");
        // The headless PIN serves one prompt; a second would find it gone.
        assert!(!log.contains("KEYSEAL_PIN isn't set"), "{log}");
        let job = Job::batch(certificate, 3);
        for index in 0..3 {
            let digest = hex::encode(message_digest(&job, index));
            assert!(
                log.contains(&format!("  Document {}: {digest}", index + 1)),
                "{log}"
            );
        }
        let signatures = posted.signatures.unwrap();
        assert_eq!(signatures.len(), 3);
        for (to_sign, signature) in posted.to_sign.iter().zip(&signatures) {
            setup.verify(name, "sha256", "rsa-pkcs1-v1_5", to_sign, signature);
        }
        let downloads: Vec<&String> = posted
            .requests
            .iter()
            .filter(|r| r.contains("/documents/"))
            .collect();
        assert_eq!(downloads.len(), 3, "{:?}", posted.requests);
    }

    // The login-first path with a wrong PIN fails at login, before round 1.
    let (output, posted) = setup.run_job(
        &private,
        Job::sign(&hidden, "sha256", "rsa-pkcs1-v1_5"),
        WRONG_PIN,
        true,
    );
    assert!(!output.status.success());
    assert!(
        posted
            .failure
            .unwrap()
            .starts_with("The token refused the PIN")
    );
    assert!(posted.certificate.is_none());

    // With the wrong PIN, a job that gets as far as the token fails at login...
    let (output, posted) = setup.run_job(
        &public,
        Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5"),
        WRONG_PIN,
        true,
    );
    assert!(!output.status.success());
    assert!(
        posted
            .failure
            .unwrap()
            .starts_with("The token refused the PIN")
    );
    assert!(posted.signatures.is_none());

    // ...so refusals with it show the checks come before the PIN prompt.
    let smime_capabilities = attribute(&oid!(raw 1.2.840.113549.1.9.15), der_tlv(0x30, &[]));
    let p256 = setup.read("p256.der");
    let p384 = setup.read("p384.der");
    let tampered = Job {
        extra: Some(smime_capabilities),
        ..Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5")
    };
    let long_digest = Job {
        digest_len: 48,
        ..Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5")
    };
    let changed_digest = Job {
        job_digest: Some("sha384"),
        ..Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5")
    };
    for (job, refusal) in [
        (tampered, "unexpected attribute 1.2.840.113549.1.9.15"),
        (long_digest, "messageDigest isn't a Sha256 digest"),
        (
            changed_digest,
            "the job said Sha384 but round 1 asked for Sha256",
        ),
        (
            Job::sign(&p256, "sha384", "ecdsa"),
            "which a P256 key doesn't sign",
        ),
        (
            Job::sign(&p384, "sha256", "ecdsa"),
            "which a P384 key doesn't sign",
        ),
        (
            Job::sign(&rsa, "sha256", "ecdsa"),
            "which a Rsa key doesn't sign",
        ),
        (
            Job::sign(&p256, "sha256", "rsa-pss"),
            "which a P256 key doesn't sign",
        ),
    ] {
        let (output, posted) = setup.run_job(&public, job, WRONG_PIN, true);
        let log = stderr(&output);
        assert!(!output.status.success());
        assert!(!log.contains("Document digest"), "{log}");
        let failure = posted.failure.unwrap();
        assert!(
            failure.contains("asked to sign something this helper won't sign")
                && failure.contains(refusal),
            "{failure}"
        );
        assert!(posted.signatures.is_none());
    }

    // A document that doesn't hash to the digest, one such document in a
    // batch, or no document at all, is refused before the PIN prompt...
    let tampered = Job {
        tampered: Some(0),
        ..Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5")
    };
    let tampered_batch = Job {
        tampered: Some(1),
        ..Job::batch(&rsa, 3)
    };
    let missing = Job {
        documents: 0,
        ..Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5")
    };
    for (job, refusal) in [
        (tampered, "The document from http://127.0.0.1"),
        (
            tampered_batch,
            "The document \"Document 2\" from http://127.0.0.1",
        ),
        (
            missing,
            "sent an invalid job: it is a sign job without 1 to 20 documents",
        ),
    ] {
        let (output, posted) = setup.run_job(&public, job, WRONG_PIN, true);
        let log = stderr(&output);
        assert!(!output.status.success());
        assert!(!log.contains("Document digest"), "{log}");
        let failure = posted.failure.unwrap();
        assert!(failure.contains(refusal), "{failure}");
        if !refusal.contains("invalid job") {
            assert!(
                failure.ends_with(
                    "and the digest it asks to sign disagree: the document's digest isn't the digest to be signed."
                ),
                "{failure}"
            );
        }
        assert!(posted.signatures.is_none());
    }

    // ...and, when the PIN comes first, before the digest confirm.
    let (output, posted) = setup.run_job(
        &private,
        Job {
            tampered: Some(0),
            ..Job::sign(&hidden, "sha256", "rsa-pkcs1-v1_5")
        },
        PIN,
        true,
    );
    let log = stderr(&output);
    assert!(!output.status.success());
    assert!(log.contains("will be shown for confirmation"), "{log}");
    assert!(
        !log.contains("Document digest") && !log.contains("Signing confirmed"),
        "{log}"
    );
    assert!(posted.failure.unwrap().contains("disagree"));
    assert!(posted.document.is_some() && posted.signatures.is_none());

    // A job for a certificate this token doesn't hold.
    let (output, posted) = setup.run_job(
        &public,
        Job::sign(&hidden, "sha256", "rsa-pkcs1-v1_5"),
        PIN,
        true,
    );
    assert!(!output.status.success());
    assert!(
        posted
            .failure
            .unwrap()
            .contains("doesn't hold the certificate the job asks for")
    );
    assert!(posted.certificate.is_none());

    // A job whose kind isn't the link's action.
    let mismatch = Job {
        kind: "enrol",
        job_digest: None,
        ..Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5")
    };
    let (output, posted) = setup.run_job(&public, mismatch, PIN, true);
    assert!(!output.status.success());
    assert!(
        posted
            .failure
            .unwrap()
            .contains("The link asked for a Sign job")
    );

    // Enrol logs in and posts the expected certificate with the rest as chain.
    let enrol = Job {
        link_kind: "enrol",
        kind: "enrol",
        job_digest: None,
        ..Job::sign(&p256, "sha256", "ecdsa")
    };
    let (output, posted) = setup.run_job(&public, enrol, PIN, true);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(String::from_utf8_lossy(&output.stdout).contains("Certificate enrolled"));
    assert_eq!(posted.certificate.as_deref(), Some(&p256[..]));
    assert_eq!(posted.chain.len(), 3);

    // An untrusted origin gets no request at all.
    let (output, posted) = setup.run_job(
        &public,
        Job::sign(&rsa, "sha256", "rsa-pkcs1-v1_5"),
        PIN,
        false,
    );
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains(
            "A headless run trusts a new origin only when KEYSEAL_HEADLESS_TRUST_ORIGIN="
        )
    );
    assert!(posted.requests.is_empty());

    // Development origins are never written to the trust store.
    assert!(!setup.dir.join("config").join("trust.json").exists());

    let _ = std::fs::remove_dir_all(&setup.dir);
}

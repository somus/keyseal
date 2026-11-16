//! The worker protocol end to end against SoftHSM: the helper's client
//! starts `keyseal-token-worker`, lists certificates before and after login,
//! has a wrong PIN refused, signs with an RSA and a P-256 key and with an
//! RSA key that needs the PIN for each signature, and closes
//! the worker. A raw session checks that stdout carries only protocol lines
//! and that the worker exits when stdin closes.
//! Runs when `KEYSEAL_SOFTHSM_MODULE` names libsofthsm2, and needs
//! softhsm2-util, pkcs11-tool (OpenSC) and openssl on the PATH. When
//! `KEYSEAL_X86_64_WORKER` and `KEYSEAL_X86_64_SOFTHSM_MODULE` name x86_64
//! builds of the worker and of libsofthsm2, it runs again with those, under
//! Rosetta on an arm64 Mac.

#[path = "../../../testing/softhsm.rs"]
mod fixture;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use keyseal_core::cms::{DigestAlgorithm, SignatureAlgorithm};
use keyseal_core::token::{Driver, LoginError};
use keyseal_core::worker::{self, Runner, WorkerToken};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use fixture::{Objects, PIN, init_token, make_certificate, softhsm_conf, write_objects};

const DATA: &[u8] = b"signed attributes";

/// A SoftHSM token labelled `worker` in `conf`, with an RSA and a P-256 key, and an RSA key with CKA_ALWAYS_AUTHENTICATE, each
/// beside a public, self-signed certificate.
fn make_token(dir: &Path, conf: &Path, module: &str) {
    init_token(conf, "worker");
    let keys: [(&str, &str, &[&str]); 3] = [
        ("rsa", "01", &["-newkey", "rsa:2048"]),
        (
            "p256",
            "02",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
        ),
        ("always", "03", &["-newkey", "rsa:2048"]),
    ];
    for (name, id, newkey) in keys {
        make_certificate(dir, name, &format!("Worker {name}"), newkey, None);
        let objects = Objects {
            always_auth: name == "always",
            ..Objects::default()
        };
        write_objects(dir, module, conf, None, name, id, objects);
    }
}

/// The helper's side of the protocol through [`WorkerToken`].
fn round_trip(dir: &Path, worker: &Path, module: &Path) {
    let rsa = std::fs::read(dir.join("rsa.der")).unwrap();
    let p256 = std::fs::read(dir.join("p256.der")).unwrap();
    let always = std::fs::read(dir.join("always.der")).unwrap();
    let started = WorkerToken::start(worker).unwrap();
    let tokens = started.tokens(module, Duration::ZERO).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(started.shown(tokens[0].slot).len(), 3);
    let token = Box::new(started).open(tokens[0].slot).unwrap();
    assert!(!token.pin_pad());
    assert_eq!(token.pin_warning(), None);
    let public: Vec<Vec<u8>> = token
        .certificates(false)
        .unwrap()
        .into_iter()
        .map(|c| c.der)
        .collect();
    assert!(public.contains(&rsa) && public.contains(&p256));
    // The keys are private objects, invisible before login.
    assert!(token.certificates(true).unwrap().is_empty());
    // A wrong PIN, then the right one in the same session.
    let refused = token.login(Zeroizing::new("0000".into())).unwrap_err();
    assert!(matches!(refused, LoginError::WrongPin), "{refused}");
    token.login(Zeroizing::new(PIN.into())).unwrap();
    assert_eq!(token.certificates(true).unwrap().len(), 3);
    // A job's documents are signed in one request, in the one session; the
    // worker keeps the PIN from login for the key that needs it for each
    // signature, and drops it after that request.
    let documents = [
        DATA.to_vec(),
        b"second document".to_vec(),
        b"third".to_vec(),
    ];
    let sign = |certificate: &[u8], scheme| {
        token.sign(
            certificate,
            &documents,
            DigestAlgorithm::Sha256,
            scheme,
            None,
        )
    };
    for (name, certificate, scheme, scheme_name) in [
        (
            "always",
            &always,
            SignatureAlgorithm::RsaPkcs1v15,
            "rsa-pkcs1-v1_5",
        ),
        (
            "rsa",
            &rsa,
            SignatureAlgorithm::RsaPkcs1v15,
            "rsa-pkcs1-v1_5",
        ),
        ("p256", &p256, SignatureAlgorithm::Ecdsa, "ecdsa"),
    ] {
        let signatures = sign(certificate, scheme).unwrap();
        assert_eq!(signatures.len(), documents.len());
        for (data, signature) in documents.iter().zip(&signatures) {
            fixture::verify(dir, name, "sha256", scheme_name, data, signature);
        }
    }
    let dropped = sign(&always, SignatureAlgorithm::RsaPkcs1v15).unwrap_err();
    assert!(dropped.0.contains("none was kept from login"), "{dropped}");
    token.close();
}

/// Raw lines: every stdout line is a reply, a bad request gets an error
/// reply, and closing stdin ends the worker.
fn raw_session(worker: &Path, module: &Path) {
    let started = WorkerToken::start(worker).unwrap();
    let slot = started.tokens(module, Duration::ZERO).unwrap()[0].slot;
    drop(started);
    let mut child = Command::new(worker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({ "Tokens": { "module": module, "wait": Duration::ZERO } })
    )
    .unwrap();
    writeln!(stdin, "{}", json!({ "Open": { "slot": slot } })).unwrap();
    writeln!(stdin, "not json").unwrap();
    writeln!(
        stdin,
        "{}",
        json!({ "Certificates": { "with_private_key": false } })
    )
    .unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let replies: Vec<Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 4, "{replies:?}");
    assert_eq!(replies[0]["Ok"]["Tokens"][0]["slot"], slot, "{replies:?}");
    assert!(replies[1]["Ok"]["Opened"].is_object(), "{replies:?}");
    assert!(replies[2]["Err"].is_string(), "{replies:?}");
    assert_eq!(
        replies[3]["Ok"]["Certificates"].as_array().unwrap().len(),
        3
    );
}

#[test]
fn worker_runs_softhsm() {
    let Ok(module) = std::env::var("KEYSEAL_SOFTHSM_MODULE") else {
        eprintln!("skipped: set KEYSEAL_SOFTHSM_MODULE to libsofthsm2 to run");
        return;
    };
    let dir = std::env::temp_dir().join(format!("keyseal-worker-softhsm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // One config for the whole test: the workers it starts, native and
    // x86_64, read it from the environment.
    let conf = softhsm_conf(&dir, "tokens");
    // SAFETY: the only test in this binary, and no other thread reads the
    // environment while it is set.
    unsafe { std::env::set_var("SOFTHSM2_CONF", &conf) };
    make_token(&dir, &conf, &module);

    let worker = Path::new(env!("CARGO_BIN_EXE_keyseal-token-worker"));
    round_trip(&dir, worker, Path::new(&module));
    raw_session(worker, Path::new(&module));

    let (Some(worker), Some(module)) = (
        std::env::var_os("KEYSEAL_X86_64_WORKER").map(PathBuf::from),
        std::env::var_os("KEYSEAL_X86_64_SOFTHSM_MODULE").map(PathBuf::from),
    ) else {
        eprintln!(
            "x86_64 run skipped: set KEYSEAL_X86_64_WORKER and KEYSEAL_X86_64_SOFTHSM_MODULE"
        );
        return;
    };
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        assert_eq!(worker::runner_for(&module).unwrap(), Runner::Worker);
    }
    round_trip(&dir, &worker, &module);
    raw_session(&worker, &module);
}

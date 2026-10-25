//! The worker protocol end to end against SoftHSM: the helper's client
//! starts `keyseal-token-worker`, lists certificates before and after login,
//! has a wrong PIN refused, signs with an RSA and a P-256 key, and closes
//! the worker. A raw session checks that stdout carries only protocol lines
//! and that the worker exits when stdin closes.
//! Runs when `KEYSEAL_SOFTHSM_MODULE` names libsofthsm2, and needs
//! softhsm2-util, pkcs11-tool (OpenSC) and openssl on the PATH. When
//! `KEYSEAL_X86_64_WORKER` and `KEYSEAL_X86_64_SOFTHSM_MODULE` name x86_64
//! builds of the worker and of libsofthsm2, it runs again with those, under
//! Rosetta on an arm64 Mac.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use keyseal_core::cms::{DigestAlgorithm, SignatureAlgorithm};
use keyseal_core::token::TokenBackend;
use keyseal_core::worker::{self, Backend, WorkerToken};
use serde_json::{Value, json};
use zeroize::Zeroizing;

const PIN: &str = "1234";
const DATA: &[u8] = b"signed attributes";

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// A SoftHSM token in `dir` with an RSA and a P-256 key, each beside a
/// public certificate.
fn make_token(dir: &Path, module: &str) {
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    std::fs::write(
        dir.join("softhsm2.conf"),
        format!("directories.tokendir = {}\n", dir.join("tokens").display()),
    )
    .unwrap();
    run(Command::new("softhsm2-util").args([
        "--init-token",
        "--free",
        "--label",
        "worker",
        "--pin",
        PIN,
        "--so-pin",
        "5678",
    ]));
    let keys: [(&str, &str, &[&str]); 2] = [
        ("rsa", "01", &["-newkey", "rsa:2048"]),
        (
            "p256",
            "02",
            &["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"],
        ),
    ];
    for (name, id, newkey) in keys {
        run(Command::new("openssl")
            .current_dir(dir)
            .args(["req", "-x509", "-nodes", "-days", "1"])
            .args(["-subj", &format!("/CN=Worker {name}")])
            .args(newkey)
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
        for (file, kind) in [
            (format!("{name}.der"), "cert"),
            (format!("{name}.key"), "privkey"),
        ] {
            let mut command = Command::new("pkcs11-tool");
            command
                .current_dir(dir)
                .args(["--module", module, "--login", "--pin", PIN])
                .args(["--write-object", &file, "--type", kind, "--id", id])
                .args(["--label", name]);
            if kind == "privkey" {
                command.arg("--usage-sign");
            }
            run(&mut command);
        }
    }
}

/// Checks `signature` over `data` with the certificate in `name.der`.
fn verify(dir: &Path, name: &str, data: &[u8], signature: &[u8]) {
    std::fs::write(dir.join("data"), data).unwrap();
    std::fs::write(dir.join("signature"), signature).unwrap();
    let public_key = run(Command::new("openssl").current_dir(dir).args([
        "x509",
        "-inform",
        "DER",
        "-in",
        &format!("{name}.der"),
        "-pubkey",
        "-noout",
    ]));
    std::fs::write(dir.join("public.pem"), public_key.stdout).unwrap();
    run(Command::new("openssl").current_dir(dir).args([
        "dgst",
        "-sha256",
        "-verify",
        "public.pem",
        "-signature",
        "signature",
        "data",
    ]));
}

/// The helper's side of the protocol through [`WorkerToken`].
fn round_trip(dir: &Path, worker: &Path, module: &Path) {
    let rsa = std::fs::read(dir.join("rsa.der")).unwrap();
    let p256 = std::fs::read(dir.join("p256.der")).unwrap();
    let token = WorkerToken::open(worker, module, Duration::ZERO).unwrap();
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
    let refused = token.login(Zeroizing::new("0000".into())).unwrap_err();
    assert!(refused.0.contains("refused the PIN"), "{refused}");
    token.login(Zeroizing::new(PIN.into())).unwrap();
    assert_eq!(token.certificates(true).unwrap().len(), 2);
    // A job's documents are signed in one request, in the one session.
    let documents = [
        DATA.to_vec(),
        b"second document".to_vec(),
        b"third".to_vec(),
    ];
    for (name, certificate, scheme) in [
        ("rsa", &rsa, SignatureAlgorithm::RsaPkcs1v15),
        ("p256", &p256, SignatureAlgorithm::Ecdsa),
    ] {
        let signatures = token
            .sign(
                certificate,
                &documents,
                DigestAlgorithm::Sha256,
                scheme,
                None,
            )
            .unwrap();
        assert_eq!(signatures.len(), documents.len());
        for (data, signature) in documents.iter().zip(&signatures) {
            verify(dir, name, data, signature);
        }
    }
    token.close();
}

/// Raw lines: every stdout line is a reply, a bad request gets an error
/// reply, and closing stdin ends the worker.
fn raw_session(worker: &Path, module: &Path) {
    let mut child = Command::new(worker)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        "{}",
        json!({ "Open": { "module": module, "wait": Duration::ZERO } })
    )
    .unwrap();
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
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert!(replies[0]["Ok"]["Opened"].is_object(), "{replies:?}");
    assert!(replies[1]["Err"].is_string(), "{replies:?}");
    assert_eq!(
        replies[2]["Ok"]["Certificates"].as_array().unwrap().len(),
        2
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
    // SAFETY: the only test in this binary, and no other thread reads the
    // environment while it is set.
    unsafe { std::env::set_var("SOFTHSM2_CONF", dir.join("softhsm2.conf")) };
    make_token(&dir, &module);

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
        assert_eq!(worker::backend_for(&module).unwrap(), Backend::Worker);
    }
    round_trip(&dir, &worker, &module);
    raw_session(&worker, &module);
}

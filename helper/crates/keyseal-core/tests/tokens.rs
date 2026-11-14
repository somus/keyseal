//! Two tokens in one SoftHSM module: both are listed, and the one the
//! signer chooses is opened and signs. Runs when `KEYSEAL_SOFTHSM_MODULE`
//! names libsofthsm2, like the other SoftHSM suites, and needs
//! softhsm2-util, pkcs11-tool (OpenSC) and openssl on the PATH.

use std::process::{Command, Output};

use keyseal_core::cms::{DigestAlgorithm, SignatureAlgorithm};
use keyseal_core::flow;
use keyseal_core::protocol::KeyUsage;
use keyseal_core::token::TokenSummary;
use zeroize::Zeroizing;

const PIN: &str = "1234";

fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn opens_the_token_the_signer_chooses() {
    let Ok(module) = std::env::var("KEYSEAL_SOFTHSM_MODULE") else {
        eprintln!("skipped: set KEYSEAL_SOFTHSM_MODULE to libsofthsm2 to run");
        return;
    };
    let dir = std::env::temp_dir().join(format!("keyseal-core-tokens-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!("directories.tokendir = {}\n", dir.join("tokens").display()),
    )
    .unwrap();
    // SAFETY: the only test in this binary, and no other thread reads the
    // environment while it is set.
    unsafe {
        std::env::set_var("SOFTHSM2_CONF", &conf);
        std::env::set_var("KEYSEAL_PKCS11_MODULE", &module);
    }
    for label in ["first", "second"] {
        run(Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", label])
            .args(["--pin", PIN, "--so-pin", "5678"]));
    }
    // Only the second token holds a certificate and its key.
    run(Command::new("openssl")
        .current_dir(&dir)
        .args([
            "req", "-x509", "-nodes", "-days", "1", "-newkey", "rsa:2048",
        ])
        .args(["-subj", "/CN=ASHA RAO"])
        .args(["-addext", "keyUsage=critical,nonRepudiation"])
        .args(["-keyout", "key.pem", "-outform", "DER", "-out", "cert.der"]));
    run(Command::new("openssl").current_dir(&dir).args([
        "pkey", "-in", "key.pem", "-outform", "DER", "-out", "key.der",
    ]));
    for (file, kind) in [("cert.der", "cert"), ("key.der", "privkey")] {
        run(Command::new("pkcs11-tool")
            .current_dir(&dir)
            .args(["--module", &module, "--token-label", "second"])
            .args(["--login", "--pin", PIN])
            .args(["--write-object", file, "--type", kind, "--id", "01"]));
    }
    let certificate = std::fs::read(dir.join("cert.der")).unwrap();

    let found = flow::open_backend(KeyUsage::NonRepudiation, &mut || Ok(()), &mut |_, _| {})
        .unwrap_or_else(|failure| panic!("{}", failure.message));
    let backend = found
        .open(|tokens| {
            let summaries: Vec<TokenSummary> = tokens
                .iter()
                .map(|token| TokenSummary::of(token, KeyUsage::NonRepudiation))
                .collect();
            let mut labels: Vec<&str> = summaries.iter().map(|t| t.label.as_str()).collect();
            labels.sort();
            assert_eq!(labels, ["first", "second"]);
            let second = summaries.iter().position(|t| t.label == "second").unwrap();
            assert_eq!(summaries[second].names, ["ASHA RAO"]);
            assert!(summaries[1 - second].names.is_empty());
            assert!(summaries[second].model.starts_with("SoftHSM"));
            Ok(second)
        })
        .unwrap_or_else(|failure| panic!("{}", failure.message));
    let token = backend.token();
    let seen: Vec<Vec<u8>> = token
        .certificates(false)
        .unwrap()
        .into_iter()
        .map(|c| c.der)
        .collect();
    assert_eq!(seen, [certificate.clone()]);
    if let Err(error) = token.login(Zeroizing::new(PIN.into())) {
        panic!("{error}");
    }
    let signatures = token
        .sign(
            &certificate,
            &[b"signed attributes".to_vec()],
            DigestAlgorithm::Sha256,
            SignatureAlgorithm::RsaPkcs1v15,
            None,
        )
        .unwrap();
    token.close();
    std::fs::write(dir.join("data"), b"signed attributes").unwrap();
    std::fs::write(dir.join("signature"), &signatures[0]).unwrap();
    let public = run(Command::new("openssl").current_dir(&dir).args([
        "x509", "-inform", "DER", "-in", "cert.der", "-pubkey", "-noout",
    ]));
    std::fs::write(dir.join("public.pem"), public.stdout).unwrap();
    run(Command::new("openssl").current_dir(&dir).args([
        "dgst",
        "-sha256",
        "-verify",
        "public.pem",
        "-signature",
        "signature",
        "data",
    ]));
    std::fs::remove_dir_all(&dir).unwrap();
}

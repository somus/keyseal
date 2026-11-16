//! Two tokens in one SoftHSM module: both are listed, and the one the
//! signer chooses is opened and signs. Runs when `KEYSEAL_SOFTHSM_MODULE`
//! names libsofthsm2, like the other SoftHSM suites, and needs
//! softhsm2-util, pkcs11-tool (OpenSC) and openssl on the PATH.

#[path = "../../../testing/softhsm.rs"]
mod fixture;

use keyseal_core::backend;
use keyseal_core::cms::{DigestAlgorithm, SignatureAlgorithm};
use keyseal_core::protocol::KeyUsage;
use keyseal_core::token::TokenSummary;
use zeroize::Zeroizing;

use fixture::{Objects, PIN, init_token, make_certificate, softhsm_conf, write_objects};

#[test]
fn opens_the_token_the_signer_chooses() {
    let Ok(module) = std::env::var("KEYSEAL_SOFTHSM_MODULE") else {
        eprintln!("skipped: set KEYSEAL_SOFTHSM_MODULE to libsofthsm2 to run");
        return;
    };
    let dir = std::env::temp_dir().join(format!("keyseal-core-tokens-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let conf = softhsm_conf(&dir, "tokens");
    // SAFETY: the only test in this binary, and no other thread reads the
    // environment while it is set.
    unsafe {
        std::env::set_var("SOFTHSM2_CONF", &conf);
        std::env::set_var("KEYSEAL_PKCS11_MODULE", &module);
    }
    for label in ["first", "second"] {
        init_token(&conf, label);
    }
    // Only the second token holds a certificate and its key.
    make_certificate(&dir, "ca", "Test CA", &["-newkey", "rsa:2048"], None);
    make_certificate(
        &dir,
        "cert",
        "ASHA RAO",
        &["-newkey", "rsa:2048"],
        Some("nonRepudiation"),
    );
    write_objects(
        &dir,
        &module,
        &conf,
        Some("second"),
        "cert",
        "01",
        Objects::default(),
    );
    let certificate = std::fs::read(dir.join("cert.der")).unwrap();

    let found = backend::open_backend(KeyUsage::NonRepudiation, &mut || Ok(()), &mut |_, _| {})
        .unwrap_or_else(|error| panic!("{error:?}"));
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
        .unwrap_or_else(|error| panic!("{error:?}"));
    let token = backend.token();
    let seen: Vec<Vec<u8>> = token
        .certificates(false)
        .unwrap()
        .into_iter()
        .map(|c| c.der)
        .collect();
    assert_eq!(seen, std::slice::from_ref(&certificate));
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
    fixture::verify(
        &dir,
        "cert",
        "sha256",
        "rsa-pkcs1-v1_5",
        b"signed attributes",
        &signatures[0],
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

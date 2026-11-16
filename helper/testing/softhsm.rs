//! SoftHSM tokens for the tests, which include this file with `#[path]`:
//! a config file, tokens, certificates made with openssl and written with
//! pkcs11-tool, and a signature checked with `openssl dgst -verify`. Needs
//! softhsm2-util, pkcs11-tool (OpenSC) and openssl on the PATH.

// Each test file uses part of this.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub const PIN: &str = "1234";

/// The key usage of an end-entity signing certificate.
pub const SIGNING: Option<&str> = Some("digitalSignature,nonRepudiation");

/// Runs `command`, failing the test with its stderr unless it succeeds.
pub fn run(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

/// `<dir>/<name>.conf`, a SoftHSM config whose tokens live in
/// `<dir>/<name>/`.
pub fn softhsm_conf(dir: &Path, name: &str) -> PathBuf {
    std::fs::create_dir_all(dir.join(name)).unwrap();
    let conf = dir.join(format!("{name}.conf"));
    std::fs::write(
        &conf,
        format!("directories.tokendir = {}\n", dir.join(name).display()),
    )
    .unwrap();
    conf
}

/// A token labelled `label`, with [`PIN`], among the tokens of `conf`.
pub fn init_token(conf: &Path, label: &str) {
    run(Command::new("softhsm2-util")
        .env("SOFTHSM2_CONF", conf)
        .args(["--init-token", "--free", "--label", label])
        .args(["--pin", PIN, "--so-pin", "5678"]));
}

/// A config of its own, `<dir>/<name>.conf`, holding one token labelled
/// `name`.
pub fn token_with_conf(dir: &Path, name: &str) -> PathBuf {
    let conf = softhsm_conf(dir, name);
    init_token(&conf, name);
    conf
}

/// A certificate `name.der` for `CN=<common_name>` and its key, `name.pem`
/// and `name.key` (DER): with no `key_usage` a self-signed CA, otherwise an
/// end-entity certificate with that key usage issued by `ca.der`.
pub fn make_certificate(
    dir: &Path,
    name: &str,
    common_name: &str,
    newkey: &[&str],
    key_usage: Option<&str>,
) {
    let key_usage = key_usage.map(|usage| format!("keyUsage=critical,{usage}"));
    let extensions: Vec<&str> = match &key_usage {
        None => Vec::new(),
        Some(key_usage) => vec![
            "-CA",
            "ca.der",
            "-CAkey",
            "ca.pem",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            key_usage,
        ],
    };
    run(Command::new("openssl")
        .current_dir(dir)
        .args(["req", "-x509", "-nodes", "-days", "1"])
        .args(["-subj", &format!("/CN={common_name}")])
        .args(newkey)
        .args(&extensions)
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

/// What [`write_objects`] puts on a token besides the certificate.
#[derive(Clone, Copy, Default)]
pub struct Objects {
    /// The certificate alone, without its key.
    pub cert_only: bool,
    /// The certificate as a private object, invisible before login.
    pub private_cert: bool,
    /// A key that needs the PIN for each signature.
    pub always_auth: bool,
}

/// Writes `name`'s certificate and key from `dir`, labelled `name` with
/// `id`, to the token labelled `token` in `conf`, or with `None` to the one
/// token there.
pub fn write_objects(
    dir: &Path,
    module: &str,
    conf: &Path,
    token: Option<&str>,
    name: &str,
    id: &str,
    objects: Objects,
) {
    let mut files = vec![(format!("{name}.der"), "cert")];
    if !objects.cert_only {
        files.push((format!("{name}.key"), "privkey"));
    }
    for (file, kind) in files {
        let mut command = Command::new("pkcs11-tool");
        command
            .current_dir(dir)
            .env("SOFTHSM2_CONF", conf)
            .args(["--module", module])
            .args(
                token
                    .map(|token| ["--token-label", token])
                    .into_iter()
                    .flatten(),
            )
            .args(["--login", "--pin", PIN])
            .args(["--write-object", &file, "--type", kind, "--id", id])
            .args(["--label", name]);
        if kind == "privkey" {
            command.arg("--usage-sign");
            if objects.always_auth {
                command.arg("--always-auth");
            }
        }
        if kind == "cert" && objects.private_cert {
            command.arg("--private");
        }
        run(&mut command);
    }
}

/// Checks `signature` over `data` with the certificate in `dir/name.der`,
/// hashed with `digest` (`sha256` or `sha384`); `scheme` is the protocol's
/// name, of which only `rsa-pss` changes the check.
pub fn verify(dir: &Path, name: &str, digest: &str, scheme: &str, data: &[u8], signature: &[u8]) {
    std::fs::write(dir.join("to-sign"), data).unwrap();
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
    let mut command = Command::new("openssl");
    command
        .current_dir(dir)
        .args(["dgst", &format!("-{digest}"), "-verify", "public.pem"]);
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

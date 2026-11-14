//! The gallery's sample data.

#[cfg(feature = "gallery")]
use std::sync::mpsc;

#[cfg(feature = "gallery")]
use gpui_kit::App;
use keyseal_core::doctor::{Driver, DriverState, Report, Status};
#[cfg(feature = "gallery")]
use keyseal_core::flow::Step;
#[cfg(feature = "gallery")]
use keyseal_core::modules;
#[cfg(feature = "gallery")]
use keyseal_core::protocol::Kind;
#[cfg(feature = "gallery")]
use keyseal_core::trust::TrustStore;

#[cfg(feature = "gallery")]
use super::Windows;
#[cfg(feature = "gallery")]
use super::job::set_always_show_details;
#[cfg(feature = "gallery")]
use super::settings::open_settings;
#[cfg(feature = "gallery")]
use crate::{Job, Probe, Request, Stage, strings};

/// Every view [`gallery`] opens.
#[cfg(feature = "gallery")]
pub const GALLERY_VIEWS: &[&str] = &[
    "trust",
    "trust-insecure",
    "pin",
    "pin-details",
    "pin-plain",
    "pin-opaque",
    "pin-pad",
    "pin-warning",
    "pin-wrong",
    "pin-final-try",
    "pin-batch",
    "pin-batch-details",
    "confirm",
    "choose",
    "choose-many",
    "enrol",
    "busy",
    "progress-connecting",
    "progress-certificate",
    "message",
    "message-driver",
    "message-pin-locked",
    "message-expired",
    "message-link",
    "message-internal",
    "busy-message",
    "settings",
    "settings-empty",
    "settings-checking",
    "settings-driver-failed",
];

/// What a probe might find on a Mac with a HYP2003 plugged in: `status`,
/// with the plugged-in driver used, failed, or seeing no token.
#[cfg(any(feature = "gallery", test))]
pub(crate) fn sample_report(status: Status) -> Report {
    use keyseal_core::doctor::Device;
    let plugged = match &status {
        Status::Ready => DriverState::Used,
        Status::NoToken => DriverState::NoToken,
        Status::Failed(reason) => DriverState::Failed(reason.clone()),
    };
    let devices = match &status {
        Status::NoToken => vec![],
        _ => vec![Device {
            id: "2ccf:080a".into(),
            product: Some("HYP2003".into()),
            token: Some("HyperSecu HYP2003".into()),
        }],
    };
    let mut drivers = vec![
        Driver {
            name: "libcastle.dylib".into(),
            detail: "/usr/local/lib/libcastle.dylib [catalogue, HyperSecu HYP2003 plugged in]"
                .into(),
            token: Some("HyperSecu HYP2003".into()),
            state: plugged,
        },
        Driver {
            name: "libeTPkcs11.dylib".into(),
            detail: "/usr/local/lib/libeTPkcs11.dylib [known drivers]".into(),
            token: None,
            state: DriverState::NoToken,
        },
        Driver {
            name: "libmtoken.dylib".into(),
            detail: "/usr/local/lib/libmtoken.dylib [known drivers]".into(),
            token: None,
            state: DriverState::Missing,
        },
    ];
    // The keychain is looked at once no driver reaches a token.
    if status != Status::Ready {
        drivers.push(Driver {
            name: "macOS keychain".into(),
            detail: "the macOS keychain (CryptoTokenKit)".into(),
            token: None,
            state: DriverState::Empty,
        });
    }
    Report {
        devices,
        drivers,
        text: "keyseal 0.1.0\nOS: macos aarch64\nTokens: sample\n".into(),
        status,
    }
}

/// Opens `view` with sample data. Answers go nowhere.
#[cfg(feature = "gallery")]
pub(crate) fn gallery(view: &str, cx: &mut App) {
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const CERTIFICATE: &str = "ASHA RAO (Verasys Sub CA 2022), valid until 12 March 2027";
    let job = |kind| Job {
        host: "sign.example.org".into(),
        insecure: view == "choose-many",
        brand: Some(crate::Brand {
            name: "Example Trust".into(),
            icon: (!view.ends_with("-plain"))
                .then(|| include_bytes!("../../examples/sample-logo.png").to_vec()),
            accent: Some(0xe8590c),
            translucent: !view.ends_with("-opaque"),
        }),
        kind,
        claimed: true,
        title: "Circular 2026/14: Operation of bank accounts".into(),
        signer: "Asha Rao".into(),
        documents: vec!["Circular 2026/14: Operation of bank accounts".into()],
    };
    let pin =
        |certificate: Option<&str>, digest: Option<&str>, pin_pad, warning, wrong_pin| Stage::Pin {
            certificate: certificate.map(Into::into),
            digests: digest.map(|digest| vec![digest.into()]),
            pin_pad,
            warning,
            wrong_pin,
            reply: mpsc::channel().0,
        };
    let mut windows = Windows::new(|_| {});
    // pin-details: the signer chose to always see the technical details.
    set_always_show_details(matches!(view, "pin-details" | "pin-batch-details"), cx);
    if view.starts_with("pin-batch") {
        // The most a job may carry, one of them with a title that must wrap.
        let mut documents: Vec<String> = (1..=20)
            .map(|n| format!("Resolution 2026/{n:02}: Annual accounts and audit"))
            .collect();
        documents[0] = "Minutes of the 41st meeting of the Board of Trustees held at the registered office on 12 March 2026, with annexures A to F and the statement of accounts".into();
        let digests = (0..documents.len())
            .map(|n| format!("{n:02x}{}", &DIGEST[2..]))
            .collect();
        let mut batch = job(Kind::Sign);
        batch.title = "Board pack for March 2026, 20 documents".into();
        batch.documents = documents;
        windows.handle(
            Request::Job {
                job: batch,
                stage: Stage::Pin {
                    certificate: Some(CERTIFICATE.into()),
                    digests: Some(digests),
                    pin_pad: false,
                    warning: None,
                    wrong_pin: false,
                    reply: mpsc::channel().0,
                },
            },
            cx,
        );
        std::mem::forget(windows);
        return;
    }
    let stage = match view {
        "trust" | "trust-insecure" => {
            windows.handle(
                Request::Trust {
                    host: if view == "trust" {
                        "sign.example.org".into()
                    } else {
                        "localhost:3021".into()
                    },
                    insecure: view == "trust-insecure",
                    reply: mpsc::channel().0,
                },
                cx,
            );
            return;
        }
        "message" | "message-driver" | "message-pin-locked" | "message-expired"
        | "message-link" | "message-internal" => {
            let message = match view {
                "message" => {
                    "The signing service refused the signature: the certificate has expired.".into()
                }
                "message-driver" => format!(
                    "{} Install your token's driver, then try again.",
                    modules::NO_DRIVER
                ),
                "message-pin-locked" => keyseal_core::token::PIN_LOCKED.into(),
                "message-expired" => {
                    let expired =
                        include_bytes!("../../../keyseal-core/tests/fixtures/expired.der");
                    keyseal_core::token::outside_validity(expired, i64::MAX).unwrap_or_default()
                }
                "message-link" => keyseal_core::protocol::DAMAGED_LINK.into(),
                _ => keyseal_core::flow::INTERNAL_ERROR.into(),
            };
            windows.message(strings::ERROR_HEADING, message, None, cx);
            return;
        }
        "busy-message" => {
            windows.busy(cx);
            return;
        }
        // Before the claim: the host only, never branding.
        "progress-connecting" => {
            windows.handle(
                Request::Job {
                    job: Job {
                        brand: None,
                        claimed: false,
                        title: String::new(),
                        signer: String::new(),
                        documents: Vec::new(),
                        ..job(Kind::Sign)
                    },
                    stage: Stage::Progress(Step::Connecting),
                },
                cx,
            );
            std::mem::forget(windows);
            return;
        }
        "progress-certificate" => Stage::Progress(Step::CheckingCertificate),
        "settings" | "settings-empty" | "settings-checking" | "settings-driver-failed" => {
            let dir = std::env::temp_dir().join(format!("keyseal-gallery-{view}"));
            let _ = std::fs::remove_dir_all(&dir);
            if view == "settings" {
                let store = TrustStore::new(&dir);
                for url in ["https://sign.example.org/", "https://dash.example.org/"] {
                    let url = url::Url::parse(url).expect("sample URL");
                    let origin =
                        keyseal_core::origin::Origin::of_url(&url, false).expect("sample origin");
                    store.trust(&origin).expect("sample trust store");
                }
            }
            let probe: Probe = match view {
                "settings" => || Ok(sample_report(Status::Ready)),
                "settings-empty" => || Ok(sample_report(Status::NoToken)),
                "settings-checking" => || {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                    Err("Timed out.".into())
                },
                _ => || {
                    Ok(sample_report(Status::Failed(
                        "Couldn't start the token driver: the driver is for another kind of Mac."
                            .into(),
                    )))
                },
            };
            open_settings(dir, |_| {}, probe, cx);
            return;
        }
        // pin-plain: a brand without a logo; pin-opaque: a brand that asks
        // for opaque windows.
        "pin" | "pin-details" | "pin-plain" | "pin-opaque" => {
            pin(Some(CERTIFICATE), Some(DIGEST), false, None, false)
        }
        "pin-pad" => pin(Some(CERTIFICATE), Some(DIGEST), true, None, false),
        "pin-warning" => pin(None, None, false, Some(strings::PIN_COUNT_LOW), false),
        // The token refused the PIN just entered, then says one try is left.
        "pin-wrong" => pin(Some(CERTIFICATE), Some(DIGEST), false, None, true),
        "pin-final-try" => pin(
            Some(CERTIFICATE),
            Some(DIGEST),
            false,
            Some(strings::PIN_FINAL_TRY),
            true,
        ),
        "confirm" => Stage::Confirm {
            certificate: CERTIFICATE.into(),
            digests: vec![DIGEST.into()],
            reply: mpsc::channel().0,
        },
        "choose" => Stage::Choose {
            subjects: vec![
                "ASHA RAO (Verasys Sub CA 2022), signing, valid until 12 March 2027".into(),
                "ASHA RAO (Verasys Sub CA 2022), encryption, valid until 12 March 2027".into(),
                "ASHA RAO (eMudhra Sub CA 2023), signing, valid until 2 June 2028".into(),
            ],
            reply: mpsc::channel().0,
        },
        // More certificates than the window holds, under the insecure banner.
        "choose-many" => Stage::Choose {
            subjects: (1..=8)
                .map(|n| {
                    format!("ASHA RAO (Verasys Sub CA 2022), signing, valid until {n} March 2027")
                })
                .collect(),
            reply: mpsc::channel().0,
        },
        "enrol" => Stage::Enrol {
            reply: mpsc::channel().0,
        },
        _ => Stage::Busy,
    };
    let kind = if matches!(view, "enrol" | "choose" | "pin-warning") {
        Kind::Enrol
    } else {
        Kind::Sign
    };
    windows.handle(
        Request::Job {
            job: job(kind),
            stage,
        },
        cx,
    );
    // Keeps the window's state for the app's lifetime.
    std::mem::forget(windows);
}

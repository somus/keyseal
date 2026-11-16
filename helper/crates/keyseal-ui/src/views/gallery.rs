//! The gallery's sample data.

use std::sync::mpsc;

use gpui_kit::App;
use keyseal_core::certificate::CertificateSummary;
use keyseal_core::doctor::Status;
use keyseal_core::flow::Step;
use keyseal_core::modules;
use keyseal_core::protocol::Kind;
use keyseal_core::token::TokenSummary;
use keyseal_core::trust::TrustStore;

use super::job::set_always_show_details;
use super::sample::sample_report;
use super::settings::open_settings;
use super::{MessageKind, Windows};
use crate::Probe;
use crate::bridge::{Brand, Job, Request, Stage};
use crate::strings;

/// Every view [`gallery`] opens.
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
    "choose-token",
    "pin-token",
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

/// Opens `view` with sample data, or fails on a view it doesn't know.
/// Answers go nowhere.
pub(crate) fn gallery(view: &str, cx: &mut App) -> Result<(), String> {
    const DIGEST: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const CERTIFICATE: &str = "ASHA RAO (Verasys Sub CA 2022), valid until 12 March 2027";
    let job = |kind| Job {
        host: "sign.example.org".into(),
        insecure: view == "choose-many",
        brand: Some(Brand {
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
            // pin-token: several tokens were plugged in.
            token: (view == "pin-token").then(|| "HYP2003".into()),
            certificate: certificate.map(Into::into),
            digests: digest.map(|digest| vec![digest.into()]),
            pin_pad,
            warning,
            wrong_pin,
            reply: mpsc::channel().0,
        };
    let certificate = |issuer: &str, valid_until: &str, serial_end: &str| CertificateSummary {
        name: "ASHA RAO".into(),
        issuer: issuer.into(),
        valid_until: valid_until.into(),
        serial_end: serial_end.into(),
    };
    let mut windows = Windows::default();
    // pin-details: the signer chose to always see the technical details.
    set_always_show_details(matches!(view, "pin-details" | "pin-batch-details"), cx);
    if matches!(view, "pin-batch" | "pin-batch-details") {
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
                    token: None,
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
        return Ok(());
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
            return Ok(());
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
                    keyseal_core::certificate::outside_validity(expired, i64::MAX)
                        .unwrap_or_default()
                }
                "message-link" => keyseal_core::protocol::DAMAGED_LINK.into(),
                _ => keyseal_core::flow::INTERNAL_ERROR.into(),
            };
            windows.message(MessageKind::Error, message, None, cx);
            return Ok(());
        }
        "busy-message" => {
            windows.busy(cx);
            return Ok(());
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
            return Ok(());
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
            open_settings(dir, probe, cx);
            return Ok(());
        }
        // pin-plain: a brand without a logo; pin-opaque: a brand that asks
        // for opaque windows.
        "pin" | "pin-details" | "pin-plain" | "pin-opaque" | "pin-token" => {
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
        // A renewed certificate beside the one it replaces, and one from
        // another issuer whose name is long.
        "choose" => Stage::Choose {
            certificates: vec![
                certificate("Verasys Sub CA 2022", "12 March 2027", "4F A1 9C"),
                certificate("Verasys Sub CA 2022", "2 February 2027", "0B 7E 31"),
                certificate(
                    "e-Mudhra Sub CA for Class 3 Individual 2022",
                    "2 June 2028",
                    "9C 02 D4",
                ),
            ],
            reply: mpsc::channel().0,
        },
        // More certificates than the window holds, under the insecure banner.
        "choose-many" => Stage::Choose {
            certificates: (1..=8)
                .map(|n| {
                    certificate(
                        "Verasys Sub CA 2022",
                        &format!("{n} March 2027"),
                        &format!("4F A1 {n:02X}"),
                    )
                })
                .collect(),
            reply: mpsc::channel().0,
        },
        // Two tokens that show their certificates before login, one with two
        // signers on it, and one that shows none.
        "choose-token" => Stage::ChooseToken {
            tokens: vec![
                TokenSummary {
                    label: "ePass2003".into(),
                    model: "Feitian ePass2003".into(),
                    serial: "2A8F0C1B00049813".into(),
                    names: vec!["ASHA RAO".into()],
                },
                TokenSummary {
                    label: "HYP2003".into(),
                    model: "HyperSecu HYP2003".into(),
                    serial: "HS0322771940".into(),
                    names: vec!["ASHA RAO".into(), "VIKRAM MEHTA".into()],
                },
                TokenSummary {
                    label: "SafeNet eToken 5110".into(),
                    model: "SafeNet, Inc. eToken 5110 CC".into(),
                    serial: "02A7D4E1".into(),
                    names: Vec::new(),
                },
            ],
            reply: mpsc::channel().0,
        },
        "enrol" => Stage::Enrol {
            reply: mpsc::channel().0,
        },
        "busy" => Stage::Busy,
        _ => return Err(format!("No gallery view {view}.")),
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use gpui_kit::TestAppContext;

    use super::{GALLERY_VIEWS, gallery};
    use crate::views::testing::setup;

    /// Every view the gallery lists opens: none falls through to another.
    #[gpui_kit::test]
    fn opens_every_view(cx: &mut TestAppContext) {
        setup(cx);
        for view in GALLERY_VIEWS {
            cx.update(|cx| {
                assert_eq!(gallery(view, cx), Ok(()), "{view}");
                // Closed before settings-checking's probe, which never
                // ends, can start.
                for window in cx.windows() {
                    let _ = window.update(cx, |_, window, _| window.remove_window());
                }
            });
        }
    }
}

//! What the windows' tests share.

use gpui_kit::{AnyWindowHandle, TestAppContext};
use keyseal_core::protocol::Kind;
use keyseal_core::token::CertificateSummary;

use keyseal_core::doctor::{Report, Status};

use crate::views::widgets::INPUT_DELAY;
use crate::views::{Windows, key_bindings, sample_report};
use crate::{Brand, Job};

pub(super) const DIGEST: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

pub(super) fn log(_: &str) {}

pub(super) fn probe() -> Result<Report, String> {
    Ok(sample_report(Status::Ready))
}

pub(super) fn temp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("keyseal-ui-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

pub(super) fn setup(cx: &mut TestAppContext) -> Windows {
    cx.update(|cx| {
        gpui_kit::init(cx);
        cx.bind_keys(key_bindings());
    });
    Windows::new(log)
}

pub(super) fn job() -> Job {
    Job {
        host: "dash.example.org".into(),
        insecure: false,
        brand: Some(Brand {
            name: "Example Trust".into(),
            icon: None,
            accent: Some(0x1f6feb),
            translucent: true,
        }),
        kind: Kind::Sign,
        claimed: true,
        title: "Lease agreement".into(),
        signer: "A. Signer".into(),
        documents: vec!["Lease agreement".into()],
    }
}

pub(super) fn open_windows(cx: &mut TestAppContext) -> Vec<AnyWindowHandle> {
    cx.update(|cx| cx.windows())
}

/// Lets [`INPUT_DELAY`] pass, after which confirming buttons respond.
pub(super) fn pass_input_delay(cx: &mut TestAppContext) {
    cx.executor().advance_clock(INPUT_DELAY);
    cx.run_until_parked();
}

/// A certificate named `name` from the same issuer as every other.
pub(super) fn certificate(name: &str) -> CertificateSummary {
    CertificateSummary {
        name: name.into(),
        issuer: "Verasys Sub CA 2022".into(),
        valid_until: "12 March 2027".into(),
        serial_end: "4F A1 9C".into(),
    }
}

//! Sample data the gallery and the tests share.

use keyseal_core::doctor::{Device, Driver, DriverState, Report, Status};

/// What a probe might find on a Mac with a HYP2003 plugged in: `status`,
/// with the plugged-in driver used, failed, or seeing no token.
pub(crate) fn sample_report(status: Status) -> Report {
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

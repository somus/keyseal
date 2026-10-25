//! Every string the windows show, in English (docs/design.md: one table).

macro_rules! strings {
    ($($name:ident = $text:expr;)*) => {
        $(pub const $name: &str = $text;)*

        #[cfg(test)]
        pub const ALL: &[(&str, &str)] = &[$((stringify!($name), $text)),*];
    };
}

strings! {
    APP_NAME = "KeySeal";
    SETTINGS_MENU_ITEM = "Settings...";

    TRUST_WINDOW_TITLE = "New site";
    TRUST_ASK = "wants to use KeySeal for the first time";
    TRUST_EXPLANATION = "Allow it only if you just asked this site to sign a document or set up your certificate.";
    TRUST = "Allow";
    CANCEL = "Cancel";

    SIGN_WINDOW_TITLE = "Sign a document";
    SIGN_BATCH_WINDOW_TITLE = "Sign documents";
    ENROL_WINDOW_TITLE = "Enrol a certificate";
    INSECURE_BANNER = "Test site: this connection isn't secure, so KeySeal won't remember it.";
    SIGN_ASK = "wants you to sign a document";
    SIGN_BATCH_ASK = "wants you to sign several documents";
    ENROL_ASK = "wants to set up your signing certificate";
    TITLE = "Document";
    // "{count}" is the number of documents, two or more.
    DOCUMENT_COUNT = "{count} documents";
    SIGNER = "Signing as";
    SHOW_DETAILS = "Show technical details";
    HIDE_DETAILS = "Hide technical details";
    CERTIFICATE = "Certificate";
    DIGEST = "Document fingerprint (digest)";
    PIN = "Token PIN";
    PIN_PLACEHOLDER = "Enter your token's PIN";
    PIN_PAD = "Enter your PIN on the token's keypad when it asks.";
    DIGEST_NEXT = "You'll check the document once more before it's signed.";
    DIGESTS_NEXT = "You'll check the documents once more before they're signed.";
    ENROL_NOTE = "Your PIN unlocks your token so KeySeal can find your certificate.";
    CONFIRM_NOTE = "Make sure this is the document you meant to sign, then confirm.";
    CONFIRM_BATCH_NOTE = "Make sure these are the documents you meant to sign, then confirm.";
    ENROL_STORE_NOTE = "Next, KeySeal looks for your certificate in Windows.";
    CHOOSE_NOTE = "Your token holds more than one certificate. Choose the one to use.";
    WORKING = "Working...";
    SIGN = "Sign";
    CONTINUE = "Continue";
    CONFIRM = "Confirm";

    ERROR_HEADING = "Something went wrong";
    INFO_HEADING = "Please note";
    BUSY_HEADING = "KeySeal is busy";
    BUSY = "Finish or cancel the job in progress, then open the link again.";
    DOCTOR_HINT = "Tokens and drivers shows what KeySeal found, with details you can copy for support.";
    CLOSE = "Close";

    SETTINGS_WINDOW_TITLE = "KeySeal settings";
    TRUSTED_SITES = "Trusted sites";
    NO_TRUSTED_SITES = "No sites yet. Sites you allow appear here.";
    FORGET = "Forget";
    SIGNING = "Signing";
    ALWAYS_SHOW_DETAILS = "Always show technical details";
    ALWAYS_SHOW_DETAILS_NOTE = "Shows the certificate and the document fingerprints before you sign, without a click.";
    TOKENS = "Tokens and drivers";
    CHECKING_TOKENS = "Looking for your token...";
    TOKEN_READY = "Your token is ready";
    TOKEN_READY_NOTE = "KeySeal can sign with it.";
    NO_TOKEN_FOUND = "No token found";
    NO_TOKEN_NOTE = "Plug in your token, wait a moment, then select Refresh.";
    TOKEN_PROBLEM = "KeySeal can't use your token";
    CHECK_FAILED = "KeySeal couldn't check your token";
    DRIVER_USED = "Driver working";
    DRIVER_NO_TOKEN = "Driver installed, but it doesn't see the token";
    DRIVER_FAILED = "Driver didn't work";
    DRIVER_MISSING = "Driver not installed";
    DRIVER_NOT_TRIED = "Driver installed, not needed";
    NO_DRIVER_LISTED = "No driver is known for this computer";
    REFRESH = "Refresh";
    COPY_DIAGNOSTICS = "Copy diagnostics";
    COPIED = "Copied";
    DIAGNOSTICS_NOTE = "Copy diagnostics and paste them into a message to your support team.";
    APPEARANCE = "Appearance";
    TRANSLUCENT_WINDOWS = "Transparent windows";
    TRANSLUCENT_NOTE = "Lets the desktop show through. Reduce transparency in System Settings also turns it off.";
    ABOUT = "About";
    VERSION = "Version";
    CONFIG_DIRECTORY = "Config directory";

    NO_GPU = "KeySeal can't open its window: no compatible graphics device (GPU) is available.";
}

#[cfg(test)]
mod tests {
    use super::ALL;

    #[test]
    fn every_string_is_plain_english_text() {
        assert!(ALL.len() > 30);
        for (name, text) in ALL {
            assert!(!text.is_empty(), "{name} is empty");
            assert_eq!(text.trim(), *text, "{name} has outer whitespace");
            assert!(text.is_ascii(), "{name} isn't ASCII");
            assert!(!text.contains("  "), "{name} has a double space");
            assert!(
                text.chars().next().is_some_and(|c| !c.is_ascii_lowercase())
                    // These follow the site's name: "example.org wants ...".
                    || name.ends_with("_ASK"),
                "{name} starts in lowercase"
            );
        }
    }

    #[test]
    fn names_and_texts_are_unique() {
        for (i, (name, text)) in ALL.iter().enumerate() {
            for (other_name, other_text) in &ALL[i + 1..] {
                assert_ne!(name, other_name);
                assert_ne!(text, other_text, "{name} and {other_name} repeat a string");
            }
        }
    }
}

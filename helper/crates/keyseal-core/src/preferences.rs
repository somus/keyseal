//! The signer's own choices for the helper, as `preferences.json` in the
//! helper's config directory. A missing or damaged file means the defaults.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Preferences {
    /// Translucent windows where the platform has them (glass on macOS).
    pub translucent_windows: bool,
    /// The job window opens with the certificate and digest shown.
    pub always_show_details: bool,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            translucent_windows: true,
            always_show_details: false,
        }
    }
}

impl Preferences {
    fn path(config_dir: &Path) -> PathBuf {
        config_dir.join("preferences.json")
    }

    pub fn load(config_dir: &Path) -> Self {
        std::fs::read(Self::path(config_dir))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Writes beside the file and renames, so a crash never leaves half a file.
    pub fn save(&self, config_dir: &Path) -> Result<(), String> {
        let path = Self::path(config_dir);
        let error = |e: std::io::Error| format!("Couldn't write {}: {e}", path.display());
        std::fs::create_dir_all(config_dir).map_err(error)?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        let temporary = path.with_extension("json.tmp");
        std::fs::write(&temporary, bytes).map_err(error)?;
        std::fs::rename(&temporary, &path).map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_round_trip_and_default_when_missing_or_damaged() {
        let dir = std::env::temp_dir().join(format!("keyseal-preferences-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(Preferences::load(&dir), Preferences::default());
        assert!(Preferences::load(&dir).translucent_windows);
        assert!(!Preferences::load(&dir).always_show_details);

        let changed = Preferences {
            translucent_windows: false,
            always_show_details: true,
        };
        changed.save(&dir).unwrap();
        assert_eq!(Preferences::load(&dir), changed);
        let saved = std::fs::read_to_string(dir.join("preferences.json")).unwrap();
        assert!(saved.contains(r#""alwaysShowDetails": true"#), "{saved}");

        // A file from before a setting existed keeps that setting's default.
        std::fs::write(
            dir.join("preferences.json"),
            br#"{"translucentWindows":false}"#,
        )
        .unwrap();
        assert_eq!(
            Preferences::load(&dir),
            Preferences {
                translucent_windows: false,
                always_show_details: false,
            }
        );

        std::fs::write(dir.join("preferences.json"), b"{not json").unwrap();
        assert_eq!(Preferences::load(&dir), Preferences::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

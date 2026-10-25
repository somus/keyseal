//! The branding manifest (section 6): fetched per job after trust and
//! before the claim, with the icon, within 2 seconds; a cached copy stands
//! in when the fetch fails. A manifest never affects trust.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use ureq::Agent;

use crate::origin::Origin;
use crate::protocol::{VERSION_HEADER, plain};
use crate::token::sha256_hex;

const BUDGET: Duration = Duration::from_secs(2);
const MAX_MANIFEST_BYTES: u64 = 16_384;
const MAX_ICON_BYTES: u64 = 262_144;
const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub protocol: u64,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    /// `false` asks for opaque job windows where the helper would use
    /// translucent ones (section 6.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub translucent: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_helper_version: Option<String>,
}

impl Manifest {
    /// The manifest in `bytes` if section 6.2 allows it.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let mut manifest: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        manifest.name = plain(&manifest.name);
        if manifest.protocol != 1 {
            return Err(format!("protocol {} isn't 1", manifest.protocol));
        }
        if !(1..=64).contains(&manifest.name.chars().count()) {
            return Err("name isn't 1 to 64 characters".into());
        }
        if let Some(color) = &manifest.accent_color
            && !(color.len() == 7
                && color.starts_with('#')
                && color[1..].bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("accentColor isn't #rrggbb".into());
        }
        if let Some(version) = &manifest.min_helper_version {
            semver::Version::parse(version).map_err(|e| format!("minHelperVersion: {e}"))?;
        }
        Ok(manifest)
    }

    /// Whether this helper is older than `minHelperVersion` (section 6.2).
    pub fn needs_newer_helper(&self) -> bool {
        let minimum = self
            .min_helper_version
            .as_deref()
            .and_then(|v| semver::Version::parse(v).ok());
        let current = semver::Version::parse(crate::VERSION).ok();
        matches!((minimum, current), (Some(minimum), Some(current)) if current < minimum)
    }
}

#[derive(Clone, Debug)]
pub struct Branding {
    pub manifest: Manifest,
    /// PNG bytes, when the manifest names a usable icon.
    pub icon: Option<Vec<u8>>,
}

/// The origin's branding: fetched, or cached in `cache_dir` from an earlier
/// fetch, or `None`.
pub fn branding(origin: &Origin, cache_dir: &Path) -> Option<Branding> {
    let deadline = Instant::now() + BUDGET;
    let agent = origin.agent(BUDGET);
    let (manifest_path, icon_path) = cache_paths(origin, cache_dir);
    let url = format!("{origin}/.well-known/keyseal.json");
    let Ok(manifest) =
        get(&agent, &url, MAX_MANIFEST_BYTES, deadline).and_then(|bytes| Manifest::parse(&bytes))
    else {
        let manifest = std::fs::read(&manifest_path)
            .ok()
            .and_then(|bytes| Manifest::parse(&bytes).ok())?;
        let icon = std::fs::read(&icon_path).ok();
        return Some(Branding { manifest, icon });
    };
    let icon = manifest
        .icon
        .as_deref()
        .and_then(|icon| url::Url::parse(icon).ok())
        .filter(|icon| origin.contains(icon))
        .and_then(|icon| get(&agent, icon.as_str(), MAX_ICON_BYTES, deadline).ok())
        .filter(|bytes| bytes.starts_with(PNG_SIGNATURE));
    // The cache is a convenience; failing to write it doesn't stop the job.
    if std::fs::create_dir_all(cache_dir).is_ok()
        && let Ok(bytes) = serde_json::to_vec(&manifest)
    {
        let _ = std::fs::write(&manifest_path, bytes);
        let _ = match &icon {
            Some(icon) => std::fs::write(&icon_path, icon),
            None => std::fs::remove_file(&icon_path),
        };
    }
    Some(Branding { manifest, icon })
}

fn cache_paths(origin: &Origin, cache_dir: &Path) -> (PathBuf, PathBuf) {
    let key = sha256_hex(origin.as_string().as_bytes());
    (
        cache_dir.join(format!("{key}.json")),
        cache_dir.join(format!("{key}.png")),
    )
}

/// A `200` body of at most `limit` bytes, before `deadline`.
fn get(agent: &Agent, url: &str, limit: u64, deadline: Instant) -> Result<Vec<u8>, String> {
    let timeout = deadline
        .checked_duration_since(Instant::now())
        .ok_or("out of time")?;
    let mut response = agent
        .get(url)
        .header(VERSION_HEADER, crate::VERSION)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .map_err(|e| e.to_string())?;
    if response.status() != 200 {
        return Err(format!("status {}", response.status()));
    }
    response
        .body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_manifests() {
        let manifest = Manifest::parse(
            br##"{"protocol":1,"name":"Example Trust","icon":"https://dash.example.org/i.png","accentColor":"#1F6feb","translucent":false,"minHelperVersion":"1.0.0","modulePath":"/tmp/evil.so"}"##,
        )
        .unwrap();
        assert_eq!(manifest.name, "Example Trust");
        assert_eq!(manifest.accent_color.as_deref(), Some("#1F6feb"));
        assert_eq!(manifest.translucent, Some(false));
        for bad in [
            &br#"{"protocol":2,"name":"x"}"#[..],
            br#"{"protocol":1,"name":""}"#,
            br#"{"protocol":1}"#,
            br##"{"protocol":1,"name":"x","accentColor":"#12345"}"##,
            br#"{"protocol":1,"name":"x","accentColor":"1234567"}"#,
            br#"{"protocol":1,"name":"x","minHelperVersion":"1.0"}"#,
            b"[]",
        ] {
            assert!(
                Manifest::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
        let long = format!(r#"{{"protocol":1,"name":"{}"}}"#, "x".repeat(65));
        assert!(Manifest::parse(long.as_bytes()).is_err());
    }

    #[test]
    fn compares_helper_versions() {
        let manifest = |version: &str| Manifest {
            protocol: 1,
            name: "x".into(),
            icon: None,
            accent_color: None,
            translucent: None,
            min_helper_version: Some(version.into()),
        };
        assert!(manifest("99.0.0").needs_newer_helper());
        assert!(!manifest(crate::VERSION).needs_newer_helper());
        assert!(!manifest("0.0.1").needs_newer_helper());
    }
}

//! Trust on first use (section 5): a JSON file of trusted origins, each with
//! the time it was trusted, in the helper's config directory.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::origin::Origin;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    /// `scheme://host[:port]`, host in A-label form.
    pub origin: String,
    /// Seconds since the Unix epoch.
    pub trusted_at: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    origins: Vec<Record>,
}

pub struct TrustStore {
    path: PathBuf,
}

impl TrustStore {
    /// The store in `config_dir`, as `trust.json`.
    pub fn new(config_dir: &Path) -> Self {
        Self {
            path: config_dir.join("trust.json"),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn list(&self) -> Result<Vec<Record>, String> {
        Ok(self.read()?.origins)
    }

    pub fn is_trusted(&self, origin: &Origin) -> Result<bool, String> {
        if origin.insecure {
            return Ok(false);
        }
        let origin = origin.as_string();
        Ok(self.read()?.origins.iter().any(|r| r.origin == origin))
    }

    /// Records `origin` as trusted now. Development origins are never stored.
    pub fn trust(&self, origin: &Origin) -> Result<(), String> {
        if origin.insecure {
            return Err(format!(
                "{origin} is a development origin and is never stored."
            ));
        }
        let mut file = self.read()?;
        let origin = origin.as_string();
        file.origins.retain(|r| r.origin != origin);
        let trusted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_secs();
        file.origins.push(Record { origin, trusted_at });
        self.write(&file)
    }

    /// Deletes the record for `origin`, given as a URL on it. Returns
    /// whether there was one.
    pub fn forget(&self, origin: &str) -> Result<bool, String> {
        let origin = url::Url::parse(origin)
            .map_err(|e| format!("{origin} isn't an origin: {e}"))?
            .origin()
            .ascii_serialization();
        let mut file = self.read()?;
        let before = file.origins.len();
        file.origins.retain(|r| r.origin != origin);
        if file.origins.len() == before {
            return Ok(false);
        }
        self.write(&file)?;
        Ok(true)
    }

    fn read(&self) -> Result<File, String> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("The trust store {} is damaged: {e}", self.path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
            Err(e) => Err(format!("Couldn't read {}: {e}", self.path.display())),
        }
    }

    /// Writes beside the store and renames, so a crash never leaves half a file.
    fn write(&self, file: &File) -> Result<(), String> {
        let error = |e: std::io::Error| format!("Couldn't write {}: {e}", self.path.display());
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir).map_err(error)?;
        }
        let bytes = serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?;
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, bytes).map_err(error)?;
        std::fs::rename(&temporary, &self.path).map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keyseal-trust-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn origin(url: &str) -> Origin {
        Origin::of_url(&Url::parse(url).unwrap(), true).unwrap()
    }

    #[test]
    fn trusts_lists_and_forgets_exact_origins() {
        let dir = temp_dir("roundtrip");
        let store = TrustStore::new(&dir.join("nested"));
        let dash = origin("https://dash.example.org/v1/jobs/x");
        assert!(store.list().unwrap().is_empty());
        assert!(!store.is_trusted(&dash).unwrap());

        store.trust(&dash).unwrap();
        assert!(store.is_trusted(&dash).unwrap());
        assert!(
            !store
                .is_trusted(&origin("https://dash.example.org:8443/"))
                .unwrap()
        );
        assert!(
            !store
                .is_trusted(&origin("https://other.example.org/"))
                .unwrap()
        );

        store.trust(&dash).unwrap();
        let records = store.list().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].origin, "https://dash.example.org");
        assert!(records[0].trusted_at > 1_700_000_000);

        let reopened = TrustStore::new(&dir.join("nested"));
        assert!(reopened.is_trusted(&dash).unwrap());
        assert!(!reopened.forget("https://other.example.org").unwrap());
        assert!(reopened.forget("https://Dash.example.org:443/").unwrap());
        assert!(!reopened.is_trusted(&dash).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn never_stores_development_origins() {
        let dir = temp_dir("insecure");
        let store = TrustStore::new(&dir);
        let local = origin("http://127.0.0.1:8080/");
        assert!(store.trust(&local).is_err());
        assert!(!store.is_trusted(&local).unwrap());
        assert!(!store.path().exists());
    }

    #[test]
    fn reports_a_damaged_store() {
        let dir = temp_dir("damaged");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("trust.json"), b"not json").unwrap();
        let store = TrustStore::new(&dir);
        assert!(store.list().unwrap_err().contains("damaged"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

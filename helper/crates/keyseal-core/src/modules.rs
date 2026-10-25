//! Which PKCS#11 module to load. Module selection is the helper's decision
//! alone (section 6.3): `KEYSEAL_PKCS11_MODULE`, a developer override, or the
//! installed [`candidates`] in order, and on Windows the certificate store
//! through CNG ([`attempts`]).

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::catalogue::{self, Catalogue, UsbDevice};

/// System and vendor directories a module may load from, matching the
/// driver catalogue's schema. User-writable places such as the home
/// directory aren't among them; only `KEYSEAL_PKCS11_MODULE` reaches those.
#[cfg(not(target_os = "windows"))]
pub const DIRECTORIES: &[&str] = &[
    "/usr/local/lib",
    "/usr/lib",
    "/usr/lib64",
    "/Library",
    "/opt",
    "/Applications",
];
#[cfg(target_os = "windows")]
pub const DIRECTORIES: &[&str] = &[
    r"C:\Windows\System32",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
];

/// Whether `path` is an absolute path, without `.` or `..`, inside one of
/// [`DIRECTORIES`].
pub fn in_module_directory(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        && DIRECTORIES
            .iter()
            .any(|dir| path.starts_with(dir) && path != Path::new(dir))
}

/// Drivers of the DSC tokens sold in India, in the order they are tried.
#[cfg(target_os = "macos")]
pub const KNOWN: &[&str] = &[
    "/usr/local/lib/libcastle_v2.1.0.0.dylib",
    "/usr/local/lib/libcastle.dylib",
    "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
    "/usr/local/lib/libeTPkcs11.dylib",
    "/usr/local/lib/libmtoken.dylib",
    "/usr/local/lib/libwdpkcs.dylib",
    "/usr/local/lib/libInnaITKey.dylib",
    "/usr/local/lib/libIDPrimePKCS11.dylib",
];
#[cfg(target_os = "windows")]
pub const KNOWN: &[&str] = &[
    r"C:\Windows\System32\HYP2003csp11IND.dll",
    r"C:\Windows\System32\eps2003csp11.dll",
    r"C:\Windows\System32\eps2003csp11v2.dll",
    r"C:\Windows\System32\eTPKCS11.dll",
    r"C:\Windows\System32\mToken.dll",
    r"C:\Windows\System32\wdpkcs.dll",
    r"C:\Windows\System32\SignatureP11.dll",
    r"C:\Windows\System32\InnaITKey.dll",
    r"C:\Windows\System32\IDPrimePKCS11.dll",
    r"C:\Windows\System32\cryptoide_pkcs11.dll",
];
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
pub const KNOWN: &[&str] = &[
    "/usr/lib/libcastle.so",
    "/usr/lib/libcastle_v2.1.0.0.so",
    "/usr/lib/libeTPkcs11.so",
    "/usr/lib/libeToken.so",
    "/usr/lib/libmtoken.so",
    "/usr/lib/libwdpkcs.so",
    "/usr/lib/libInnaITKey.so",
    "/usr/lib/libIDPrimePKCS11.so",
];

pub const OVERRIDE: &str = "KEYSEAL_PKCS11_MODULE";

/// p11-kit's module configuration directories.
#[cfg(target_os = "linux")]
const P11_KIT_CONFIG: &[&str] = &["/usr/share/p11-kit/modules", "/etc/pkcs11/modules"];
#[cfg(not(target_os = "linux"))]
const P11_KIT_CONFIG: &[&str] = &[];

/// Where p11-kit resolves a relative `module:`, depending on the distribution.
const P11_KIT_MODULES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/pkcs11",
    "/usr/lib64/pkcs11",
    "/usr/lib/pkcs11",
];

/// Where a candidate path came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// [`OVERRIDE`].
    Override,
    /// `module` in `<config dir>/config.json`.
    Config,
    /// The catalogue token of a connected USB device.
    UsbMatch(String),
    /// A catalogue token's path, without a matching device.
    Catalogue(String),
    Known,
    P11Kit,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Override => f.write_str(OVERRIDE),
            Self::Config => f.write_str("config.json"),
            Self::UsbMatch(name) => write!(f, "catalogue, {name} plugged in"),
            Self::Catalogue(name) => write!(f, "catalogue, {name}"),
            Self::Known => f.write_str("known drivers"),
            Self::P11Kit => f.write_str("p11-kit"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub path: PathBuf,
    pub source: Source,
}

/// `<config dir>/config.json`.
#[derive(Deserialize)]
struct Config {
    module: Option<PathBuf>,
}

/// The paths the helper tries, in order: the override alone when set;
/// otherwise the module the user configured, which may be any absolute
/// path since writing it is explicit consent; the catalogue paths of
/// connected tokens, then of every token; the known drivers; and on Linux
/// the modules p11-kit is configured with. Paths other than the override
/// and the configured module must be in [`DIRECTORIES`].
pub fn candidates() -> Result<Vec<Candidate>, String> {
    Ok(search()?.0)
}

/// The [`candidates`], and whether a plugged-in token's catalogue entry
/// says it works through CNG.
fn search() -> Result<(Vec<Candidate>, bool), String> {
    if let Some(path) = std::env::var_os(OVERRIDE) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(format!(
                "{OVERRIDE} must be an absolute path, not {}.",
                path.display()
            ));
        }
        let candidate = Candidate {
            path,
            source: Source::Override,
        };
        return Ok((vec![candidate], false));
    }
    let (catalogue, _) = catalogue::current();
    let devices = catalogue::usb_devices().unwrap_or_default();
    let prefer_cng = devices
        .iter()
        .filter_map(|device| catalogue.token_for(device))
        .any(|token| token.cng);
    let candidates = collect(
        crate::config_dir().ok().as_deref(),
        &catalogue,
        &devices,
        P11_KIT_CONFIG,
    )?;
    Ok((candidates, prefer_cng))
}

/// One place the job's key may be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attempt {
    Module(Candidate),
    /// Windows: the current user's certificate store through CNG.
    Cng,
}

impl std::fmt::Display for Attempt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Module(candidate) => {
                write!(f, "{} [{}]", candidate.path.display(), candidate.source)
            }
            Self::Cng => f.write_str("the Windows certificate store (CNG)"),
        }
    }
}

/// Where the flow looks for the job's key, in order: the candidates that
/// exist, then on Windows CNG, which comes first when a plugged-in token's
/// catalogue entry has `cng`.
pub fn attempts() -> Result<Vec<Attempt>, String> {
    let (candidates, prefer_cng) = search()?;
    let installed = candidates.into_iter().filter(|c| c.path.exists()).collect();
    Ok(order(installed, cfg!(windows), prefer_cng))
}

fn order(installed: Vec<Candidate>, cng: bool, prefer_cng: bool) -> Vec<Attempt> {
    let mut list: Vec<Attempt> = installed.into_iter().map(Attempt::Module).collect();
    if cng {
        let at = if prefer_cng { 0 } else { list.len() };
        list.insert(at, Attempt::Cng);
    }
    list
}

fn collect(
    config_dir: Option<&Path>,
    catalogue: &Catalogue,
    devices: &[UsbDevice],
    p11_kit_config: &[&str],
) -> Result<Vec<Candidate>, String> {
    let mut list = Vec::new();
    if let Some(dir) = config_dir
        && let Some(path) = configured(dir)?
    {
        list.push(Candidate {
            path,
            source: Source::Config,
        });
    }
    let mut checked = Vec::new();
    if let Some(platform) = catalogue::platform() {
        let matched = devices
            .iter()
            .filter_map(|device| catalogue.token_for(device));
        for token in matched {
            for path in token.modules_for(platform) {
                checked.push((path.into(), Source::UsbMatch(token.name.clone())));
            }
        }
        for token in &catalogue.tokens {
            for path in token.modules_for(platform) {
                checked.push((path.into(), Source::Catalogue(token.name.clone())));
            }
        }
    }
    checked.extend(KNOWN.iter().map(|path| (path.into(), Source::Known)));
    checked.extend(
        p11_kit_modules(p11_kit_config)
            .into_iter()
            .map(|path| (path, Source::P11Kit)),
    );
    list.extend(
        checked
            .into_iter()
            .filter(|(path, _): &(PathBuf, Source)| in_module_directory(path))
            .map(|(path, source)| Candidate { path, source }),
    );
    let mut seen = HashSet::new();
    list.retain(|candidate| seen.insert(candidate.path.clone()));
    Ok(list)
}

/// The module in `<config dir>/config.json`, if it names one.
fn configured(config_dir: &Path) -> Result<Option<PathBuf>, String> {
    let file = config_dir.join("config.json");
    let bytes = match std::fs::read(&file) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("Couldn't read {}: {e}", file.display())),
    };
    let config: Config = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is damaged: {e}", file.display()))?;
    match config.module {
        Some(path) if !path.is_absolute() => Err(format!(
            "The module in {} must be an absolute path, not {}.",
            file.display(),
            path.display()
        )),
        module => Ok(module),
    }
}

/// The `module:` of every `*.module` file in `config`, with relative names
/// resolved against [`P11_KIT_MODULES`]. p11-kit's own trust module holds
/// no keys and is left out.
fn p11_kit_modules(config: &[&str]) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = config
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "module"))
        .collect();
    files.sort();
    let mut modules = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let Some(module) = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("module:"))
            .map(str::trim)
            .filter(|module| !module.is_empty() && *module != "p11-kit-trust.so")
        else {
            continue;
        };
        if module.starts_with('/') {
            modules.push(module.into());
        } else {
            modules.extend(
                P11_KIT_MODULES
                    .iter()
                    .map(|dir| Path::new(dir).join(module)),
            );
        }
    }
    modules
}

/// How the error when no module is installed starts, for front ends that
/// add advice to it.
pub const NO_DRIVER: &str = "No DSC token driver was found.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_drivers_are_in_module_directories() {
        assert!(
            KNOWN
                .iter()
                .all(|path| in_module_directory(Path::new(path)))
        );
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keyseal-modules-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A path in a module directory on this platform.
    fn system(name: &str) -> String {
        Path::new(DIRECTORIES[0]).join(name).display().to_string()
    }

    #[test]
    fn candidates_in_order() {
        let config = temp_dir("config");
        let configured = config.join("libconfigured.so");
        std::fs::write(&configured, b"").unwrap();
        std::fs::write(
            config.join("config.json"),
            serde_json::json!({ "module": configured }).to_string(),
        )
        .unwrap();
        let p11_kit = temp_dir("p11-kit");
        std::fs::write(
            p11_kit.join("vendor.module"),
            format!("module: {}\n", system("libp11.so")),
        )
        .unwrap();

        let platform = catalogue::platform().unwrap();
        let catalogue: Catalogue = serde_json::from_value(serde_json::json!({
            "version": 1,
            "generatedAt": "2026-10-22T00:00:00Z",
            "tokens": [
                {
                    "name": "Unplugged",
                    "vendor": "V",
                    "usb": [{ "vid": "0001", "pid": "0001" }],
                    "modules": { platform: [system("libunplugged.so"), system("libshared.so")] }
                },
                {
                    "name": "Plugged",
                    "vendor": "V",
                    "usb": [{ "vid": "abcd", "pid": "0002" }],
                    "modules": { platform: [system("libplugged.so"), "/home/user/libevil.so", system("libshared.so")] }
                }
            ]
        }))
        .unwrap();
        let devices = [UsbDevice {
            vid: 0xabcd,
            pid: 0x0002,
            product: None,
        }];

        let list = collect(
            Some(&config),
            &catalogue,
            &devices,
            &[p11_kit.to_str().unwrap()],
        )
        .unwrap();
        let mut expected = vec![
            (configured.clone(), Source::Config),
            (
                system("libplugged.so").into(),
                Source::UsbMatch("Plugged".into()),
            ),
            (
                system("libshared.so").into(),
                Source::UsbMatch("Plugged".into()),
            ),
            (
                system("libunplugged.so").into(),
                Source::Catalogue("Unplugged".into()),
            ),
        ];
        expected.extend(
            KNOWN
                .iter()
                .map(|path| (PathBuf::from(path), Source::Known)),
        );
        expected.push((system("libp11.so").into(), Source::P11Kit));
        let list: Vec<_> = list.into_iter().map(|c| (c.path, c.source)).collect();
        assert_eq!(list, expected);

        std::fs::write(config.join("config.json"), r#"{"module":"libpkcs11.so"}"#).unwrap();
        assert!(collect(Some(&config), &catalogue, &devices, &[]).is_err());
        std::fs::remove_file(config.join("config.json")).unwrap();
        let list = collect(Some(&config), &catalogue, &[], &[]).unwrap();
        assert_eq!(list[0].source, Source::Catalogue("Unplugged".into()));

        let _ = std::fs::remove_dir_all(&config);
        let _ = std::fs::remove_dir_all(&p11_kit);
    }

    #[test]
    fn the_environment_override_stands_alone() {
        let module = temp_dir("override").join("libdev.so");
        // SAFETY: no other test reads or writes this variable.
        unsafe { std::env::set_var(OVERRIDE, &module) };
        let list = candidates();
        unsafe { std::env::set_var(OVERRIDE, "libdev.so") };
        let relative = candidates();
        unsafe { std::env::remove_var(OVERRIDE) };
        assert_eq!(
            list.unwrap(),
            [Candidate {
                path: module,
                source: Source::Override
            }]
        );
        assert!(relative.is_err());
    }

    #[test]
    fn cng_comes_last_unless_a_plugged_in_token_prefers_it() {
        let module = |name: &str| Candidate {
            path: system(name).into(),
            source: Source::Known,
        };
        let installed = vec![module("liba.so"), module("libb.so")];
        let modules: Vec<Attempt> = installed.iter().cloned().map(Attempt::Module).collect();
        assert_eq!(order(installed.clone(), false, true), modules);
        let mut last = modules.clone();
        last.push(Attempt::Cng);
        assert_eq!(order(installed.clone(), true, false), last);
        let mut first = vec![Attempt::Cng];
        first.extend(modules);
        assert_eq!(order(installed, true, true), first);
        assert_eq!(order(Vec::new(), true, false), [Attempt::Cng]);
    }

    #[test]
    fn reads_p11_kit_module_files() {
        let dir = temp_dir("p11-kit-files");
        let fixture = [
            (
                "opensc.module",
                "# This is a relative path, which means it will be loaded from\n\
                 # the p11-kit default path.\n\
                 module: opensc-pkcs11.so\n",
            ),
            (
                "p11-kit-trust.module",
                "module: p11-kit-trust.so\ntrust-policy: yes\n",
            ),
            (
                "vendor.module",
                "  module:  /opt/vendor/libvendor.so \npriority: 1\n",
            ),
            ("commented.module", "# module: /opt/vendor/libnot.so\n"),
            ("notes.txt", "module: /opt/vendor/libnot.so\n"),
        ];
        for (name, text) in fixture {
            std::fs::write(dir.join(name), text).unwrap();
        }
        let mut expected: Vec<PathBuf> = P11_KIT_MODULES
            .iter()
            .map(|lib| Path::new(lib).join("opensc-pkcs11.so"))
            .collect();
        expected.push("/opt/vendor/libvendor.so".into());
        assert_eq!(
            p11_kit_modules(&[dir.to_str().unwrap(), "/nonexistent"]),
            expected
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn allows_system_and_vendor_directories_only() {
        for allowed in [
            "/usr/lib/libcastle.so",
            "/usr/lib64/libeToken.so",
            "/usr/local/lib/libmtoken.dylib",
            "/Library/Frameworks/eToken.framework/Versions/A/libeToken.dylib",
            "/opt/vendor/lib/libpkcs11.so",
            "/Applications/Vendor.app/Contents/Frameworks/libpkcs11.dylib",
        ] {
            assert!(in_module_directory(Path::new(allowed)), "{allowed}");
        }
        for refused in [
            "/home/user/libpkcs11.so",
            "/Users/user/libpkcs11.dylib",
            "/tmp/libpkcs11.so",
            "/opt",
            "/opt/../home/user/libpkcs11.so",
            "/optional/libpkcs11.so",
            "opt/libpkcs11.so",
        ] {
            assert!(!in_module_directory(Path::new(refused)), "{refused}");
        }
    }
}

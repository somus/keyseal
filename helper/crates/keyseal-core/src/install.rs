//! `keyseal install` and `keyseal uninstall`: registering the `keyseal://` scheme
//! for this user. Nothing here needs administrator rights.
//!
//! - macOS: `CFBundleURLTypes` in the app's `Info.plist` claims the scheme,
//!   and Launch Services registers it when the app is first opened or
//!   copied into a folder. `install` registers the running bundle at once
//!   with `LSRegisterURL`.
//! - Windows: a copy in `%LOCALAPPDATA%\keyseal` and the scheme under
//!   `HKCU\Software\Classes\keyseal`.
//! - Linux: a copy in `~/.local/bin` and a desktop entry for
//!   `x-scheme-handler/keyseal`, made the default with `xdg-mime`.

#[cfg(any(not(target_os = "macos"), test))]
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Runs the system tools registration needs (`reg`, `xdg-mime`); tests
/// record the calls instead.
pub trait Host {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<(), String>;
}

pub struct System;

impl Host for System {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<(), String> {
        let status = Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .status()
            .map_err(|e| format!("{program}: {e}"))?;
        if !status.success() {
            return Err(format!("{program} {} failed ({status}).", args.join(" ")));
        }
        Ok(())
    }
}

fn current_exe() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|e| format!("Couldn't find the KeySeal binary: {e}"))
}

#[cfg(target_os = "macos")]
pub fn install() -> Result<(), String> {
    let exe = current_exe()?;
    let bundle = crate::macos::bundle(&exe).ok_or(
        "Run this from KeySeal.app: drag it to Applications and open it once, which registers keyseal:// links.",
    )?;
    crate::macos::register(bundle)?;
    println!("{} handles keyseal:// links.", bundle.display());
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<(), String> {
    let exe = current_exe()?;
    match crate::macos::bundle(&exe) {
        Some(bundle) => println!(
            "Move {} to the Trash; Launch Services forgets its keyseal:// links when it's gone.",
            bundle.display()
        ),
        None => println!("KeySeal isn't running from an app bundle, so nothing is registered."),
    }
    Ok(())
}

#[cfg(windows)]
pub fn install() -> Result<(), String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA isn't set.")?;
    let target = install_windows(&current_exe()?, Path::new(&base), &mut System)?;
    println!(
        "Installed {} and registered keyseal:// links.",
        target.display()
    );
    Ok(())
}

#[cfg(windows)]
pub fn uninstall() -> Result<(), String> {
    let base = std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA isn't set.")?;
    uninstall_windows(Path::new(&base), &mut System)
}

#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    let (bin, applications) = linux_dirs()?;
    // An AppImage runs from a temporary mount; install the image itself.
    let source = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .map_or_else(current_exe, Ok)?;
    let target = install_linux(&source, &bin, &applications, &mut System)?;
    println!(
        "Installed {} and registered keyseal:// links.",
        target.display()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<(), String> {
    let (bin, applications) = linux_dirs()?;
    uninstall_linux(&bin, &applications, &mut System)
}

/// `~/.local/bin` and `~/.local/share/applications`, or their XDG overrides.
#[cfg(target_os = "linux")]
fn linux_dirs() -> Result<(PathBuf, PathBuf), String> {
    let bin = dirs::executable_dir().ok_or("This system has no ~/.local/bin.")?;
    let data = dirs::data_dir().ok_or("This system has no ~/.local/share.")?;
    Ok((bin, data.join("applications")))
}

/// Copies `source` to `target` unless it is `target`, through a temporary
/// file so a running copy is replaced, not overwritten.
#[cfg(any(not(target_os = "macos"), test))]
fn copy_binary(source: &Path, target: &Path) -> Result<(), String> {
    if source == target {
        return Ok(());
    }
    let dir = target.parent().ok_or("The install folder is missing.")?;
    let temp = target.with_extension("installing");
    let copied = std::fs::create_dir_all(dir)
        .and_then(|()| std::fs::copy(source, &temp))
        .and_then(|_| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o755))?;
            }
            std::fs::rename(&temp, target)
        });
    copied.map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("Couldn't install {}: {e}", target.display())
    })
}

#[cfg(any(windows, test))]
const WINDOWS_KEY: &str = r"HKCU\Software\Classes\keyseal";

/// Installs to `local_app_data\keyseal\keyseal.exe` and registers it. The
/// installed path.
#[cfg(any(windows, test))]
fn install_windows(
    source: &Path,
    local_app_data: &Path,
    host: &mut dyn Host,
) -> Result<PathBuf, String> {
    let target = local_app_data.join("keyseal").join("keyseal.exe");
    copy_binary(source, &target)?;
    // The copy keeps the browser's download mark, which would bring
    // SmartScreen back each time a link opens the helper.
    let _ = std::fs::remove_file(format!("{}:Zone.Identifier", target.display()));
    let command = format!("\"{}\" \"%1\"", target.display());
    let open = format!(r"{WINDOWS_KEY}\shell\open\command");
    host.run(
        "reg",
        &["add", WINDOWS_KEY, "/ve", "/d", "URL:keyseal", "/f"],
    )?;
    host.run(
        "reg",
        &["add", WINDOWS_KEY, "/v", "URL Protocol", "/d", "", "/f"],
    )?;
    host.run("reg", &["add", &open, "/ve", "/d", &command, "/f"])?;
    Ok(target)
}

#[cfg(any(windows, test))]
fn uninstall_windows(local_app_data: &Path, host: &mut dyn Host) -> Result<(), String> {
    host.run("reg", &["delete", WINDOWS_KEY, "/f"])?;
    let dir = local_app_data.join("keyseal");
    if dir.exists() && std::fs::remove_dir_all(&dir).is_err() {
        // The running keyseal.exe can't be deleted.
        println!(
            "Unregistered keyseal:// links. Delete {} once KeySeal has closed.",
            dir.display()
        );
    } else {
        println!(
            "Unregistered keyseal:// links and removed {}.",
            dir.display()
        );
    }
    Ok(())
}

/// The desktop entry that hands `keyseal://` links to `exe`.
#[cfg(any(target_os = "linux", test))]
fn desktop_entry(exe: &Path) -> Result<String, String> {
    let exe = exe.to_str().ok_or("The install path isn't valid UTF-8.")?;
    // These need escaping in an Exec line; a home folder never has them.
    if exe.contains(['"', '`', '$', '\\', '%', '\n']) {
        return Err(format!(
            "KeySeal can't register links for a path like {exe}."
        ));
    }
    // Quoted only when the spec requires it: xdg-open without a desktop
    // environment keeps the quotes and then can't find the program.
    let reserved = [
        ' ', '\t', '\'', '>', '<', '~', '|', '&', ';', '*', '?', '#', '(', ')',
    ];
    let exe = if exe.contains(reserved) {
        format!("\"{exe}\"")
    } else {
        exe.to_owned()
    };
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=KeySeal\n\
         Comment=Sign documents with a DSC token\n\
         Exec={exe} %u\n\
         Terminal=false\n\
         NoDisplay=true\n\
         MimeType=x-scheme-handler/keyseal;\n"
    ))
}

/// Installs to `bin/keyseal` and registers it in `applications`. The
/// installed path. The desktop tools are best effort: some desktops have
/// neither, and read the entry anyway.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn install_linux(
    source: &Path,
    bin: &Path,
    applications: &Path,
    host: &mut dyn Host,
) -> Result<PathBuf, String> {
    let target = bin.join("keyseal");
    let entry = desktop_entry(&target)?;
    copy_binary(source, &target)?;
    std::fs::create_dir_all(applications)
        .and_then(|()| std::fs::write(applications.join("keyseal.desktop"), entry))
        .map_err(|e| format!("Couldn't write the desktop entry: {e}"))?;
    let applications = applications.to_string_lossy();
    let tools: [(&str, &[&str]); 2] = [
        (
            "xdg-mime",
            &["default", "keyseal.desktop", "x-scheme-handler/keyseal"],
        ),
        ("update-desktop-database", &[&applications]),
    ];
    for (program, args) in tools {
        if let Err(message) = host.run(program, args) {
            eprintln!("warning: {message}");
        }
    }
    Ok(target)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn uninstall_linux(bin: &Path, applications: &Path, host: &mut dyn Host) -> Result<(), String> {
    for path in [applications.join("keyseal.desktop"), bin.join("keyseal")] {
        match std::fs::remove_file(&path) {
            Ok(()) => println!("Removed {}.", path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Couldn't remove {}: {error}", path.display())),
        }
    }
    if let Err(message) = host.run(
        "update-desktop-database",
        &[&applications.to_string_lossy()],
    ) {
        eprintln!("warning: {message}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Recorder(Vec<String>);

    impl Host for Recorder {
        fn run(&mut self, program: &str, args: &[&str]) -> Result<(), String> {
            self.0.push(format!("{program} {}", args.join("|")));
            Ok(())
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("keyseal-install-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    // A Windows temp path has backslashes, which no desktop entry takes.
    #[cfg(unix)]
    #[test]
    fn installs_and_uninstalls_on_linux() {
        let home = temp_dir("linux");
        let source = home.join("Downloads/keyseal");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, b"binary").unwrap();
        let (bin, applications) = (
            home.join(".local/bin"),
            home.join(".local/share/applications"),
        );
        let mut host = Recorder::default();

        let target = install_linux(&source, &bin, &applications, &mut host).unwrap();
        assert_eq!(target, bin.join("keyseal"));
        assert_eq!(std::fs::read(&target).unwrap(), b"binary");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        let entry = std::fs::read_to_string(applications.join("keyseal.desktop")).unwrap();
        assert!(entry.contains("MimeType=x-scheme-handler/keyseal;\n"));
        assert!(entry.contains(&format!("Exec={} %u\n", target.display())));
        assert_eq!(
            host.0,
            [
                "xdg-mime default|keyseal.desktop|x-scheme-handler/keyseal".to_string(),
                format!("update-desktop-database {}", applications.display()),
            ]
        );

        // Installing from the installed copy registers again without copying.
        install_linux(&target, &bin, &applications, &mut Recorder::default()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"binary");

        let mut host = Recorder::default();
        uninstall_linux(&bin, &applications, &mut host).unwrap();
        assert!(!target.exists() && !applications.join("keyseal.desktop").exists());
        assert_eq!(host.0.len(), 1);
        uninstall_linux(&bin, &applications, &mut Recorder::default()).unwrap();
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn refuses_paths_an_exec_line_cant_hold() {
        assert!(
            desktop_entry(Path::new("/home/a b/.local/bin/keyseal"))
                .unwrap()
                .contains("Exec=\"/home/a b/.local/bin/keyseal\" %u\n")
        );
        assert!(desktop_entry(Path::new("/home/$x/.local/bin/keyseal")).is_err());
        assert!(desktop_entry(Path::new("/home/\"x\"/.local/bin/keyseal")).is_err());
    }

    #[test]
    fn installs_and_uninstalls_on_windows() {
        let local = temp_dir("windows");
        let source = local
            .join("Downloads")
            .join("keyseal-helper-1.0.0-windows-x64.exe");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::write(&source, b"exe").unwrap();
        let mut host = Recorder::default();

        let target = install_windows(&source, &local, &mut host).unwrap();
        assert_eq!(target, local.join("keyseal").join("keyseal.exe"));
        assert_eq!(std::fs::read(&target).unwrap(), b"exe");
        assert_eq!(
            host.0,
            [
                r"reg add|HKCU\Software\Classes\keyseal|/ve|/d|URL:keyseal|/f".to_string(),
                r"reg add|HKCU\Software\Classes\keyseal|/v|URL Protocol|/d||/f".to_string(),
                format!(
                    r#"reg add|HKCU\Software\Classes\keyseal\shell\open\command|/ve|/d|"{}" "%1"|/f"#,
                    target.display()
                ),
            ]
        );

        let mut host = Recorder::default();
        uninstall_windows(&local, &mut host).unwrap();
        assert_eq!(host.0, [r"reg delete|HKCU\Software\Classes\keyseal|/f"]);
        assert!(!local.join("keyseal").exists());
        let _ = std::fs::remove_dir_all(&local);
    }

    /// A profile folder with spaces, as `C:\Users\Asha Rao\AppData\Local`:
    /// the command quotes the path whole, so the shell runs KeySeal with the
    /// link as its only argument.
    #[test]
    fn quotes_a_local_app_data_with_spaces() {
        let local = temp_dir("windows-spaces").join("Asha Rao").join("App Data");
        let source = local.join("keyseal download.exe");
        std::fs::create_dir_all(&local).unwrap();
        std::fs::write(&source, b"exe").unwrap();
        let mut host = Recorder::default();
        let target = install_windows(&source, &local, &mut host).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"exe");
        let command = host.0.last().unwrap().split('|').nth(4).unwrap();
        assert_eq!(command, format!("\"{}\" \"%1\"", target.display()));
        assert!(target.display().to_string().contains("Asha Rao"));
        let _ = std::fs::remove_dir_all(local.parent().unwrap().parent().unwrap());
    }
}

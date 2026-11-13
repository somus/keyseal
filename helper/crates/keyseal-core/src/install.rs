//! `keyseal install` and `keyseal uninstall`: registering the `keyseal://` scheme
//! for this user. Nothing here needs administrator rights.
//!
//! - macOS: `CFBundleURLTypes` in the app's `Info.plist` claims the scheme,
//!   and Launch Services registers it when the app is first opened or
//!   copied into a folder. `install` registers the running bundle at once
//!   with `LSRegisterURL`.
//! - Windows: a copy in `%LOCALAPPDATA%\keyseal`, the scheme under
//!   `HKCU\Software\Classes\keyseal`, a Start menu shortcut to the
//!   settings and an entry under Apps that uninstalls.
//! - Linux: a copy in `~/.local/bin`, its icon and a desktop entry for
//!   `x-scheme-handler/keyseal`, made the default with `xdg-mime`, that the
//!   app menu shows too.

#[cfg(any(not(target_os = "macos"), test))]
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Runs the system tools registration needs (`reg.exe`, `xdg-mime`); tests
/// record the calls instead.
pub trait Host {
    fn run(&mut self, program: &str, args: &[&str]) -> Result<(), String>;
    /// Starts `program` without a window and doesn't wait for it.
    fn spawn(&mut self, program: &str, args: &[&str]) -> Result<(), String>;
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

    fn spawn(&mut self, program: &str, args: &[&str]) -> Result<(), String> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        command
            .spawn()
            .map(drop)
            .map_err(|e| format!("{program}: {e}"))
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
    let (local_app_data, programs) = windows_dirs()?;
    let target = install_windows(&current_exe()?, &local_app_data, &programs, &mut System)?;
    println!(
        "Installed {} and registered keyseal:// links.",
        target.display()
    );
    Ok(())
}

#[cfg(windows)]
pub fn uninstall() -> Result<(), String> {
    let (local_app_data, programs) = windows_dirs()?;
    uninstall_windows(&local_app_data, &programs, &mut System)
}

/// `%LOCALAPPDATA%` and the Start menu's Programs folder in `%APPDATA%`.
/// Both must be absolute, so a missing or odd variable can't point the
/// install folder somewhere relative.
#[cfg(windows)]
fn windows_dirs() -> Result<(PathBuf, PathBuf), String> {
    let dir = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
            .ok_or(format!("{name} isn't set to a full path."))
    };
    Ok((
        dir("LOCALAPPDATA")?,
        dir("APPDATA")?.join(r"Microsoft\Windows\Start Menu\Programs"),
    ))
}

#[cfg(target_os = "linux")]
pub fn install() -> Result<(), String> {
    let (bin, data) = linux_dirs()?;
    // An AppImage runs from a temporary mount; install the image itself.
    let source = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .map_or_else(current_exe, Ok)?;
    let target = install_linux(&source, &bin, &data, &mut System)?;
    println!(
        "Installed {} and registered keyseal:// links.",
        target.display()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn uninstall() -> Result<(), String> {
    let (bin, data) = linux_dirs()?;
    uninstall_linux(&bin, &data, &mut System)
}

/// `~/.local/bin` and `~/.local/share`, or their XDG overrides.
#[cfg(target_os = "linux")]
fn linux_dirs() -> Result<(PathBuf, PathBuf), String> {
    let bin = dirs::executable_dir().ok_or("This system has no ~/.local/bin.")?;
    let data = dirs::data_dir().ok_or("This system has no ~/.local/share.")?;
    Ok((bin, data))
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
/// The entry under Apps (Add or remove programs).
#[cfg(any(windows, test))]
const UNINSTALL_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\KeySeal";
/// Every file the helper writes to its install folder: the copy, its
/// temporary while copying, and an update's new and replaced builds.
#[cfg(any(windows, test))]
const INSTALLED_FILES: [&str; 4] = [
    "keyseal.exe",
    "keyseal.installing",
    "keyseal.new.exe",
    "keyseal.old.exe",
];

/// `reg.exe` in the system folder, `%SystemRoot%\System32`, so a `reg` on
/// the `PATH` or in the current folder never runs instead.
#[cfg(any(windows, test))]
fn reg() -> String {
    format!(r"{}\System32\reg.exe", system_root())
}

/// Windows PowerShell in the system folder, for what `reg.exe` can't do.
#[cfg(any(windows, test))]
fn powershell() -> String {
    format!(
        r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
        system_root()
    )
}

#[cfg(any(windows, test))]
fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

/// `path` as a PowerShell string literal.
#[cfg(any(windows, test))]
fn quoted(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "''"))
}

/// Installs to `local_app_data\keyseal\keyseal.exe`, registers it, puts a
/// shortcut to its settings in `programs` (the Start menu) and adds it to
/// Apps. The installed path.
#[cfg(any(windows, test))]
fn install_windows(
    source: &Path,
    local_app_data: &Path,
    programs: &Path,
    host: &mut dyn Host,
) -> Result<PathBuf, String> {
    let target = local_app_data.join("keyseal").join("keyseal.exe");
    copy_binary(source, &target)?;
    // The copy keeps the browser's download mark, which would bring
    // SmartScreen back each time a link opens the helper.
    let _ = std::fs::remove_file(format!("{}:Zone.Identifier", target.display()));
    let command = format!("\"{}\" \"%1\"", target.display());
    let open = format!(r"{WINDOWS_KEY}\shell\open\command");
    let reg = reg();
    host.run(
        &reg,
        &["add", WINDOWS_KEY, "/ve", "/d", "URL:keyseal", "/f"],
    )?;
    host.run(
        &reg,
        &["add", WINDOWS_KEY, "/v", "URL Protocol", "/d", "", "/f"],
    )?;
    host.run(&reg, &["add", &open, "/ve", "/d", &command, "/f"])?;
    let shortcut = format!(
        "$s = (New-Object -ComObject WScript.Shell).CreateShortcut({}); $s.TargetPath = {}; $s.Arguments = 'settings'; $s.Save()",
        quoted(&programs.join("KeySeal.lnk")),
        quoted(&target)
    );
    host.run(
        &powershell(),
        &["-NoProfile", "-NonInteractive", "-Command", &shortcut],
    )?;
    let exe = target.display().to_string();
    let uninstall = format!("\"{exe}\" uninstall");
    let values = [
        ("DisplayName", "REG_SZ", "KeySeal"),
        ("DisplayVersion", "REG_SZ", crate::VERSION),
        ("Publisher", "REG_SZ", "KeySeal"),
        ("DisplayIcon", "REG_SZ", &exe),
        ("UninstallString", "REG_SZ", &uninstall),
        ("NoModify", "REG_DWORD", "1"),
        ("NoRepair", "REG_DWORD", "1"),
    ];
    for (name, kind, data) in values {
        host.run(
            &reg,
            &[
                "add",
                UNINSTALL_KEY,
                "/v",
                name,
                "/t",
                kind,
                "/d",
                data,
                "/f",
            ],
        )?;
    }
    Ok(target)
}

/// Removes what [`install_windows`] added. The running `keyseal.exe` can't
/// delete itself, so when it is the installed copy a hidden PowerShell
/// waits for this process to end and deletes the folder then. Only the
/// helper's own files go, and the folder only once it is empty.
#[cfg(any(windows, test))]
fn uninstall_windows(
    local_app_data: &Path,
    programs: &Path,
    host: &mut dyn Host,
) -> Result<(), String> {
    let reg = reg();
    host.run(&reg, &["delete", WINDOWS_KEY, "/f"])?;
    // A helper installed by an earlier version didn't add it.
    let _ = host.run(&reg, &["delete", UNINSTALL_KEY, "/f"]);
    let _ = std::fs::remove_file(programs.join("KeySeal.lnk"));
    let dir = local_app_data.join("keyseal");
    let files = INSTALLED_FILES.map(|name| dir.join(name));
    let gone = |result: std::io::Result<()>| {
        result.is_ok() || result.is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    };
    let mut removed = true;
    for file in &files {
        removed &= gone(std::fs::remove_file(file));
    }
    if removed && gone(std::fs::remove_dir(&dir)) {
        println!(
            "Unregistered keyseal:// links and removed {}.",
            dir.display()
        );
        return Ok(());
    }
    let files = files.iter().map(|file| quoted(file)).collect::<Vec<_>>();
    let dir_literal = quoted(&dir);
    let cleanup = format!(
        "Wait-Process -Id {} -ErrorAction SilentlyContinue; foreach ($i in 1..10) {{ Remove-Item -LiteralPath {} -Force -ErrorAction SilentlyContinue; try {{ [IO.Directory]::Delete({dir_literal}) }} catch {{}}; if (-not (Test-Path -LiteralPath {dir_literal})) {{ break }}; Start-Sleep 1 }}",
        std::process::id(),
        files.join(",")
    );
    host.spawn(
        &powershell(),
        &["-NoProfile", "-NonInteractive", "-Command", &cleanup],
    )?;
    println!(
        "Unregistered keyseal:// links. {} is removed once KeySeal closes.",
        dir.display()
    );
    Ok(())
}

/// The packaged desktop entry and icon, which `install` writes too.
#[cfg(any(target_os = "linux", test))]
const DESKTOP_ENTRY: &str = include_str!("../../../packaging/linux/keyseal.desktop");
#[cfg(any(target_os = "linux", all(test, unix)))]
const ICON: &[u8] = include_bytes!("../../../packaging/linux/keyseal.svg");
/// The icon's place in the data folder, as the deb installs it.
#[cfg(any(target_os = "linux", all(test, unix)))]
const ICON_PATH: &str = "icons/hicolor/scalable/apps/keyseal.svg";

/// The packaged desktop entry, handing `keyseal://` links to `exe`.
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
    // By line, since a Windows checkout gives the packaged file CRLF.
    Ok(DESKTOP_ENTRY
        .lines()
        .map(|line| match line {
            "Exec=keyseal %u" => format!("Exec={exe} %u\n"),
            line => format!("{line}\n"),
        })
        .collect())
}

/// Installs to `bin/keyseal` and registers it with a desktop entry and icon
/// in `data`. The installed path. The desktop tools are best effort: some
/// desktops have neither, and read the entry anyway.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn install_linux(
    source: &Path,
    bin: &Path,
    data: &Path,
    host: &mut dyn Host,
) -> Result<PathBuf, String> {
    let target = bin.join("keyseal");
    let entry = desktop_entry(&target)?;
    copy_binary(source, &target)?;
    let applications = data.join("applications");
    let icon = data.join(ICON_PATH);
    std::fs::create_dir_all(&applications)
        .and_then(|()| std::fs::write(applications.join("keyseal.desktop"), entry))
        .and_then(|()| std::fs::create_dir_all(icon.parent().unwrap_or(data)))
        .and_then(|()| std::fs::write(&icon, ICON))
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
fn uninstall_linux(bin: &Path, data: &Path, host: &mut dyn Host) -> Result<(), String> {
    let applications = data.join("applications");
    for path in [
        applications.join("keyseal.desktop"),
        data.join(ICON_PATH),
        bin.join("keyseal"),
    ] {
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

        fn spawn(&mut self, program: &str, args: &[&str]) -> Result<(), String> {
            self.0.push(format!("spawn {program} {}", args.join("|")));
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
        let (bin, data) = (home.join(".local/bin"), home.join(".local/share"));
        let applications = data.join("applications");
        let mut host = Recorder::default();

        let target = install_linux(&source, &bin, &data, &mut host).unwrap();
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
        assert_eq!(std::fs::read(data.join(ICON_PATH)).unwrap(), ICON);
        assert_eq!(
            host.0,
            [
                "xdg-mime default|keyseal.desktop|x-scheme-handler/keyseal".to_string(),
                format!("update-desktop-database {}", applications.display()),
            ]
        );

        // Installing from the installed copy registers again without copying.
        install_linux(&target, &bin, &data, &mut Recorder::default()).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"binary");

        let mut host = Recorder::default();
        uninstall_linux(&bin, &data, &mut host).unwrap();
        assert!(!target.exists() && !applications.join("keyseal.desktop").exists());
        assert!(!data.join(ICON_PATH).exists());
        assert_eq!(host.0.len(), 1);
        uninstall_linux(&bin, &data, &mut Recorder::default()).unwrap();
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

    /// The entry `install` writes is the packaged one with its own path, and
    /// the app menu shows it, so it opens the settings when started without
    /// a link.
    #[test]
    fn writes_the_packaged_entry() {
        let written = desktop_entry(Path::new("/home/asha/.local/bin/keyseal")).unwrap();
        let packaged =
            DESKTOP_ENTRY.replace("Exec=keyseal %u", "Exec=/home/asha/.local/bin/keyseal %u");
        assert!(written.lines().eq(packaged.lines()), "{written}");
        assert!(written.contains("\nExec=/home/asha/.local/bin/keyseal %u\n"));
        assert!(!DESKTOP_ENTRY.contains("NoDisplay"));
        assert!(DESKTOP_ENTRY.lines().any(|line| line == "Icon=keyseal"));
    }

    #[test]
    fn installs_and_uninstalls_on_windows() {
        let local = temp_dir("windows");
        let programs = local.join("Programs");
        let source = local
            .join("Downloads")
            .join("keyseal-helper-1.0.0-windows-x64.exe");
        std::fs::create_dir_all(source.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&programs).unwrap();
        std::fs::write(&source, b"exe").unwrap();
        let mut host = Recorder::default();

        let target = install_windows(&source, &local, &programs, &mut host).unwrap();
        assert_eq!(target, local.join("keyseal").join("keyseal.exe"));
        assert_eq!(std::fs::read(&target).unwrap(), b"exe");
        let (reg, powershell) = (reg(), powershell());
        assert!(reg.ends_with(r"\System32\reg.exe"), "{reg}");
        let exe = target.display();
        let uninstall = format!(r"{reg} add|{UNINSTALL_KEY}|/v");
        assert_eq!(
            host.0,
            [
                format!(r"{reg} add|HKCU\Software\Classes\keyseal|/ve|/d|URL:keyseal|/f"),
                format!(r"{reg} add|HKCU\Software\Classes\keyseal|/v|URL Protocol|/d||/f"),
                format!(
                    r#"{reg} add|HKCU\Software\Classes\keyseal\shell\open\command|/ve|/d|"{exe}" "%1"|/f"#
                ),
                format!(
                    "{powershell} -NoProfile|-NonInteractive|-Command|$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{exe}'; $s.Arguments = 'settings'; $s.Save()",
                    programs.join("KeySeal.lnk").display()
                ),
                format!("{uninstall}|DisplayName|/t|REG_SZ|/d|KeySeal|/f"),
                format!(
                    "{uninstall}|DisplayVersion|/t|REG_SZ|/d|{}|/f",
                    crate::VERSION
                ),
                format!("{uninstall}|Publisher|/t|REG_SZ|/d|KeySeal|/f"),
                format!("{uninstall}|DisplayIcon|/t|REG_SZ|/d|{exe}|/f"),
                format!(r#"{uninstall}|UninstallString|/t|REG_SZ|/d|"{exe}" uninstall|/f"#),
                format!("{uninstall}|NoModify|/t|REG_DWORD|/d|1|/f"),
                format!("{uninstall}|NoRepair|/t|REG_DWORD|/d|1|/f"),
            ]
        );

        // Uninstalled by another copy, so the folder goes at once.
        std::fs::write(programs.join("KeySeal.lnk"), b"shortcut").unwrap();
        std::fs::write(target.with_extension("old.exe"), b"replaced").unwrap();
        let mut host = Recorder::default();
        uninstall_windows(&local, &programs, &mut host).unwrap();
        assert_eq!(
            host.0,
            [
                format!(r"{reg} delete|HKCU\Software\Classes\keyseal|/f"),
                format!(r"{reg} delete|{UNINSTALL_KEY}|/f"),
            ]
        );
        assert!(!local.join("keyseal").exists());
        assert!(!programs.join("KeySeal.lnk").exists());
        let _ = std::fs::remove_dir_all(&local);
    }

    /// A folder that can't be removed now, as one holding the running
    /// `keyseal.exe`, is left to a process that waits for this one to end
    /// and deletes only the helper's files and then the empty folder.
    #[cfg(unix)]
    #[test]
    fn defers_removing_the_install_folder() {
        use std::os::unix::fs::PermissionsExt;
        let local = temp_dir("windows-deferred");
        let dir = local.join("keyseal");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("keyseal.exe"), b"exe").unwrap();
        std::fs::write(dir.join("notes.txt"), b"mine").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        let mut host = Recorder::default();
        uninstall_windows(&local, &local.join("Programs"), &mut host).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let cleanup = host.0.last().unwrap();
        assert!(
            cleanup.starts_with(&format!(
                "spawn {} -NoProfile|-NonInteractive|-Command|Wait-Process -Id {} ",
                powershell(),
                std::process::id()
            )),
            "{cleanup}"
        );
        for name in INSTALLED_FILES {
            assert!(cleanup.contains(&format!("'{}'", dir.join(name).display())));
        }
        assert!(cleanup.contains(&format!("[IO.Directory]::Delete('{}')", dir.display())));
        assert!(!cleanup.contains("notes.txt") && !cleanup.contains("-Recurse"));
        assert_eq!(std::fs::read(dir.join("notes.txt")).unwrap(), b"mine");
        let _ = std::fs::remove_dir_all(&local);
    }

    #[test]
    fn quotes_powershell_paths() {
        assert_eq!(
            quoted(Path::new(r"C:\Users\O'Brien\AppData")),
            r"'C:\Users\O''Brien\AppData'"
        );
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
        let target = install_windows(&source, &local, &local, &mut host).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"exe");
        let command = host.0[2].split('|').nth(4).unwrap();
        assert_eq!(command, format!("\"{}\" \"%1\"", target.display()));
        assert!(target.display().to_string().contains("Asha Rao"));
        let _ = std::fs::remove_dir_all(local.parent().unwrap().parent().unwrap());
    }
}

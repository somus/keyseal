//! The token worker. Several Indian token drivers ship only x86_64 dylibs
//! on macOS, which the universal helper can't load when it runs as arm64.
//! For those the helper starts `keyseal-token-worker`, built for x86_64 and
//! run under Rosetta, which loads the driver and runs the PKCS#11
//! operations. The two speak newline-delimited JSON over the worker's stdin
//! and stdout: each [`Request`] line is answered by one line holding a
//! `Result<Reply, String>`.

use std::cell::RefCell;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::cms::{DigestAlgorithm, SignatureAlgorithm};
use crate::token::{PinWarning, TokenBackend, TokenCertificate, TokenError, err};

/// The worker's file name, beside the helper's executable.
pub const WORKER: &str = "keyseal-token-worker";

const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const MH_MAGIC: u32 = 0xfeed_face;
const MH_MAGIC_64: u32 = 0xfeed_facf;

/// A Mach-O CPU type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    /// arm64 and arm64e.
    Arm64,
    Other(u32),
}

impl From<u32> for Arch {
    fn from(cpu_type: u32) -> Self {
        match cpu_type {
            CPU_TYPE_X86_64 => Self::X86_64,
            CPU_TYPE_ARM64 => Self::Arm64,
            other => Self::Other(other),
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::X86_64 => f.write_str("x86_64"),
            Self::Arm64 => f.write_str("arm64"),
            Self::Other(cpu_type) => write!(f, "CPU type {cpu_type:#x}"),
        }
    }
}

/// The architectures of a thin or fat Mach-O file from its first bytes, or
/// `None` if `header` doesn't start one.
pub fn architectures(header: &[u8]) -> Option<Vec<Arch>> {
    let word = |at: usize, big_endian: bool| -> Option<u32> {
        let bytes = header.get(at..at + 4)?.try_into().ok()?;
        Some(if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    };
    let magic = word(0, true)?;
    if magic == FAT_MAGIC || magic == FAT_MAGIC_64 {
        // Big-endian fat_header, then fat_arch (20 bytes) or fat_arch_64
        // (32 bytes) entries, each starting with the CPU type.
        let entry = if magic == FAT_MAGIC { 20 } else { 32 };
        let count = word(4, true)? as usize;
        return (0..count)
            .map(|i| word(8 + i * entry, true).map(Arch::from))
            .collect();
    }
    // A thin mach_header in the file's byte order, the CPU type after the magic.
    if magic == MH_MAGIC || magic == MH_MAGIC_64 {
        return Some(vec![Arch::from(word(4, true)?)]);
    }
    if magic.swap_bytes() == MH_MAGIC || magic.swap_bytes() == MH_MAGIC_64 {
        return Some(vec![Arch::from(word(4, false)?)]);
    }
    None
}

/// Where a module's PKCS#11 operations run.
#[derive(Debug, PartialEq, Eq)]
pub enum Backend {
    InProcess,
    Worker,
}

/// In this process when the module at `path` has a slice for this
/// process's architecture, in the worker when it has only x86_64 and this
/// process runs as arm64. Off macOS, always in this process.
pub fn backend_for(path: &Path) -> Result<Backend, TokenError> {
    if !cfg!(target_os = "macos") {
        return Ok(Backend::InProcess);
    }
    let current = if cfg!(target_arch = "aarch64") {
        Arch::Arm64
    } else {
        Arch::X86_64
    };
    let mut header = Vec::new();
    File::open(path)
        .and_then(|file| file.take(4096).read_to_end(&mut header))
        .map_err(|e| {
            err(
                &format!("Couldn't read the token driver at {}", path.display()),
                e,
            )
        })?;
    let found = architectures(&header).ok_or_else(|| {
        TokenError(format!(
            "The token driver at {} isn't a macOS library.",
            path.display()
        ))
    })?;
    if found.contains(&current) {
        return Ok(Backend::InProcess);
    }
    if current == Arch::Arm64 && found.contains(&Arch::X86_64) {
        return Ok(Backend::Worker);
    }
    let found: Vec<String> = found.iter().map(Arch::to_string).collect();
    Err(TokenError(format!(
        "The token driver at {} is built for {}, which a {current} helper can't load.",
        path.display(),
        found.join(", ")
    )))
}

/// The worker beside this executable: in `Contents/MacOS/` of the app
/// bundle. One that resolves to another directory isn't run.
pub fn locate() -> Result<PathBuf, TokenError> {
    let exe = std::env::current_exe()
        .and_then(|exe| exe.canonicalize())
        .map_err(|e| err("Couldn't find the helper's executable", e))?;
    let worker = exe.with_file_name(WORKER).canonicalize().map_err(|e| {
        err(
            "The token driver is Intel-only, and the token worker isn't installed beside the helper",
            e,
        )
    })?;
    if worker.parent() != exe.parent() {
        return Err(TokenError(format!(
            "The token worker resolves to {}, outside the helper's directory, so it isn't run.",
            worker.display()
        )));
    }
    Ok(worker)
}

/// One line from the helper to the worker.
#[derive(Serialize, Deserialize)]
pub enum Request {
    /// Loads the module and opens a session on its first token, waiting
    /// up to `wait` for one.
    Open {
        module: PathBuf,
        wait: Duration,
    },
    Certificates {
        with_private_key: bool,
    },
    /// The only request carrying the PIN, zeroised when dropped. The PIN
    /// is lowercase hex of its UTF-8 bytes, which serde_json writes and
    /// reads without escaping, so no escape buffer of its holds the PIN.
    Login {
        pin: Zeroizing<String>,
    },
    /// One signature per item of `data`, in order, in the session the
    /// login opened.
    Sign {
        certificate: Vec<u8>,
        data: Vec<Vec<u8>>,
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
    },
    Logout,
    /// Ends the worker after the reply.
    Close,
}

/// The worker's answer to a request, sent as `Result<Reply, String>`.
#[derive(Serialize, Deserialize)]
pub enum Reply {
    Opened {
        pin_pad: bool,
        pin_warning: Option<PinWarning>,
    },
    Certificates(Vec<TokenCertificate>),
    Signatures(Vec<Vec<u8>>),
    Done,
}

const OUT_OF_TURN: &str = "The token worker answered out of turn.";
/// The longest reply line read, far above a token's certificates.
const MAX_REPLY_BYTES: u64 = 4 * 1024 * 1024;

/// The PIN of a [`Request::Login`], from its hex.
pub fn decode_pin(hex: &str) -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new(vec![0; hex.len() / 2]);
    hex::decode_to_slice(hex, &mut bytes).map_err(|_| "The PIN from the helper isn't hex.")?;
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(pin) => Ok(Zeroizing::new(pin)),
        Err(error) => {
            error.into_bytes().zeroize();
            Err("The PIN from the helper isn't UTF-8.".into())
        }
    }
}

/// A token whose driver runs in the worker.
pub struct WorkerToken {
    /// Taken when dropped, to be reaped on another thread.
    child: Option<Child>,
    stdin: ChildStdin,
    stdout: RefCell<BufReader<ChildStdout>>,
    pin_pad: bool,
    pin_warning: Option<PinWarning>,
}

impl WorkerToken {
    /// Starts the worker at `worker` and opens the first token of `module`
    /// in it, waiting up to `wait` for one.
    pub fn open(worker: &Path, module: &Path, wait: Duration) -> Result<Self, TokenError> {
        let mut child = Command::new(worker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| {
                err(
                    "Couldn't start the token worker for the Intel-only token driver (it needs Rosetta)",
                    e,
                )
            })?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut token = Self {
            child: Some(child),
            stdin,
            stdout: RefCell::new(BufReader::new(stdout)),
            pin_pad: false,
            pin_warning: None,
        };
        let request = Request::Open {
            module: module.to_owned(),
            wait,
        };
        let Reply::Opened {
            pin_pad,
            pin_warning,
        } = token.call(&request)?
        else {
            return Err(TokenError(OUT_OF_TURN.into()));
        };
        token.pin_pad = pin_pad;
        token.pin_warning = pin_warning;
        Ok(token)
    }

    fn call(&self, request: &Request) -> Result<Reply, TokenError> {
        // Zeroised when dropped, and large enough that a login line, which
        // holds the PIN, is never reallocated.
        let mut line = Zeroizing::new(Vec::with_capacity(1024));
        serde_json::to_writer(&mut *line, request)
            .map_err(|e| err("Couldn't write a request for the token worker", e))?;
        line.push(b'\n');
        (&self.stdin)
            .write_all(&line)
            .map_err(|e| err("The token worker stopped", e))?;
        let mut reply = String::new();
        let read = (&mut *self.stdout.borrow_mut())
            .take(MAX_REPLY_BYTES)
            .read_line(&mut reply)
            .map_err(|e| err("The token worker stopped", e))?;
        if read == 0 {
            return Err(TokenError("The token worker stopped unexpectedly.".into()));
        }
        if !reply.ends_with('\n') {
            return Err(TokenError(
                "The token worker sent a reply that is too long.".into(),
            ));
        }
        serde_json::from_str::<Result<Reply, String>>(&reply)
            .map_err(|e| err("The token worker sent something unreadable", e))?
            .map_err(TokenError)
    }

    fn call_done(&self, request: &Request) -> Result<(), TokenError> {
        match self.call(request)? {
            Reply::Done => Ok(()),
            _ => Err(TokenError(OUT_OF_TURN.into())),
        }
    }
}

impl TokenBackend for WorkerToken {
    fn pin_pad(&self) -> bool {
        self.pin_pad
    }

    fn pin_warning(&self) -> Option<&'static str> {
        self.pin_warning.map(PinWarning::message)
    }

    fn certificates(&self, with_private_key: bool) -> Result<Vec<TokenCertificate>, TokenError> {
        match self.call(&Request::Certificates { with_private_key })? {
            Reply::Certificates(certificates) => Ok(certificates),
            _ => Err(TokenError(OUT_OF_TURN.into())),
        }
    }

    fn login(&self, pin: Zeroizing<String>) -> Result<(), TokenError> {
        let mut hex = Zeroizing::new(vec![0; pin.len() * 2]);
        hex::encode_to_slice(pin.as_bytes(), &mut hex).expect("the buffer is twice the PIN");
        let hex = String::from_utf8(std::mem::take(&mut *hex)).expect("hex is ASCII");
        self.call_done(&Request::Login {
            pin: Zeroizing::new(hex),
        })
    }

    fn sign(
        &self,
        certificate: &[u8],
        data: &[Vec<u8>],
        digest: DigestAlgorithm,
        scheme: SignatureAlgorithm,
        _window: Option<isize>,
    ) -> Result<Vec<Vec<u8>>, TokenError> {
        let request = Request::Sign {
            certificate: certificate.to_vec(),
            data: data.to_vec(),
            digest,
            scheme,
        };
        match self.call(&request)? {
            Reply::Signatures(signatures) => Ok(signatures),
            _ => Err(TokenError(OUT_OF_TURN.into())),
        }
    }

    fn close(&self) {
        let _ = self.call_done(&Request::Logout);
    }
}

impl Drop for WorkerToken {
    fn drop(&mut self) {
        let _ = self.call_done(&Request::Close);
        // Some drivers take seconds to unload, so the worker is reaped on
        // another thread; it exits after `Close` or when stdin closes.
        if let Some(mut child) = self.child.take() {
            std::thread::spawn(move || child.wait());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fat(magic: u32, entry: usize, cpu_types: &[u32]) -> Vec<u8> {
        let mut header = [magic.to_be_bytes(), (cpu_types.len() as u32).to_be_bytes()].concat();
        for cpu_type in cpu_types {
            let mut arch = vec![0; entry];
            arch[..4].copy_from_slice(&cpu_type.to_be_bytes());
            header.extend(arch);
        }
        header
    }

    fn thin(cpu_type: u32) -> Vec<u8> {
        // Little-endian, as on every current Mac: magic, cputype, cpusubtype.
        [MH_MAGIC_64.to_le_bytes(), cpu_type.to_le_bytes(), [0; 4]].concat()
    }

    #[test]
    fn reads_fat_headers() {
        let both = [CPU_TYPE_X86_64, CPU_TYPE_ARM64];
        assert_eq!(
            architectures(&fat(FAT_MAGIC, 20, &both)),
            Some(vec![Arch::X86_64, Arch::Arm64])
        );
        assert_eq!(
            architectures(&fat(FAT_MAGIC_64, 32, &both)),
            Some(vec![Arch::X86_64, Arch::Arm64])
        );
        assert_eq!(
            architectures(&fat(FAT_MAGIC, 20, &[7])),
            Some(vec![Arch::Other(7)])
        );
        let mut truncated = fat(FAT_MAGIC, 20, &both);
        truncated.truncate(30);
        assert_eq!(architectures(&truncated), None);
    }

    #[test]
    fn reads_thin_headers() {
        assert_eq!(
            architectures(&thin(CPU_TYPE_ARM64)),
            Some(vec![Arch::Arm64])
        );
        assert_eq!(
            architectures(&thin(CPU_TYPE_X86_64)),
            Some(vec![Arch::X86_64])
        );
        let big_endian = [MH_MAGIC.to_be_bytes(), 18u32.to_be_bytes()].concat();
        assert_eq!(architectures(&big_endian), Some(vec![Arch::Other(18)]));
    }

    #[test]
    fn refuses_other_files() {
        assert_eq!(architectures(b""), None);
        assert_eq!(architectures(b"\x7fELF\x02\x01\x01\0"), None);
        assert_eq!(architectures(&MH_MAGIC_64.to_le_bytes()), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_a_system_binary() {
        // Universal on every Mac that runs Rosetta: x86_64 and arm64e.
        let header = std::fs::read("/bin/ls").unwrap();
        let found = architectures(&header).unwrap();
        assert!(found.contains(&Arch::X86_64), "{found:?}");
        assert!(found.contains(&Arch::Arm64), "{found:?}");
        assert_eq!(
            backend_for(Path::new("/bin/ls")).unwrap(),
            Backend::InProcess
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn names_the_architectures_it_cannot_load() {
        let dir = std::env::temp_dir().join(format!("keyseal-worker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let x86_64 = dir.join("x86_64.dylib");
        let other = dir.join("other.dylib");
        std::fs::write(&x86_64, thin(CPU_TYPE_X86_64)).unwrap();
        std::fs::write(&other, fat(FAT_MAGIC, 20, &[7, 18])).unwrap();
        let expected = if cfg!(target_arch = "aarch64") {
            Backend::Worker
        } else {
            Backend::InProcess
        };
        assert_eq!(backend_for(&x86_64).unwrap(), expected);
        let message = backend_for(&other).unwrap_err().0;
        assert!(
            message.contains("built for CPU type 0x7, CPU type 0x12"),
            "{message}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decodes_the_pin_from_hex() {
        assert_eq!(decode_pin("31323334").unwrap().as_str(), "1234");
        assert_eq!(decode_pin("").unwrap().as_str(), "");
        assert!(decode_pin("3132333").is_err());
        assert!(decode_pin("1234 ").is_err());
        assert!(decode_pin("ff").is_err());
    }

    /// A fake worker: a shell script that answers each request line with
    /// the next of `replies`.
    #[cfg(unix)]
    fn fake_worker(name: &str, replies: &[&str]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("keyseal-fake-worker-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut script = String::from("#!/bin/sh\n");
        for reply in replies {
            script.push_str(&format!("read line || exit 0\n{reply}\n"));
        }
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn refuses_unreadable_out_of_turn_or_oversized_replies() {
        let opened = r#"echo '{"Ok":{"Opened":{"pin_pad":false,"pin_warning":null}}}'"#;
        let open = |name: &str, replies: &[&str]| {
            WorkerToken::open(
                &fake_worker(name, replies),
                Path::new("/usr/lib/libfake.so"),
                Duration::ZERO,
            )
        };
        let error = |result: Result<WorkerToken, TokenError>| result.err().unwrap().0;

        assert!(
            error(open("garbage", &["echo 'not json'"])).contains("unreadable"),
            "garbage"
        );
        assert_eq!(
            error(open("turn", &[r#"echo '{"Ok":"Done"}'"#])),
            OUT_OF_TURN
        );
        let flood = format!(
            "head -c {} /dev/zero | tr '\\0' a; echo",
            MAX_REPLY_BYTES + 1
        );
        assert!(
            error(open("flood", &[&flood])).contains("too long"),
            "flood"
        );
        assert!(error(open("silent", &[":"])).contains("stopped"), "silent");
        assert!(
            error(open(
                "refusal",
                &[r#"echo '{"Err":"No DSC token is plugged in."}'"#]
            ))
            .contains("No DSC token")
        );

        let token = open("later", &[opened, r#"echo '{"Ok":"Done"}'"#]).unwrap();
        assert_eq!(token.certificates(false).err().unwrap().0, OUT_OF_TURN);
        let token = open(
            "signature",
            &[opened, r#"echo '{"Ok":{"Signatures":[[1]]}}'"#],
        )
        .unwrap();
        assert_eq!(
            token.login(Zeroizing::new("1234".into())).unwrap_err().0,
            OUT_OF_TURN
        );
    }
}

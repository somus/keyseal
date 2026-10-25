//! `keyseal-token-worker`: runs the PKCS#11 operations of an Intel-only
//! macOS token driver for the KeySeal helper, which starts it under Rosetta
//! (see `keyseal_core::worker`). It answers each JSON request line on stdin
//! with one JSON line on stdout, writes nothing else there, and exits when
//! stdin closes or after `Close`.

use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;

use keyseal_core::token::{Module, Token, TokenBackend};
use keyseal_core::worker::{self, Reply, Request};
use zeroize::{Zeroize, Zeroizing};

fn main() -> ExitCode {
    match serve() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keyseal-token-worker: {e}");
            ExitCode::FAILURE
        }
    }
}

fn serve() -> io::Result<()> {
    let (mut input, mut output) = protocol_pipes()?;
    let mut token = None;
    // Requests are read into this buffer only, zeroised after each one: a
    // login request holds the PIN. Large enough that it never reallocates
    // for a login line.
    let mut line = Zeroizing::new(Vec::with_capacity(64 * 1024));
    loop {
        if !read_line(&mut input, &mut line)? {
            return Ok(());
        }
        let request = serde_json::from_slice::<Request>(&line);
        line.zeroize();
        let close = matches!(request, Ok(Request::Close));
        let reply = match request {
            Ok(Request::Close) => Ok(Reply::Done),
            Ok(request) => handle(&mut token, request),
            Err(e) => Err(format!("The token worker couldn't read a request: {e}")),
        };
        let mut json = serde_json::to_vec(&reply)?;
        json.push(b'\n');
        output.write_all(&json)?;
        if close {
            return Ok(());
        }
    }
}

fn handle(token: &mut Option<Token>, request: Request) -> Result<Reply, String> {
    if let Request::Open { module, wait } = request {
        let opened = Module::load(&module)?.open(wait)?;
        let reply = Reply::Opened {
            pin_pad: opened.pin_pad,
            pin_warning: opened.pin_warning,
        };
        *token = Some(opened);
        return Ok(reply);
    }
    let token = token.as_ref().ok_or("No token is open in the worker.")?;
    match request {
        Request::Certificates { with_private_key } => {
            Ok(Reply::Certificates(token.certificates(with_private_key)?))
        }
        Request::Login { pin } => {
            token.login(worker::decode_pin(&pin)?)?;
            Ok(Reply::Done)
        }
        Request::Sign {
            certificate,
            data,
            digest,
            scheme,
        } => Ok(Reply::Signatures(token.sign(
            &certificate,
            &data,
            digest,
            scheme,
            None,
        )?)),
        Request::Logout => {
            token.close();
            Ok(Reply::Done)
        }
        Request::Open { .. } | Request::Close => unreachable!("handled before"),
    }
}

/// Reads one line into `line` a byte at a time, so that no buffer but
/// `line` holds the PIN. False at the end of input.
#[expect(
    clippy::unbuffered_bytes,
    reason = "a read buffer would keep a copy of the PIN"
)]
fn read_line(input: &mut File, line: &mut Vec<u8>) -> io::Result<bool> {
    for byte in input.bytes() {
        match byte? {
            b'\n' => return Ok(true),
            byte => line.push(byte),
        }
    }
    Ok(false)
}

/// Stdin and stdout as unbuffered files. Descriptor 1 then points at
/// stderr, so a driver that prints can't corrupt the protocol.
#[cfg(unix)]
fn protocol_pipes() -> io::Result<(File, File)> {
    use std::os::fd::AsFd;
    let input = File::from(io::stdin().as_fd().try_clone_to_owned()?);
    let output = File::from(io::stdout().as_fd().try_clone_to_owned()?);
    // SAFETY: dup2 only replaces this process's own descriptor 1.
    if unsafe { libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) } == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((input, output))
}

#[cfg(windows)]
fn protocol_pipes() -> io::Result<(File, File)> {
    use std::os::windows::io::AsHandle;
    let input = File::from(io::stdin().as_handle().try_clone_to_owned()?);
    let output = File::from(io::stdout().as_handle().try_clone_to_owned()?);
    Ok((input, output))
}

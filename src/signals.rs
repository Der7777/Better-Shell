use std::io;

use log::debug;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

pub fn install_signal_handlers() -> io::Result<()> {
    let action = SigAction::new(SigHandler::SigIgn, SaFlags::SA_RESTART, SigSet::empty());
    install_action(Signal::SIGINT, &action)?;
    install_action(Signal::SIGTSTP, &action)?;
    install_action(Signal::SIGQUIT, &action)?;
    install_action(Signal::SIGTTIN, &action)?;
    install_action(Signal::SIGTTOU, &action)?;
    debug!("signal event=install mode=ignore");
    Ok(())
}

pub fn init_session(interactive: bool) -> io::Result<i32> {
    let pid = unsafe { libc::getpid() };
    if !interactive {
        let sid = unsafe { libc::getsid(0) };
        if sid != pid {
            let rc = unsafe { libc::setsid() };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::EPERM) {
                    return Err(err);
                }
            }
        }
    }
    let pgid = unsafe { libc::getpgrp() };
    if interactive && pgid != pid {
        let rc = unsafe { libc::setpgid(0, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let pgid = unsafe { libc::getpgrp() };
    let rc = unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, pgid) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOTTY) {
            return Err(err);
        }
    }
    Ok(pgid)
}

fn install_action(signal: Signal, action: &SigAction) -> io::Result<()> {
    unsafe { sigaction(signal, action) }
        .map(|_| ())
        .map_err(|err| io::Error::other(err.to_string()))
}

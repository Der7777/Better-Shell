use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};

use log::{debug, warn};
use nix::sys::signal::{
    kill, sigaction, sigprocmask, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal,
};
use nix::sys::termios::{tcgetattr, tcsetattr, SetArg, Termios};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{setpgid, tcsetpgrp, Pid};

pub fn set_process_group(command: &mut Command, fg_pgid: &Arc<AtomicI32>) {
    let fg_pgid = Arc::clone(fg_pgid);
    unsafe {
        command.pre_exec(move || {
            reset_ignored_signals()?;
            let pgid = fg_pgid.load(Ordering::SeqCst);
            let target = if pgid == 0 { 0 } else { pgid };
            setpgid(Pid::from_raw(0), Pid::from_raw(target))
                .map_err(|err| io::Error::other(err.to_string()))?;
            Ok(())
        });
    }
}

pub fn set_process_group_explicit(command: &mut Command, pgid: i32) {
    unsafe {
        command.pre_exec(move || {
            reset_ignored_signals()?;
            setpgid(Pid::from_raw(0), Pid::from_raw(pgid))
                .map_err(|err| io::Error::other(err.to_string()))?;
            Ok(())
        });
    }
}

fn reset_ignored_signals() -> io::Result<()> {
    let action = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
    for &sig in &[
        Signal::SIGTSTP,
        Signal::SIGQUIT,
        Signal::SIGTTIN,
        Signal::SIGTTOU,
    ] {
        unsafe { sigaction(sig, &action) }.map_err(|err| io::Error::other(err.to_string()))?;
    }
    Ok(())
}

pub fn set_terminal_foreground(pgid: i32) -> io::Result<()> {
    let fd = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
    match tcsetpgrp(fd, Pid::from_raw(pgid)) {
        Ok(()) => Ok(()),
        Err(nix::errno::Errno::ENOTTY) => Ok(()),
        Err(err) => Err(io::Error::other(err.to_string())),
    }
}

pub struct SignalMaskGuard {
    old: SigSet,
}

impl SignalMaskGuard {
    pub fn new() -> io::Result<Self> {
        let mut set = SigSet::empty();
        set.add(Signal::SIGINT);
        set.add(Signal::SIGCHLD);
        let mut old = SigSet::empty();
        sigprocmask(SigmaskHow::SIG_BLOCK, Some(&set), Some(&mut old))
            .map_err(|err| io::Error::other(err.to_string()))?;
        Ok(Self { old })
    }
}

impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if let Err(err) = sigprocmask(SigmaskHow::SIG_SETMASK, Some(&self.old), None) {
            warn!("signal event=restore mask error={}", err);
        }
    }
}

pub struct TermiosGuard {
    saved: Option<Termios>,
}

impl TermiosGuard {
    pub fn new() -> Self {
        Self {
            saved: tcgetattr(unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) }).ok(),
        }
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        if let Some(ref termios) = self.saved {
            let fd = unsafe { BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
            if let Err(err) = tcsetattr(fd, SetArg::TCSANOW, termios) {
                warn!("termios event=restore error={}", err);
            }
        }
    }
}

pub struct TerminalGuard {
    shell_pgid: i32,
    active: bool,
}

impl TerminalGuard {
    pub fn new(shell_pgid: i32) -> Self {
        Self {
            shell_pgid,
            active: false,
        }
    }

    pub fn set_foreground(&mut self, pgid: i32) -> io::Result<()> {
        set_terminal_foreground(pgid)?;
        self.active = true;
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if self.active {
            if let Err(err) = set_terminal_foreground(self.shell_pgid) {
                warn!("tty event=restore error={}", err);
            }
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum JobStatus {
    Running,
    Stopped,
}

pub struct Job {
    pub id: usize,
    pub pgid: i32,
    pub last_pid: i32,
    pub count: usize,
    pub command: String,
    pub status: JobStatus,
}

pub enum JobPoll {
    Done,
    Stopped,
    Running,
    NoChange,
}

pub enum WaitOutcome {
    Exited,
    Stopped,
}

pub struct WaitResult {
    pub outcome: WaitOutcome,
    pub status_code: Option<i32>,
    pub pipefail_status: Option<i32>,
}

pub struct BringJobResult {
    #[allow(dead_code)]
    pub outcome: WaitOutcome,
    pub status_code: Option<i32>,
    pub stopped_job: Option<Job>,
}

pub fn add_job_with_status(
    jobs: &mut Vec<Job>,
    next_job_id: &mut usize,
    pgid: i32,
    last_pid: i32,
    count: usize,
    command: &str,
    status: JobStatus,
) -> usize {
    let id = *next_job_id;
    *next_job_id += 1;
    jobs.push(Job {
        id,
        pgid,
        last_pid,
        count,
        command: command.trim_end_matches('&').trim().to_string(),
        status,
    });
    id
}

pub fn list_jobs(jobs: &[Job]) {
    if jobs.is_empty() {
        return;
    }
    for job in jobs {
        let status = match job.status {
            JobStatus::Running => "Running",
            JobStatus::Stopped => "Stopped",
        };
        println!("[{}] {status} {}", job.id, job.command);
    }
}

pub fn parse_job_id(arg: Option<&String>) -> io::Result<Option<usize>> {
    if let Some(value) = arg {
        let trimmed = value.strip_prefix('%').unwrap_or(value);
        trimmed
            .parse::<usize>()
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "job id must be a number"))
    } else {
        Ok(None)
    }
}

pub fn take_job(jobs: &mut Vec<Job>, id: Option<usize>) -> Option<Job> {
    if jobs.is_empty() {
        return None;
    }
    match id {
        Some(id) => {
            let index = jobs.iter().position(|job| job.id == id)?;
            Some(jobs.remove(index))
        }
        None => jobs.pop(),
    }
}

pub fn find_job(jobs: &mut [Job], id: Option<usize>) -> Option<&mut Job> {
    if jobs.is_empty() {
        return None;
    }
    match id {
        Some(id) => jobs.iter_mut().find(|job| job.id == id),
        None => jobs.last_mut(),
    }
}

pub fn bring_job_foreground(
    mut job: Job,
    fg_pgid: &Arc<AtomicI32>,
    shell_pgid: i32,
) -> io::Result<BringJobResult> {
    debug!("job event=fg pgid={} id={}", job.pgid, job.id);
    let handoff_guard = SignalMaskGuard::new()?;
    fg_pgid.store(job.pgid, Ordering::SeqCst);
    let _termios_guard = TermiosGuard::new();
    let mut tty_guard = TerminalGuard::new(shell_pgid);
    tty_guard.set_foreground(job.pgid)?;
    drop(handoff_guard);
    continue_job(job.pgid)?;
    let outcome = wait_for_process_group(job.pgid, job.count, job.last_pid)?;
    fg_pgid.store(0, Ordering::SeqCst);
    match outcome.outcome {
        WaitOutcome::Exited => Ok(BringJobResult {
            outcome: WaitOutcome::Exited,
            status_code: outcome.status_code,
            stopped_job: None,
        }),
        WaitOutcome::Stopped => {
            job.status = JobStatus::Stopped;
            Ok(BringJobResult {
                outcome: WaitOutcome::Stopped,
                status_code: outcome.status_code,
                stopped_job: Some(job),
            })
        }
    }
}

pub fn continue_job(pgid: i32) -> io::Result<()> {
    debug!("job event=cont pgid={}", pgid);
    kill(Pid::from_raw(-pgid), Signal::SIGCONT).map_err(|err| io::Error::other(err.to_string()))
}

pub fn wait_for_process_group(
    pgid: i32,
    expected_count: usize,
    last_pid: i32,
) -> io::Result<WaitResult> {
    debug!(
        "job event=wait pgid={} expected_count={} last_pid={}",
        pgid, expected_count, last_pid
    );
    let mut exited = 0usize;
    let mut status_code = None;
    let mut pipefail_status = None;
    loop {
        match waitpid(Pid::from_raw(-pgid), Some(WaitPidFlag::WUNTRACED)) {
            Ok(WaitStatus::Exited(pid, code)) => {
                debug!("job event=exit pgid={} pid={} code={}", pgid, pid, code);
                if pid.as_raw() == last_pid {
                    status_code = Some(code);
                }
                if code != 0 {
                    pipefail_status = Some(code);
                }
                exited += 1;
                if expected_count > 0 && exited >= expected_count {
                    return Ok(WaitResult {
                        outcome: WaitOutcome::Exited,
                        status_code: Some(status_code.unwrap_or(0)),
                        pipefail_status: Some(pipefail_status.unwrap_or(0)),
                    });
                }
            }
            Ok(WaitStatus::Signaled(pid, sig, _)) => {
                debug!(
                    "job event=signal pgid={} pid={} signal={}",
                    pgid, pid, sig as i32
                );
                if pid.as_raw() == last_pid {
                    status_code = Some(128 + sig as i32);
                }
                pipefail_status = Some(128 + sig as i32);
                exited += 1;
                if expected_count > 0 && exited >= expected_count {
                    return Ok(WaitResult {
                        outcome: WaitOutcome::Exited,
                        status_code: Some(status_code.unwrap_or(0)),
                        pipefail_status: Some(pipefail_status.unwrap_or(0)),
                    });
                }
                continue;
            }
            Ok(WaitStatus::Stopped(_, _)) => {
                debug!("job event=stopped pgid={}", pgid);
                let _ = kill(Pid::from_raw(-pgid), Signal::SIGTSTP);
                return Ok(WaitResult {
                    outcome: WaitOutcome::Stopped,
                    status_code: None,
                    pipefail_status: None,
                });
            }
            Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => continue,
            Ok(WaitStatus::StillAlive) | Ok(WaitStatus::Continued(_)) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => break,
            Err(err) => {
                debug!("job event=wait error={}", err);
                return Err(io::Error::other(err.to_string()));
            }
        }
    }
    Ok(WaitResult {
        outcome: WaitOutcome::Exited,
        status_code: Some(status_code.unwrap_or(0)),
        pipefail_status: Some(pipefail_status.unwrap_or(0)),
    })
}

pub fn reap_jobs(jobs: &mut Vec<Job>) {
    let mut index = 0;
    while index < jobs.len() {
        let pgid = jobs[index].pgid;
        match poll_job_status(pgid) {
            JobPoll::Done => {
                let job = jobs.remove(index);
                debug!("job event=reap done pgid={} id={}", job.pgid, job.id);
                println!("[{}] Done {}", job.id, job.command);
            }
            JobPoll::Stopped => {
                if jobs[index].status != JobStatus::Stopped {
                    jobs[index].status = JobStatus::Stopped;
                    debug!(
                        "job event=reap stopped pgid={} id={}",
                        jobs[index].pgid, jobs[index].id
                    );
                    println!("[{}] Stopped {}", jobs[index].id, jobs[index].command);
                }
                index += 1;
            }
            JobPoll::Running => {
                if jobs[index].status != JobStatus::Running {
                    jobs[index].status = JobStatus::Running;
                    debug!(
                        "job event=reap running pgid={} id={}",
                        jobs[index].pgid, jobs[index].id
                    );
                    println!("[{}] Running {}", jobs[index].id, jobs[index].command);
                }
                index += 1;
            }
            JobPoll::NoChange => {
                index += 1;
            }
        }
    }
}

fn poll_job_status(pgid: i32) -> JobPoll {
    let mut outcome = JobPoll::NoChange;
    loop {
        match waitpid(
            Pid::from_raw(-pgid),
            Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED | WaitPidFlag::WCONTINUED),
        ) {
            Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {
                debug!("job event=poll done pgid={}", pgid);
                outcome = JobPoll::Done;
                continue;
            }
            Ok(WaitStatus::Stopped(_, _)) => {
                debug!("job event=poll stopped pgid={}", pgid);
                outcome = JobPoll::Stopped;
                break;
            }
            Ok(WaitStatus::Continued(_)) => {
                debug!("job event=poll continued pgid={}", pgid);
                outcome = JobPoll::Running;
                continue;
            }
            Ok(WaitStatus::PtraceEvent(_, _, _)) | Ok(WaitStatus::PtraceSyscall(_)) => continue,
            Ok(WaitStatus::StillAlive) => break,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(nix::errno::Errno::ECHILD) => {
                if matches!(outcome, JobPoll::NoChange) {
                    outcome = JobPoll::Done;
                }
                break;
            }
            Err(_) => break,
        }
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::errno::Errno;
    use nix::sys::signal::{kill, Signal};
    use nix::sys::wait::waitpid;

    fn spawn_in_own_pgid(command: &str, args: &[&str]) -> io::Result<i32> {
        let mut cmd = Command::new(command);
        cmd.args(args);
        set_process_group_explicit(&mut cmd, 0);
        let child = cmd.spawn()?;
        Ok(child.id() as i32)
    }

    fn spawn_in_pgid(command: &str, args: &[&str], pgid: i32) -> io::Result<i32> {
        let mut cmd = Command::new(command);
        cmd.args(args);
        set_process_group_explicit(&mut cmd, pgid);
        let child = cmd.spawn()?;
        Ok(child.id() as i32)
    }

    fn reap_process_group(pgid: i32) {
        loop {
            match waitpid(Pid::from_raw(-pgid), None) {
                Ok(_) => continue,
                Err(Errno::EINTR) => continue,
                Err(Errno::ECHILD) => break,
                Err(_) => break,
            }
        }
    }

    #[test]
    fn wait_for_process_group_exits_with_status() {
        let pid = spawn_in_own_pgid("sh", &["-c", "exit 3"]).unwrap();
        let result = wait_for_process_group(pid, 1, pid).unwrap();
        assert!(matches!(result.outcome, WaitOutcome::Exited));
        assert_eq!(result.status_code, Some(3));
    }

    #[test]
    fn wait_for_process_group_stops_and_can_continue() {
        let pid = spawn_in_own_pgid("sh", &["-c", "kill -STOP $$; sleep 1"]).unwrap();
        let result = wait_for_process_group(pid, 1, pid).unwrap();
        assert!(matches!(result.outcome, WaitOutcome::Stopped));
        continue_job(pid).unwrap();
        let _ = kill(Pid::from_raw(-pid), Signal::SIGTERM);
        reap_process_group(pid);
    }

    #[test]
    fn wait_for_process_group_pipeline_pipefail() {
        let leader = spawn_in_own_pgid("sh", &["-c", "exit 0"]).unwrap();
        let follower = spawn_in_pgid("sh", &["-c", "exit 7"], leader).unwrap();
        let result = wait_for_process_group(leader, 2, follower).unwrap();
        assert!(matches!(result.outcome, WaitOutcome::Exited));
        assert_eq!(result.status_code, Some(7));
        assert_eq!(result.pipefail_status, Some(7));
    }

    #[test]
    fn wait_for_process_group_stops_when_member_stops() {
        let leader = spawn_in_own_pgid("sh", &["-c", "sleep 2"]).unwrap();
        let follower = spawn_in_pgid("sh", &["-c", "kill -STOP $$; sleep 1"], leader).unwrap();
        let result = wait_for_process_group(leader, 2, follower).unwrap();
        assert!(matches!(result.outcome, WaitOutcome::Stopped));
        continue_job(leader).unwrap();
        let _ = kill(Pid::from_raw(-leader), Signal::SIGTERM);
        reap_process_group(leader);
    }
}

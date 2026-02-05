use std::io;
use std::process::Command;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};

use log::debug;

use crate::job_control::{
    set_process_group, set_process_group_explicit, wait_for_process_group, SignalMaskGuard,
    TerminalGuard, TermiosGuard,
};
use crate::parse::CommandSpec;

use super::redirection::{
    apply_fd_closures, apply_input_redirection, apply_pipeline_stdin, apply_pipeline_stdout,
    apply_stderr_redirection, apply_stdout_redirection,
};
use super::sandbox::{apply_sandbox, SandboxOptions};
use super::{spawn_error_message, ForegroundResult};

pub fn build_command(cmd: &CommandSpec) -> io::Result<Command> {
    let mut command = Command::new(&cmd.args[0]);
    command.args(&cmd.args[1..]);

    apply_input_redirection(&mut command, cmd)?;
    if let Some(ref output) = cmd.stdout {
        apply_stdout_redirection(&mut command, output)?;
    }
    apply_stderr_redirection(&mut command, cmd)?;
    apply_fd_closures(&mut command, cmd)?;

    Ok(command)
}

pub(crate) fn build_pipeline_command(
    cmd: &CommandSpec,
    prev_stdout: Option<std::process::ChildStdout>,
    last: bool,
    pipe_last_if_missing: bool,
) -> io::Result<Command> {
    let mut command = Command::new(&cmd.args[0]);
    command.args(&cmd.args[1..]);

    apply_pipeline_stdin(&mut command, cmd, prev_stdout);
    apply_input_redirection(&mut command, cmd)?;
    apply_pipeline_stdout(&mut command, cmd, last, pipe_last_if_missing)?;
    apply_stderr_redirection(&mut command, cmd)?;
    apply_fd_closures(&mut command, cmd)?;

    Ok(command)
}

pub fn run_command_in_foreground(
    command: &mut Command,
    fg_pgid: &Arc<AtomicI32>,
    shell_pgid: i32,
    trace: bool,
    sandbox: Option<SandboxOptions>,
) -> io::Result<ForegroundResult> {
    // Use pre_exec so the child changes its own process group before exec.
    set_process_group(command, fg_pgid);
    // Block SIGCHLD during the handoff to avoid races with wait/reap.
    let handoff_guard = SignalMaskGuard::new()?;
    if let Some(options) = sandbox {
        apply_sandbox(command, &options)?;
    }
    let child = command
        .spawn()
        .map_err(|err| wrap_spawn_error(&command.get_program().to_string_lossy(), err))?;
    if trace {
        let pid = child.id();
        eprintln!("trace: spawn pid {pid} pgid {pid}");
    }
    debug!(
        "job event=spawn kind=single pid={} pgid={}",
        child.id(),
        child.id()
    );
    let pgid = child.id() as i32;
    fg_pgid.store(pgid, Ordering::SeqCst);
    let _termios_guard = TermiosGuard::new();
    let mut tty_guard = TerminalGuard::new(shell_pgid);
    // Hand the terminal to the job's process group for interactive control.
    tty_guard.set_foreground(pgid)?;
    drop(handoff_guard);
    let outcome = wait_for_process_group(pgid, 1, pgid)?;
    fg_pgid.store(0, Ordering::SeqCst);
    Ok(ForegroundResult {
        outcome: outcome.outcome,
        status_code: outcome.status_code,
        pipefail_status: outcome.pipefail_status,
        pgid,
        last_pid: pgid,
    })
}

pub fn spawn_command_background(
    command: &mut Command,
    trace: bool,
    sandbox: Option<SandboxOptions>,
) -> io::Result<(i32, i32)> {
    // Background jobs are tracked separately and do not take terminal control.
    let job_pgid = Arc::new(AtomicI32::new(0));
    set_process_group(command, &job_pgid);
    if let Some(options) = sandbox {
        apply_sandbox(command, &options)?;
    }
    let child = command
        .spawn()
        .map_err(|err| wrap_spawn_error(&command.get_program().to_string_lossy(), err))?;
    if trace {
        let pid = child.id();
        eprintln!("trace: spawn bg pid {pid} pgid {pid}");
    }
    debug!(
        "job event=spawn kind=background-single pid={} pgid={}",
        child.id(),
        child.id()
    );
    job_pgid.store(child.id() as i32, Ordering::SeqCst);
    Ok((job_pgid.load(Ordering::SeqCst), child.id() as i32))
}

#[cfg_attr(not(feature = "sandbox"), allow(dead_code))]
pub fn spawn_command_sandboxed(
    command: &mut Command,
    options: SandboxOptions,
) -> io::Result<(i32, i32)> {
    let job_pgid = Arc::new(AtomicI32::new(0));
    set_process_group(command, &job_pgid);
    apply_sandbox(command, &options)?;
    let child = command
        .spawn()
        .map_err(|err| wrap_spawn_error(&command.get_program().to_string_lossy(), err))?;
    if options.trace {
        let pid = child.id();
        eprintln!("trace: spawn sandboxed bg pid {pid} pgid {pid}");
    }
    debug!(
        "job event=spawn kind=sandboxed-background-single pid={} pgid={}",
        child.id(),
        child.id()
    );
    job_pgid.store(child.id() as i32, Ordering::SeqCst);
    Ok((job_pgid.load(Ordering::SeqCst), child.id() as i32))
}

pub fn spawn_pipeline_background(
    pipeline: &[CommandSpec],
    trace: bool,
    sandbox: &super::SandboxConfig,
) -> io::Result<(i32, i32)> {
    let mut prev_stdout = None;
    let mut pgid: Option<i32> = None;
    let mut last_pid: Option<i32> = None;

    for (idx, cmd) in pipeline.iter().enumerate() {
        let last = idx + 1 == pipeline.len();
        let mut command = build_pipeline_command(cmd, prev_stdout.take(), last, false)?;

        if let Some(id) = pgid {
            set_process_group_explicit(&mut command, id);
        } else {
            set_process_group_explicit(&mut command, 0);
        }
        if let Some(options) = super::sandbox_options_for_command(cmd, sandbox, trace) {
            apply_sandbox(&mut command, &options)?;
        }
        let mut child = command
            .spawn()
            .map_err(|err| wrap_spawn_error(&cmd.args[0], err))?;
        if trace {
            let pid = child.id();
            let pgid = pgid.unwrap_or(pid as i32);
            eprintln!("trace: spawn bg pid {pid} pgid {pgid}");
        }
        debug!(
            "job event=spawn kind=background idx={} pid={} pgid={}",
            idx,
            child.id(),
            pgid.unwrap_or(child.id() as i32)
        );
        if pgid.is_none() {
            pgid = Some(child.id() as i32);
        }
        if idx + 1 == pipeline.len() {
            last_pid = Some(child.id() as i32);
        }
        prev_stdout = child.stdout.take();
    }

    Ok((pgid.unwrap_or(0), last_pid.unwrap_or(0)))
}

#[cfg_attr(not(feature = "sandbox"), allow(dead_code))]
pub fn spawn_pipeline_sandboxed(
    pipeline: &[CommandSpec],
    options: SandboxOptions,
) -> io::Result<(i32, i32)> {
    let mut prev_stdout = None;
    let mut pgid: Option<i32> = None;
    let mut last_pid: Option<i32> = None;

    for (idx, cmd) in pipeline.iter().enumerate() {
        let last = idx + 1 == pipeline.len();
        let mut command = build_pipeline_command(cmd, prev_stdout.take(), last, false)?;

        if let Some(id) = pgid {
            set_process_group_explicit(&mut command, id);
        } else {
            set_process_group_explicit(&mut command, 0);
        }

        apply_sandbox(&mut command, &options)?;
        let mut child = command
            .spawn()
            .map_err(|err| wrap_spawn_error(&cmd.args[0], err))?;
        if options.trace {
            let pid = child.id();
            let pgid = pgid.unwrap_or(pid as i32);
            eprintln!("trace: spawn sandboxed bg pid {pid} pgid {pgid}");
        }
        debug!(
            "job event=spawn kind=sandboxed-background idx={} pid={} pgid={}",
            idx,
            child.id(),
            pgid.unwrap_or(child.id() as i32)
        );
        if pgid.is_none() {
            pgid = Some(child.id() as i32);
        }
        if idx + 1 == pipeline.len() {
            last_pid = Some(child.id() as i32);
        }
        prev_stdout = child.stdout.take();
    }

    Ok((pgid.unwrap_or(0), last_pid.unwrap_or(0)))
}

pub fn wrap_spawn_error(cmd: &str, err: io::Error) -> io::Error {
    let (message, kind) = spawn_error_message(cmd, &err);
    io::Error::new(kind, message)
}

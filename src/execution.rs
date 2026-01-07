use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};

use log::debug;
use nix::unistd::{pipe, write};
#[cfg(feature = "sandbox")]
use std::ffi::CString;
#[cfg(feature = "sandbox")]
use std::os::unix::ffi::OsStrExt;
#[cfg(feature = "sandbox")]
use std::os::unix::process::CommandExt;

use crate::job_control::{
    set_process_group, set_process_group_explicit, wait_for_process_group, SignalMaskGuard,
    TerminalGuard, TermiosGuard, WaitOutcome, WaitResult,
};
use crate::parse::{CommandSpec, SandboxDirective};

pub struct ForegroundResult {
    pub outcome: WaitOutcome,
    pub status_code: Option<i32>,
    pub pipefail_status: Option<i32>,
    pub pgid: i32,
    pub last_pid: i32,
}

pub struct CaptureResult {
    pub output: String,
    pub status_code: i32,
}

#[derive(Debug, Clone, Copy)]
pub enum SandboxBackend {
    Bubblewrap,
    Native,
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub backend: SandboxBackend,
    pub bubblewrap_path: Option<String>,
    pub bubblewrap_args: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: SandboxBackend::Native,
            bubblewrap_path: None,
            bubblewrap_args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "sandbox"), allow(dead_code))]
pub struct SandboxOptions {
    pub trace: bool,
    pub backend: SandboxBackend,
    pub bubblewrap_path: Option<String>,
    pub bubblewrap_args: Vec<String>,
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            trace: false,
            backend: SandboxBackend::Native,
            bubblewrap_path: None,
            bubblewrap_args: Vec::new(),
        }
    }
}

pub fn apply_sandbox_directive(sandbox: &mut SandboxConfig, directive: SandboxDirective) {
    match directive {
        SandboxDirective::Enable => sandbox.enabled = true,
        SandboxDirective::Disable => sandbox.enabled = false,
        SandboxDirective::Bubblewrap => {
            sandbox.enabled = true;
            sandbox.backend = SandboxBackend::Bubblewrap;
        }
        SandboxDirective::Native => {
            sandbox.enabled = true;
            sandbox.backend = SandboxBackend::Native;
        }
    }
}

pub fn sandbox_options_for_command(
    cmd: &CommandSpec,
    sandbox: &SandboxConfig,
    trace: bool,
) -> Option<SandboxOptions> {
    let mut enabled = sandbox.enabled;
    let mut backend = sandbox.backend;
    if let Some(directive) = cmd.sandbox {
        match directive {
            SandboxDirective::Enable => enabled = true,
            SandboxDirective::Disable => enabled = false,
            SandboxDirective::Bubblewrap => {
                enabled = true;
                backend = SandboxBackend::Bubblewrap;
            }
            SandboxDirective::Native => {
                enabled = true;
                backend = SandboxBackend::Native;
            }
        }
    }
    if !enabled {
        return None;
    }
    Some(SandboxOptions {
        trace,
        backend,
        bubblewrap_path: sandbox.bubblewrap_path.clone(),
        bubblewrap_args: sandbox.bubblewrap_args.clone(),
    })
}

pub fn run_pipeline_capture(
    pipeline: &[CommandSpec],
    fg_pgid: &Arc<AtomicI32>,
    trace: bool,
    sandbox: &SandboxConfig,
) -> io::Result<CaptureResult> {
    debug!("job event=capture start count={}", pipeline.len());
    let mut children = Vec::with_capacity(pipeline.len());
    let mut prev_stdout = None;
    let mut capture_stdout = None;
    let mut pgid: Option<i32> = None;
    let mut last_pid: Option<i32> = None;

    for (idx, cmd) in pipeline.iter().enumerate() {
        let mut command = Command::new(&cmd.args[0]);
        command.args(&cmd.args[1..]);

        if let Some(stdout) = prev_stdout.take() {
            if cmd.stdin.is_none() && cmd.heredoc.is_none() {
                command.stdin(Stdio::from(stdout));
            }
        }

        apply_input_redirection(&mut command, cmd)?;

        let last = idx + 1 == pipeline.len();
        if last {
            if cmd.stdout.is_none() {
                command.stdout(Stdio::piped());
            } else if let Some(ref output) = cmd.stdout {
                let mut opts = OpenOptions::new();
                opts.write(true).create(true);
                if output.append {
                    opts.append(true);
                } else {
                    opts.truncate(true);
                }
                let file = opts.open(&output.path)?;
                command.stdout(Stdio::from(file));
            }
        } else {
            command.stdout(Stdio::piped());
        }

        if let Some(id) = pgid {
            set_process_group_explicit(&mut command, id);
        } else {
            set_process_group_explicit(&mut command, 0);
        }
        if let Some(options) = sandbox_options_for_command(cmd, sandbox, trace) {
            apply_sandbox(&mut command, &options)?;
        }
        let mut child = command
            .spawn()
            .map_err(|err| wrap_spawn_error(&cmd.args[0], err))?;
        if trace {
            let pid = child.id();
            let pgid = pgid.unwrap_or(pid as i32);
            eprintln!("trace: spawn sub pid {pid} pgid {pgid}");
        }
        debug!(
            "job event=spawn kind=substitution idx={} pid={} pgid={}",
            idx,
            child.id(),
            pgid.unwrap_or(child.id() as i32)
        );
        if pgid.is_none() {
            let id = child.id() as i32;
            pgid = Some(id);
            fg_pgid.store(id, Ordering::SeqCst);
        }
        if last {
            last_pid = Some(child.id() as i32);
        }
        if last {
            capture_stdout = child.stdout.take();
        } else {
            prev_stdout = child.stdout.take();
        }
        children.push(child);
    }

    let mut output = String::new();
    if let Some(mut stdout) = capture_stdout {
        stdout.read_to_string(&mut output)?;
    }

    let mut status_code = 0;
    for mut child in children {
        let status = child.wait()?;
        if Some(child.id() as i32) == last_pid {
            status_code = exit_status_code(status);
        }
        if !status.success() {
            eprintln!("process exited with {status}");
        }
    }

    fg_pgid.store(0, Ordering::SeqCst);
    debug!("job event=capture done status={}", status_code);
    Ok(CaptureResult {
        output,
        status_code,
    })
}

pub fn run_pipeline(
    pipeline: &[CommandSpec],
    fg_pgid: &Arc<AtomicI32>,
    shell_pgid: i32,
    trace: bool,
    sandbox: &SandboxConfig,
) -> io::Result<ForegroundResult> {
    debug!("job event=pipeline start count={}", pipeline.len());
    let mut prev_stdout = None;
    let mut pgid: Option<i32> = None;
    let mut last_pid: Option<i32> = None;
    let mut handoff_guard: Option<SignalMaskGuard> = None;

    for (idx, cmd) in pipeline.iter().enumerate() {
        let mut command = Command::new(&cmd.args[0]);
        command.args(&cmd.args[1..]);

        if let Some(stdout) = prev_stdout.take() {
            if cmd.stdin.is_none() && cmd.heredoc.is_none() {
                command.stdin(Stdio::from(stdout));
            }
        }

        apply_input_redirection(&mut command, cmd)?;

        if idx + 1 < pipeline.len() {
            command.stdout(Stdio::piped());
        } else if let Some(ref output) = cmd.stdout {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true);
            if output.append {
                opts.append(true);
            } else {
                opts.truncate(true);
            }
            let file = opts.open(&output.path)?;
            command.stdout(Stdio::from(file));
        }

        if let Some(id) = pgid {
            set_process_group_explicit(&mut command, id);
        } else {
            set_process_group_explicit(&mut command, 0);
        }
        if let Some(options) = sandbox_options_for_command(cmd, sandbox, trace) {
            apply_sandbox(&mut command, &options)?;
        }
        let mut child = command
            .spawn()
            .map_err(|err| wrap_spawn_error(&cmd.args[0], err))?;
        if trace {
            let pid = child.id();
            let pgid = pgid.unwrap_or(pid as i32);
            eprintln!("trace: spawn pid {pid} pgid {pgid}");
        }
        debug!(
            "job event=spawn kind=foreground idx={} pid={} pgid={}",
            idx,
            child.id(),
            pgid.unwrap_or(child.id() as i32)
        );
        if pgid.is_none() {
            handoff_guard = Some(SignalMaskGuard::new()?);
            let id = child.id() as i32;
            pgid = Some(id);
            fg_pgid.store(id, Ordering::SeqCst);
        }
        if idx + 1 == pipeline.len() {
            last_pid = Some(child.id() as i32);
        }
        prev_stdout = child.stdout.take();
    }

    let outcome = if let Some(id) = pgid {
        let _termios_guard = TermiosGuard::new();
        let mut tty_guard = TerminalGuard::new(shell_pgid);
        tty_guard.set_foreground(id)?;
        drop(handoff_guard.take());
        wait_for_process_group(id, pipeline.len(), last_pid.unwrap_or(id))?
    } else {
        WaitResult {
            outcome: WaitOutcome::Exited,
            status_code: Some(0),
            pipefail_status: Some(0),
        }
    };

    fg_pgid.store(0, Ordering::SeqCst);
    debug!(
        "job event=pipeline done pgid={} last_pid={} status={:?}",
        pgid.unwrap_or(0),
        last_pid.unwrap_or(0),
        outcome.status_code
    );
    Ok(ForegroundResult {
        outcome: outcome.outcome,
        status_code: outcome.status_code,
        pipefail_status: outcome.pipefail_status,
        pgid: pgid.unwrap_or(0),
        last_pid: last_pid.unwrap_or(0),
    })
}

pub fn spawn_pipeline_background(
    pipeline: &[CommandSpec],
    trace: bool,
    sandbox: &SandboxConfig,
) -> io::Result<(i32, i32)> {
    let mut prev_stdout = None;
    let mut pgid: Option<i32> = None;
    let mut last_pid: Option<i32> = None;

    for (idx, cmd) in pipeline.iter().enumerate() {
        let mut command = Command::new(&cmd.args[0]);
        command.args(&cmd.args[1..]);

        if let Some(stdout) = prev_stdout.take() {
            if cmd.stdin.is_none() && cmd.heredoc.is_none() {
                command.stdin(Stdio::from(stdout));
            }
        }

        apply_input_redirection(&mut command, cmd)?;

        if idx + 1 < pipeline.len() {
            command.stdout(Stdio::piped());
        } else if let Some(ref output) = cmd.stdout {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true);
            if output.append {
                opts.append(true);
            } else {
                opts.truncate(true);
            }
            let file = opts.open(&output.path)?;
            command.stdout(Stdio::from(file));
        }

        if let Some(id) = pgid {
            set_process_group_explicit(&mut command, id);
        } else {
            set_process_group_explicit(&mut command, 0);
        }
        if let Some(options) = sandbox_options_for_command(cmd, sandbox, trace) {
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
        let mut command = Command::new(&cmd.args[0]);
        command.args(&cmd.args[1..]);

        if let Some(stdout) = prev_stdout.take() {
            if cmd.stdin.is_none() && cmd.heredoc.is_none() {
                command.stdin(Stdio::from(stdout));
            }
        }

        apply_input_redirection(&mut command, cmd)?;

        if idx + 1 < pipeline.len() {
            command.stdout(Stdio::piped());
        } else if let Some(ref output) = cmd.stdout {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true);
            if output.append {
                opts.append(true);
            } else {
                opts.truncate(true);
            }
            let file = opts.open(&output.path)?;
            command.stdout(Stdio::from(file));
        }

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

pub fn run_command_in_foreground(
    command: &mut Command,
    fg_pgid: &Arc<AtomicI32>,
    shell_pgid: i32,
    trace: bool,
    sandbox: Option<SandboxOptions>,
) -> io::Result<ForegroundResult> {
    set_process_group(command, fg_pgid);
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

pub fn build_command(cmd: &CommandSpec) -> io::Result<Command> {
    let mut command = Command::new(&cmd.args[0]);
    command.args(&cmd.args[1..]);

    apply_input_redirection(&mut command, cmd)?;
    if let Some(ref output) = cmd.stdout {
        let mut opts = OpenOptions::new();
        opts.write(true).create(true);
        if output.append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let file = opts.open(&output.path)?;
        command.stdout(Stdio::from(file));
    }

    Ok(command)
}

pub fn apply_input_redirection(command: &mut Command, cmd: &CommandSpec) -> io::Result<()> {
    if cmd.stdin.is_some() && cmd.heredoc.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multiple input redirections",
        ));
    }
    if let Some(ref path) = cmd.stdin {
        let file = OpenOptions::new().read(true).open(path)?;
        command.stdin(Stdio::from(file));
    }
    if let Some(ref heredoc) = cmd.heredoc {
        let Some(ref content) = heredoc.content else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "heredoc not supported here",
            ));
        };
        command.stdin(heredoc_stdin(content)?);
    }
    Ok(())
}

fn heredoc_stdin(content: &str) -> io::Result<Stdio> {
    let (read_fd, write_fd) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
    let bytes = content.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let written =
            write(&write_fd, &bytes[offset..]).map_err(|err| io::Error::other(err.to_string()))?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "heredoc write returned 0",
            ));
        }
        offset += written;
    }
    drop(write_fd);
    let file = unsafe { fs::File::from_raw_fd(read_fd.into_raw_fd()) };
    Ok(Stdio::from(file))
}

fn apply_sandbox(command: &mut Command, options: &SandboxOptions) -> io::Result<()> {
    #[cfg(feature = "sandbox")]
    {
        match options.backend {
            SandboxBackend::Bubblewrap => {
                let program = command.get_program().to_os_string();
                let args: Vec<_> = command.get_args().map(|arg| arg.to_os_string()).collect();
                let bwrap_path = options
                    .bubblewrap_path
                    .unwrap_or_else(|| "bwrap".to_string());
                let bwrap_path_os = std::ffi::OsString::from(bwrap_path);
                let mut bwrap_args = options
                    .bubblewrap_args
                    .into_iter()
                    .map(|arg| arg.into())
                    .collect::<Vec<_>>();
                bwrap_args.push("--".into());
                bwrap_args.push(program);
                bwrap_args.extend(args);
                unsafe {
                    command.pre_exec(move || {
                        execvp_os(&bwrap_path_os, &bwrap_args).map_err(|err| {
                            io::Error::new(err.kind(), format!("bwrap exec failed: {err}"))
                        })
                    });
                }
                Ok(())
            }
            SandboxBackend::Native => {
                let program = command.get_program().to_os_string();
                let args: Vec<_> = command.get_args().map(|arg| arg.to_os_string()).collect();
                unsafe {
                    command.pre_exec(move || native_sandbox_exec(&program, &args));
                }
                Ok(())
            }
        }
    }
    #[cfg(not(feature = "sandbox"))]
    {
        let _ = (command, options);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sandbox feature disabled",
        ))
    }
}

#[cfg(feature = "sandbox")]
fn execvp_os(program: &std::ffi::OsStr, args: &[std::ffi::OsString]) -> io::Result<()> {
    let prog_c = CString::new(program.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "program contains null"))?;
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(prog_c.clone());
    for arg in args {
        let cstr = CString::new(arg.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains null"))?;
        argv.push(cstr);
    }
    nix::unistd::execvp(&prog_c, &argv).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(())
}

#[cfg(feature = "sandbox")]
fn native_sandbox_exec(
    program: &std::ffi::OsString,
    args: &[std::ffi::OsString],
) -> io::Result<()> {
    // Placeholder for advanced native sandbox setup.
    execvp_os(program, args)
}

pub fn wrap_spawn_error(cmd: &str, err: io::Error) -> io::Error {
    let (message, kind) = spawn_error_message(cmd, &err);
    io::Error::new(kind, message)
}

pub fn status_from_error(err: &io::Error) -> i32 {
    match err.kind() {
        io::ErrorKind::NotFound => 127,
        io::ErrorKind::PermissionDenied => 126,
        _ => 1,
    }
}

pub fn exit_status_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}

fn spawn_error_message(cmd: &str, err: &io::Error) -> (String, io::ErrorKind) {
    match err.kind() {
        io::ErrorKind::NotFound => (format!("{cmd}: command not found"), io::ErrorKind::NotFound),
        io::ErrorKind::PermissionDenied => (
            format!("{cmd}: permission denied"),
            io::ErrorKind::PermissionDenied,
        ),
        _ => {
            if cmd.contains('/') {
                if let Ok(meta) = fs::metadata(cmd) {
                    if meta.is_dir() {
                        return (
                            format!("{cmd}: is a directory"),
                            io::ErrorKind::PermissionDenied,
                        );
                    }
                }
            }
            (format!("{cmd}: {err}"), err.kind())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::HeredocSpec;
    use tempfile::tempdir;

    fn run_cat_with_spec(spec: CommandSpec) -> io::Result<String> {
        let mut command = build_command(&spec)?;
        command.stdout(Stdio::piped());
        let child = command.spawn()?;
        let output = child.wait_with_output()?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[test]
    fn apply_input_redirection_reads_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("input.txt");
        fs::write(&path, "hello").unwrap();

        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.stdin = Some(path.display().to_string());

        match run_cat_with_spec(spec) {
            Ok(output) => assert_eq!(output, "hello"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                eprintln!("cat not found; skipping test");
            }
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn heredoc_pipes_content() {
        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.heredoc = Some(HeredocSpec {
            delimiter: "EOF".to_string(),
            quoted: false,
            content: Some("line1\nline2\n".to_string()),
        });

        match run_cat_with_spec(spec) {
            Ok(output) => assert_eq!(output, "line1\nline2\n"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                eprintln!("cat not found; skipping test");
            }
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn multiple_input_redirections_error() {
        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.stdin = Some("in.txt".to_string());
        spec.heredoc = Some(HeredocSpec {
            delimiter: "EOF".to_string(),
            quoted: false,
            content: Some("data".to_string()),
        });
        let mut command = Command::new("cat");
        let err = apply_input_redirection(&mut command, &spec).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

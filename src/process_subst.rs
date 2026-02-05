use std::io;
use std::os::unix::io::RawFd;
use std::sync::Arc;

use nix::unistd::{close, pipe};

use crate::execution::{spawn_pipeline_background, SandboxConfig};
use crate::expansion::{expand_globs, expand_tokens};
use crate::job_control::wait_for_process_group;
use crate::parse::{parse_line, parse_line_lenient, split_pipeline, split_sequence, SeqOp};
use crate::{build_expansion_context};

pub struct ProcessSubstResult {
    pub tokens: Vec<String>,
    pub keep_fds: Vec<RawFd>,
}

pub struct FdGuard(pub Vec<RawFd>);

impl Drop for FdGuard {
    fn drop(&mut self) {
        close_fds(std::mem::take(&mut self.0));
    }
}

pub fn apply_process_subst(
    tokens: Vec<String>,
    fg_pgid: Arc<std::sync::atomic::AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
    arrays: std::collections::HashMap<String, Vec<String>>,
    strict: bool,
) -> io::Result<ProcessSubstResult> {
    let mut out = Vec::with_capacity(tokens.len());
    let mut keep_fds = Vec::new();

    for token in tokens {
        if let Some((kind, inner)) = parse_process_subst_token(&token) {
            let (read_fd, write_fd) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
            let (path_fd, child_fd, keep_fd) = match kind {
                SubstKind::Input => (read_fd, write_fd, read_fd),
                SubstKind::Output => (write_fd, read_fd, write_fd),
            };
            let path = format!("/dev/fd/{path_fd}");
            let pipeline = build_subst_pipeline(
                &inner,
                &fg_pgid,
                trace,
                sandbox.clone(),
                arrays.clone(),
                strict,
                child_fd,
                kind,
            )?;
            let (pgid, last_pid) = spawn_pipeline_background(&pipeline, trace, &sandbox)?;
            std::thread::spawn(move || {
                let _ = wait_for_process_group(pgid, pipeline.len(), last_pid);
            });
            let _ = close(child_fd);
            out.push(path);
            keep_fds.push(keep_fd);
        } else {
            out.push(token);
        }
    }

    Ok(ProcessSubstResult { tokens: out, keep_fds })
}

#[derive(Copy, Clone)]
enum SubstKind {
    Input,
    Output,
}

fn parse_process_subst_token(token: &str) -> Option<(SubstKind, String)> {
    if token.starts_with("<(") && token.ends_with(')') && token.len() > 3 {
        let inner = token[2..token.len() - 1].to_string();
        return Some((SubstKind::Input, inner));
    }
    if token.starts_with(">(") && token.ends_with(')') && token.len() > 3 {
        let inner = token[2..token.len() - 1].to_string();
        return Some((SubstKind::Output, inner));
    }
    None
}

fn build_subst_pipeline(
    inner: &str,
    fg_pgid: &Arc<std::sync::atomic::AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
    arrays: std::collections::HashMap<String, Vec<String>>,
    strict: bool,
    fd: RawFd,
    kind: SubstKind,
) -> io::Result<Vec<crate::parse::CommandSpec>> {
    let tokens = if strict {
        parse_line(inner)
    } else {
        parse_line_lenient(inner)
    }
    .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    let ctx = build_expansion_context(
        Arc::clone(fg_pgid),
        trace,
        sandbox.clone(),
        arrays,
        &[],
        strict,
    );
    let expanded = expand_tokens(tokens, &ctx)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    let expanded = expand_globs(expanded)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    let segments = split_sequence(expanded)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    if segments.len() != 1 || !matches!(segments[0].op, SeqOp::Always) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process substitution requires a single command",
        ));
    }
    let (mut pipeline, background) = split_pipeline(segments[0].tokens.clone())
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    if background {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "background jobs not supported in process substitution",
        ));
    }
    if pipeline.iter().any(|cmd| crate::builtins::is_builtin(cmd.args.first().map(String::as_str)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "builtins not supported in process substitution",
        ));
    }
    match kind {
        SubstKind::Input => {
            let last = pipeline
                .last_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
            if last.stdout.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "process substitution conflicts with stdout redirection",
                ));
            }
            last.stdout = Some(crate::parse::OutputRedirection {
                path: format!("/dev/fd/{fd}"),
                append: false,
            });
        }
        SubstKind::Output => {
            let first = pipeline
                .first_mut()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
            if first.stdin.is_some() || first.heredoc.is_some() || first.herestring.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "process substitution conflicts with stdin redirection",
                ));
            }
            first.stdin = Some(format!("/dev/fd/{fd}"));
        }
    }
    Ok(pipeline)
}

pub fn close_fds(fds: Vec<RawFd>) {
    for fd in fds {
        let _ = close(fd);
    }
}

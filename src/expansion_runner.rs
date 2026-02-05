use std::env;
use std::io;
use std::sync::{
    atomic::AtomicI32,
    Arc,
};

use crate::builtins::{execute_builtin_substitution_capture, is_builtin};
use crate::execution::{builtin_pipe_capture, run_pipeline_capture, SandboxConfig};
use crate::expansion::{expand_globs, expand_tokens, ExpansionContext};
use crate::io_helpers::normalize_command_output;
use crate::parse::{
    parse_line, parse_line_lenient, split_pipeline, split_sequence, SeqOp, SeqSegment,
};
use crate::process_subst::{apply_process_subst, FdGuard, ProcessSubstResult};

fn execute_command_substitution(
    inner: &str,
    fg_pgid: &Arc<AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
    arrays: std::collections::HashMap<String, Vec<String>>,
    strict: bool,
) -> Result<String, String> {
    let tokens = if strict {
        parse_line(inner)?
    } else {
        parse_line_lenient(inner)?
    };
    if tokens.is_empty() {
        return Ok(String::new());
    }
    let ctx = build_expansion_context(
        Arc::clone(fg_pgid),
        trace,
        sandbox.clone(),
        arrays.clone(),
        &[],
        strict,
    );
    let (segments, _fd_guard) = expand_and_split_tokens(
        tokens,
        &ctx,
        fg_pgid,
        trace,
        &sandbox,
        arrays.clone(),
        strict,
    )?;
    if segments.is_empty() {
        return Ok(String::new());
    }
    execute_segments_capture(
        segments,
        fg_pgid,
        trace,
        &sandbox,
        "background jobs not allowed in command substitution",
        "command substitution failed",
    )
}

pub(crate) fn execute_tokens_capture(
    tokens: Vec<String>,
    fg_pgid: Arc<AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
    arrays: std::collections::HashMap<String, Vec<String>>,
    strict: bool,
) -> Result<String, String> {
    // Capture mode forbids background jobs to keep substitutions deterministic.
    let ctx = build_expansion_context(
        Arc::clone(&fg_pgid),
        trace,
        sandbox.clone(),
        arrays.clone(),
        &[],
        strict,
    );
    let (segments, _fd_guard) = expand_and_split_tokens(
        tokens,
        &ctx,
        &fg_pgid,
        trace,
        &sandbox,
        arrays.clone(),
        strict,
    )?;
    if segments.is_empty() {
        return Ok(String::new());
    }
    execute_segments_capture(
        segments,
        &fg_pgid,
        trace,
        &sandbox,
        "background jobs not allowed in prompt function",
        "prompt function failed",
    )
}

fn expand_and_split_tokens(
    tokens: Vec<String>,
    ctx: &ExpansionContext<'_>,
    fg_pgid: &Arc<AtomicI32>,
    trace: bool,
    sandbox: &SandboxConfig,
    arrays: std::collections::HashMap<String, Vec<String>>,
    strict: bool,
) -> Result<(Vec<SeqSegment>, FdGuard), String> {
    let expanded = expand_tokens(tokens, ctx)?;
    if expanded.is_empty() {
        return Ok((Vec::new(), FdGuard(Vec::new())));
    }
    let ProcessSubstResult { tokens: expanded, keep_fds } = apply_process_subst(
        expanded,
        Arc::clone(fg_pgid),
        trace,
        sandbox.clone(),
        arrays,
        strict,
    )
    .map_err(|err| err.to_string())?;
    let fd_guard = FdGuard(keep_fds);
    let expanded = expand_globs(expanded)?;
    if expanded.is_empty() {
        return Ok((Vec::new(), fd_guard));
    }
    let segments = split_sequence(expanded)?;
    Ok((segments, fd_guard))
}

fn execute_segments_capture(
    segments: Vec<SeqSegment>,
    fg_pgid: &Arc<AtomicI32>,
    trace: bool,
    sandbox: &SandboxConfig,
    background_error: &str,
    failure_context: &str,
) -> Result<String, String> {
    let mut output = String::new();
    let mut last_status = 0;

    for segment in segments {
        let should_run = match segment.op {
            SeqOp::Always => true,
            SeqOp::And => last_status == 0,
            SeqOp::Or => last_status != 0,
        };
        if !should_run {
            continue;
        }
        let (pipeline, background) = split_pipeline(segment.tokens)?;
        if background {
            return Err(background_error.to_string());
        }
        let has_builtin = pipeline
            .iter()
            .any(|cmd| is_builtin(cmd.args.first().map(String::as_str)));
        if has_builtin {
            if pipeline.len() == 1 {
                let result = execute_builtin_substitution_capture(&pipeline[0], None)?;
                output.push_str(&result.output);
                last_status = result.status_code;
                continue;
            }
            let result = builtin_pipe_capture(
                &pipeline,
                |cmd| is_builtin(cmd.args.first().map(String::as_str)),
                |cmd, stdin| {
                    execute_builtin_substitution_capture(cmd, stdin)
                        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
                },
                trace,
                sandbox,
            )
            .map_err(|err| format!("{failure_context}: {err}"))?;
            output.push_str(&result.output);
            last_status = result.status_code;
            continue;
        }
        let result = run_pipeline_capture(pipeline.as_slice(), fg_pgid, trace, sandbox)
            .map_err(|err| format!("{failure_context}: {err}"))?;
        output.push_str(&result.output);
        last_status = result.status_code;
    }

    Ok(normalize_command_output(output))
}

pub(crate) fn build_expansion_context(
    fg_pgid: Arc<AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
    arrays: std::collections::HashMap<String, Vec<String>>,
    positional: &'static [String],
    strict: bool,
) -> ExpansionContext<'static> {
    let arrays_for_lookup = arrays.clone();
    let arrays_for_subst = arrays.clone();
    ExpansionContext {
        // Static slice keeps closures simple for expansion usage sites.
        lookup_var: Box::new(move |name| {
            if let Ok(idx) = name.parse::<usize>() {
                if idx > 0 && idx <= positional.len() {
                    return Some(positional[idx - 1].clone());
                }
            }
            match name {
                "#" => Some(positional.len().to_string()),
                "*" => Some(positional.join(" ")),
                "@" => Some(positional.join(" ")), // for now, same as *
                _ => env::var(name).ok(),
            }
        }),
        lookup_array: Box::new(move |name| arrays_for_lookup.get(name).cloned()),
        // Boxed closure allows swapping implementations in tests or future shells.
        command_subst: Box::new(move |inner| {
            execute_command_substitution(
                inner,
                &fg_pgid,
                trace,
                sandbox.clone(),
                arrays_for_subst.clone(),
                strict,
            )
        }),
        positional,
        strict,
    }
}

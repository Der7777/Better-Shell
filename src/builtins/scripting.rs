use std::io;
use std::sync::Arc;

use crate::expansion::{expand_globs_with, expand_tokens};
use crate::expansion::GlobOptions;
use crate::process_subst::{apply_process_subst, FdGuard, ProcessSubstResult};
use crate::parse::{split_sequence, token_str, SeqOp};
use crate::utils::is_valid_var_name;
use crate::{build_expansion_context, execute_segment, run_return_trap, trace_tokens, ShellState};

pub(crate) fn execute_script_tokens(state: &mut ShellState, tokens: Vec<String>) -> io::Result<()> {
    let glob_options = GlobOptions {
        extglob: state.extglob,
        nullglob: state.nullglob,
        failglob: state.failglob,
        dotglob: state.dotglob,
        nocaseglob: state.nocaseglob,
        dirspell: state.dirspell,
    };
    let positional = state.current_positional().to_vec();
    let ctx = build_expansion_context(
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        state.assoc_arrays.clone(),
        state.builtin_enabled.clone(),
        glob_options,
        &positional,
        true,
    );
    let expanded = match expand_tokens(tokens, &ctx) {
        Ok(v) => v,
        Err(msg) => {
            state.last_status = 2;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse error: {msg}"),
            ));
        }
    };
    trace_tokens(state, "expanded tokens", &expanded);

    if expanded.is_empty() {
        return Ok(());
    }

    let ProcessSubstResult { tokens: expanded, keep_fds } = apply_process_subst(
        expanded,
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        state.assoc_arrays.clone(),
        state.builtin_enabled.clone(),
        glob_options,
        true,
    )?;
    let _fd_guard = FdGuard(keep_fds);

    let expanded = match expand_globs_with(expanded, glob_options) {
        Ok(v) => v,
        Err(msg) => {
            state.last_status = 2;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse error: {msg}"),
            ));
        }
    };
    trace_tokens(state, "globbed tokens", &expanded);

    if expanded.is_empty() {
        return Ok(());
    }

    let segments = match split_sequence(expanded) {
        Ok(v) => v,
        Err(msg) => {
            state.last_status = 2;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse error: {msg}"),
            ));
        }
    };

    for segment in segments {
        if state.return_requested.is_some() {
            break;
        }
        let should_run = match segment.op {
            SeqOp::Always => true,
            SeqOp::And => state.last_status == 0,
            SeqOp::Or => state.last_status != 0,
        };
        if should_run {
            execute_segment(state, segment.tokens, &segment.display)?;
            if state.return_requested.is_some() {
                break;
            }
        }
    }

    Ok(())
}

pub(crate) fn execute_function(
    state: &mut ShellState,
    func_tokens: Vec<String>,
    args: &[String],
) -> io::Result<()> {
    state.push_local_scope();
    state.push_function_scope();
    state.push_positional(args.to_vec());
    let glob_options = GlobOptions {
        extglob: state.extglob,
        nullglob: state.nullglob,
        failglob: state.failglob,
        dotglob: state.dotglob,
        nocaseglob: state.nocaseglob,
        dirspell: state.dirspell,
    };
    let positional = state.current_positional().to_vec();
    let ctx = build_expansion_context(
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        state.assoc_arrays.clone(),
        state.builtin_enabled.clone(),
        glob_options,
        &positional,
        true,
    );
    let result = (|| {
    let expanded = match expand_tokens(func_tokens, &ctx) {
        Ok(v) => v,
        Err(msg) => {
            state.last_status = 2;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                    format!("parse error: {msg}"),
                ));
            }
        };
    trace_tokens(state, "function expanded tokens", &expanded);

    if expanded.is_empty() {
        return Ok(());
    }

    let ProcessSubstResult { tokens: expanded, keep_fds } = apply_process_subst(
        expanded,
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        state.assoc_arrays.clone(),
        state.builtin_enabled.clone(),
        glob_options,
        true,
    )?;
    let _fd_guard = FdGuard(keep_fds);

    let expanded = match expand_globs_with(expanded, glob_options) {
        Ok(v) => v,
        Err(msg) => {
            state.last_status = 2;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse error: {msg}"),
                ));
            }
        };
        trace_tokens(state, "function globbed tokens", &expanded);

        if expanded.is_empty() {
            return Ok(());
        }

        let segments = match split_sequence(expanded) {
            Ok(v) => v,
            Err(msg) => {
                state.last_status = 2;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parse error: {msg}"),
                ));
            }
        };

        for segment in segments {
            if state.return_requested.is_some() {
                break;
            }
            let should_run = match segment.op {
                SeqOp::Always => true,
                SeqOp::And => state.last_status == 0,
                SeqOp::Or => state.last_status != 0,
            };
            if should_run {
                execute_segment(state, segment.tokens, &segment.display)?;
                if state.return_requested.is_some() {
                    break;
                }
            }
        }

        Ok(())
    })();
    if let Some(code) = state.return_requested.take() {
        state.last_status = code;
    }
    if let Err(err) = run_return_trap(state) {
        eprintln!("{err}");
    }
    state.pop_positional();
    state.pop_function_scope();
    state.pop_local_scope();
    result
}

pub(crate) fn is_function_def_start(tokens: &[String]) -> bool {
    if tokens.len() >= 2 && tokens[0] == "function" {
        return is_valid_var_name(&tokens[1]);
    }
    if tokens.len() >= 3 && tokens[1] == "()" {
        return is_valid_var_name(&tokens[0]);
    }
    if tokens.len() >= 2 && tokens[0] == "function" {
        return is_valid_var_name(&tokens[1]) && tokens.contains(&"{".to_string());
    }
    false
}

pub(crate) fn define_function(state: &mut ShellState, tokens: Vec<String>) -> io::Result<()> {
    let (name, body_tokens) = parse_function_tokens(tokens)?;
    state.functions.insert(name, body_tokens);
    state.last_status = 0;
    Ok(())
}

fn parse_function_tokens(tokens: Vec<String>) -> io::Result<(String, Vec<String>)> {
    if tokens.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "function missing",
        ));
    }
    let name = if tokens[0] == "function" {
        tokens
            .get(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "function name missing"))?
            .to_string()
    } else if tokens[1] == "()" {
        tokens[0].to_string()
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "function missing",
        ));
    };
    let brace_pos = tokens
        .iter()
        .position(|t| t == "{")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "function missing {"))?;
    let mut depth = 0i32;
    let mut end_pos = None;
    for (idx, tok) in tokens.iter().enumerate().skip(brace_pos) {
        let t = token_str(tok);
        if t == "{" {
            depth += 1;
        } else if t == "}" {
            depth -= 1;
            if depth == 0 {
                end_pos = Some(idx);
                break;
            }
        }
    }
    let end_pos =
        end_pos.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "function missing }"))?;
    let body = tokens[brace_pos + 1..end_pos].to_vec();
    Ok((name, body))
}

use nix::unistd::isatty;
use signal_hook::consts::signal::SIGCHLD;
use signal_hook::flag;
use std::env;
use std::sync::Arc;

mod builtins;
mod colors;
mod completion;
mod completions;
mod config;
mod error;
mod expansion_runner;
mod execution;
mod expansion;
mod arithmetic;
mod heredoc;
mod io_helpers;
mod job_control;
mod parse;
mod process_subst;
mod prompt;
mod repl;
mod signals;
mod utils;

pub(crate) use expansion_runner::build_expansion_context;
pub(crate) use repl::{execute_segment, run_return_trap, trace_tokens, ShellState};

use repl::{init_state, run_once};
use signals::{init_session, install_signal_handlers};

use parse::{parse_sandbox_value, SandboxDirective};

fn main() {
    init_logging();
    let mut trace = false;
    let mut sandbox_override: Option<SandboxDirective> = None;
    for arg in env::args().skip(1) {
        if arg == "-x" {
            trace = true;
        } else if arg == "--sandbox" {
            sandbox_override = Some(SandboxDirective::Enable);
        } else if arg == "--no-sandbox" {
            sandbox_override = Some(SandboxDirective::Disable);
        } else if let Some(value) = arg.strip_prefix("--sandbox=") {
            match parse_sandbox_value(value) {
                Ok(directive) => sandbox_override = Some(directive),
                Err(err) => {
                    eprintln!("error: {err}");
                    return;
                }
            }
        }
    }
    let interactive = isatty(libc::STDIN_FILENO).unwrap_or(false);
    if let Err(err) = install_signal_handlers() {
        eprintln!("error: {err}");
        return;
    }
    let shell_pgid = match init_session(interactive) {
        Ok(pgid) => pgid,
        Err(err) => {
            eprintln!("error: {err}");
            return;
        }
    };
    let mut state = match init_state(trace, interactive, shell_pgid, sandbox_override) {
        Ok(state) => state,
        Err(err) => {
            eprintln!("error: {err}");
            return;
        }
    };
    if let Err(err) = flag::register(SIGCHLD, Arc::clone(&state.sigchld_flag)) {
        eprintln!("error: {err}");
        return;
    }

    loop {
        if let Err(err) = run_once(&mut state) {
            eprintln!("error: {err}");
        }
    }
}

fn init_logging() {
    let env = env_logger::Env::default().filter_or("MINISHELL_LOG", "info");
    let _ = env_logger::Builder::from_env(env)
        .format_timestamp_millis()
        .try_init();
}

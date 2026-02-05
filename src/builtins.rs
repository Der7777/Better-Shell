mod config_cmds;
mod control_flow;
mod job_cmds;
mod scripting;

pub(crate) use scripting::execute_function;

use std::fmt::Write;
use std::io::{self, Read};

use crate::completions::suggest_command;
use crate::error::{ErrorKind, ShellError};
use crate::execution::{
    build_command, command_stdin_reader, run_command_in_foreground, sandbox_options_for_command,
    status_from_error, write_command_output, CaptureResult,
};
use crate::job_control::{add_job_with_status, list_jobs, JobStatus, WaitOutcome};
use crate::parse::CommandSpec;
use crate::ShellState;

use config_cmds::{
    handle_abbr, handle_complete, handle_fish_config, handle_history, handle_set_color,
    handle_source,
};
use control_flow::{
    execute_case, execute_for, execute_if, execute_while, is_case_start, is_for_start, is_if_start,
    is_while_start, read_compound_tokens, CompoundKind,
};
use job_cmds::{handle_bg, handle_fg};
use scripting::{define_function, execute_script_tokens, is_function_def_start};

pub fn is_builtin(cmd: Option<&str>) -> bool {
    matches!(
        cmd,
        Some(
            "exit"
                | "cd"
                | "pwd"
                | "jobs"
                | "fg"
                | "bg"
                | "help"
                | "echo"
                | "true"
                | "false"
                | "abbr"
                | "complete"
                | "set_color"
                | "fish_config"
                | "source"
                | "history"
        )
    )
}

pub fn try_execute_compound(
    state: &mut ShellState,
    tokens: &[String],
    display: &str,
) -> io::Result<Option<bool>> {
    if is_if_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::If)?;
        execute_if(state, tokens, display)?;
        return Ok(Some(true));
    }
    if is_while_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::While)?;
        execute_while(state, tokens, display)?;
        return Ok(Some(true));
    }
    if is_for_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::For)?;
        execute_for(state, tokens, display)?;
        return Ok(Some(true));
    }
    if is_case_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::Case)?;
        execute_case(state, tokens, display)?;
        return Ok(Some(true));
    }
    if is_function_def_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::Function)?;
        define_function(state, tokens)?;
        return Ok(Some(true));
    }
    Ok(Some(false))
}

pub fn execute_builtin(state: &mut ShellState, cmd: &CommandSpec, display: &str) -> io::Result<()> {
    let args = &cmd.args;
    let name = args.first().map(String::as_str);
    if matches!(name, Some(name) if is_builtin(Some(name)) || name == "set") {
        let mut stdin = command_stdin_reader(cmd, None)?;
        let result = execute_builtin_capture(state, cmd, display, stdin.as_deref_mut())?;
        write_command_output(cmd, &result.output)?;
        state.last_status = result.status_code;
        return Ok(());
    }

    match name {
        Some(cmd_name) => {
            if let Some(body) = state.functions.get(cmd_name) {
                let body_tokens = body.clone();
                execute_script_tokens(state, body_tokens)?;
                return Ok(());
            }
            let mut command = build_command(cmd)?;
            let sandbox = sandbox_options_for_command(cmd, &state.sandbox, state.trace);
            match run_command_in_foreground(
                &mut command,
                &state.fg_pgid,
                state.shell_pgid,
                state.trace,
                sandbox,
            ) {
                Ok(result) => {
                    if matches!(result.outcome, WaitOutcome::Stopped) {
                        let job_id = add_job_with_status(
                            &mut state.jobs,
                            &mut state.next_job_id,
                            result.pgid,
                            result.last_pid,
                            1,
                            display,
                            JobStatus::Stopped,
                        );
                        println!("[{job_id}] Stopped {display}");
                        state.last_status = 128 + libc::SIGTSTP;
                    } else {
                        let last = result.status_code.unwrap_or(0);
                        let pipefail = result.pipefail_status.unwrap_or(last);
                        state.last_status = if state.pipefail { pipefail } else { last };
                    }
                }
                Err(err) => {
                    eprintln!("{err}");
                    if err.kind() == io::ErrorKind::NotFound {
                        if let Some(suggestion) = suggest_command(
                            &cmd.args[0],
                            &state.aliases,
                            &state.functions,
                            &state.abbreviations,
                            &state.completions,
                        ) {
                            if suggestion != cmd.args[0] {
                                eprintln!("Command not found—did you mean '{suggestion}'?");
                            }
                        }
                    }
                    state.last_status = status_from_error(&err);
                }
            }
        }
        None => {
            state.last_status = 0;
        }
    }

    Ok(())
}

pub fn execute_builtin_capture(
    state: &mut ShellState,
    cmd: &CommandSpec,
    display: &str,
    mut stdin: Option<&mut dyn Read>,
) -> io::Result<CaptureResult> {
    let mut output = String::new();
    let status = execute_builtin_with_output(state, cmd, display, stdin, &mut output)?;
    Ok(CaptureResult {
        output,
        status_code: status,
    })
}

fn execute_builtin_with_output(
    state: &mut ShellState,
    cmd: &CommandSpec,
    _display: &str,
    _stdin: Option<&mut dyn Read>,
    output: &mut String,
) -> io::Result<i32> {
    let args = &cmd.args;
    let name = args.first().map(String::as_str);
    match name {
        Some("exit") => {
            let code = args
                .get(1)
                .and_then(|s| s.parse::<i32>().ok())
                .unwrap_or(state.last_status);
            std::process::exit(code);
        }
        Some("cd") => {
            let target = args.get(1).map(String::as_str).unwrap_or("~");
            let expanded = if let Some(rest) = target.strip_prefix('~') {
                if let Ok(home) = std::env::var("HOME") {
                    format!("{home}{rest}")
                } else {
                    target.to_string()
                }
            } else {
                target.to_string()
            };
            if let Err(err) = std::env::set_current_dir(&expanded) {
                eprintln!("cd: {err}");
                state.last_status = 1;
            } else {
                state.last_status = 0;
            }
        }
        Some("pwd") => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
            let _ = writeln!(output, "{}", cwd.display());
            state.last_status = 0;
        }
        Some("jobs") => {
            list_jobs(&state.jobs, output);
            state.last_status = 0;
        }
        Some("fg") => {
            handle_fg(state, args, output)?;
        }
        Some("bg") => {
            handle_bg(state, args, output)?;
        }
        Some("help") => {
            if args.len() > 1 {
                let topic = &args[1];
                match std::process::Command::new("man").arg(topic).output() {
                    Ok(result) => {
                        state.last_status = if result.status.success() { 0 } else { 1 };
                        output.push_str(&String::from_utf8_lossy(&result.stdout));
                    }
                    Err(err) if err.kind() == io::ErrorKind::NotFound => {
                        eprintln!("help: man not found");
                        state.last_status = 127;
                    }
                    Err(err) => {
                        eprintln!("help: {err}");
                        state.last_status = 1;
                    }
                }
                return Ok(state.last_status);
            }
            let _ = writeln!(
                output,
                "Built-ins: cd [dir], pwd, jobs, fg [id], bg [id], help, exit [code], echo, true, false, abbr, complete"
            );
            let _ = writeln!(
                output,
                "External commands support pipes with |, background jobs with &, and redirection with <, >, >>, 2>, 2>>, 2>&1, &>, &>>, and <<<."
            );
            let _ = writeln!(output, "Config: ~/.minishellrc (aliases, env vars, prompt).");
            let _ = writeln!(
                output,
                "Abbreviations: ~/.minishell_abbr (or abbr lines in ~/.minishellrc)."
            );
            let _ = writeln!(
                output,
                "Sandbox: prefix commands with sandbox=yes/no or use --sandbox/--no-sandbox."
            );
            let _ = writeln!(output, "Completion: commands, filenames, $vars, %jobs.");
            let _ = writeln!(
                output,
                "Completions: ~/.minishell_completions and ~/.config/fish/completions/."
            );
            let _ = writeln!(output, "Prompt themes: fish (default), classic, minimal.");
            let _ = writeln!(
                output,
                "Prompt function: set prompt_function = name in config."
            );
            let _ = writeln!(output, "Colors: set_color key value (or ~/.minishell_colors).");
            let _ = writeln!(
                output,
                "Expansion order: quotes/escapes -> command substitution -> vars/tilde -> glob (no IFS splitting)."
            );
            state.last_status = 0;
        }
        Some("abbr") => {
            handle_abbr(state, args, output)?;
        }
        Some("complete") => {
            handle_complete(state, args, output)?;
        }
        Some("set_color") => {
            handle_set_color(state, args, output)?;
        }
        Some("fish_config") => {
            handle_fish_config(state, output)?;
        }
        Some("source") => {
            handle_source(state, args, output)?;
        }
        Some("history") => {
            handle_history(state, args, output)?;
        }
        Some("echo") => {
            let line = args[1..].join(" ");
            let _ = writeln!(output, "{line}");
            state.last_status = 0;
        }
        Some("true") => {
            state.last_status = 0;
        }
        Some("false") => {
            state.last_status = 1;
        }
        Some("set") => {
            if args.len() >= 3 && args[1] == "-o" && args[2] == "pipefail" {
                state.pipefail = true;
                state.last_status = 0;
            } else if args.len() >= 3 && args[1] == "+o" && args[2] == "pipefail" {
                state.pipefail = false;
                state.last_status = 0;
            } else if args.len() >= 2 && args[1] == "-x" {
                state.trace = true;
                state.last_status = 0;
            } else if args.len() >= 2 && args[1] == "+x" {
                state.trace = false;
                state.last_status = 0;
            } else if args.len() == 1 {
                let _ = writeln!(
                    output,
                    "pipefail\t{}",
                    if state.pipefail { "on" } else { "off" }
                );
                let _ = writeln!(
                    output,
                    "xtrace\t{}",
                    if state.trace { "on" } else { "off" }
                );
                state.last_status = 0;
            } else {
                eprintln!("set: unsupported option");
                state.last_status = 2;
            }
        }
        Some(other) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{other}: not a builtin"),
            ));
        }
        None => {
            state.last_status = 0;
        }
    }

    Ok(state.last_status)
}

pub fn execute_builtin_substitution(pipeline: &[CommandSpec]) -> Result<(String, i32), String> {
    if pipeline.len() != 1 {
        return Err("pipes only work with external commands".to_string());
    }
    let args = &pipeline[0].args;
    match args.first().map(String::as_str) {
        Some("pwd") => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
            Ok((cwd.display().to_string(), 0))
        }
        Some("help") => Ok((
            "Built-ins: cd [dir], pwd, jobs, fg [id], bg [id], help, exit [code], echo, true, false, abbr, complete"
                .to_string(),
            0,
        )),
        Some("cd") => Err(ShellError::new(
            ErrorKind::Execution,
            "cd is not supported in command substitution".to_string(),
        )
        .with_context("Use '$(pwd)' to get the current directory")
        .into()),
        Some("exit") => Err(ShellError::new(
            ErrorKind::Execution,
            "exit is not supported in command substitution".to_string(),
        )
        .with_context("exit is only allowed at the top level, not in subshells")
        .into()),
        Some("abbr") => Err(ShellError::new(
            ErrorKind::Execution,
            "abbr is not supported in command substitution".to_string(),
        )
        .with_context("Abbreviations must be defined in the main shell, not in subshells")
        .into()),
        Some("complete") => Err(ShellError::new(
            ErrorKind::Execution,
            "complete is not supported in command substitution".to_string(),
        )
        .with_context("Completions must be defined in the main shell, not in subshells")
        .into()),
        Some("jobs") | Some("fg") | Some("bg") => {
            Err(ShellError::new(
                ErrorKind::Execution,
                "job control is not supported in command substitution".to_string(),
            )
            .with_context("Jobs exist only in the main shell; subshells have isolated process groups")
            .into())
        }
        _ => Err(ShellError::new(
            ErrorKind::Execution,
            "built-in commands are not supported in command substitution".to_string(),
        )
        .with_context("Only external commands can be used in $(...) substitution")
        .into()),
    }
}

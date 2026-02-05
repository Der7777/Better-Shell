pub(crate) mod config_cmds;
mod control_flow;
mod job_cmds;
mod scripting;

pub(crate) use scripting::execute_function;
pub(crate) use config_cmds::load_assoc_arrays;

use std::fmt::Write;
use std::io::{self, Read};
use std::path::Path;
use std::{env, fs};

use rustyline::history::{History, SearchDirection};

use crate::completions::suggest_command;
use crate::error::{ErrorKind, ShellError};
use crate::execution::{
    build_command, command_stdin_reader, run_command_in_foreground, sandbox_options_for_command,
    status_from_error, write_command_output, CaptureResult,
};
use crate::job_control::{add_job_with_status, list_jobs, parse_job_id, take_job, JobStatus, WaitOutcome};
use rustyline::{Cmd, KeyCode, KeyEvent, Modifiers, Movement};
use crate::parse::{parse_line_lenient, CommandSpec};
use crate::execute_segment;
use crate::ShellState;

use config_cmds::{
    handle_abbr, handle_complete, handle_fish_config, handle_history, handle_set_color,
    handle_source, save_assoc_arrays,
};
use control_flow::{
    execute_brace_group, execute_case, execute_for, execute_if, execute_select, execute_while,
    execute_coproc, is_brace_group_start, is_case_start, is_coproc_start, is_for_start,
    is_if_start, is_select_start, is_while_start, read_compound_tokens, CompoundKind,
};
use job_cmds::{handle_bg, handle_fg};
use scripting::{define_function, execute_script_tokens, is_function_def_start};

const BUILTINS: &[&str] = &[
    "exit",
    "cd",
    "pwd",
    "jobs",
    "fg",
    "bg",
    "help",
    "hash",
    "echo",
    "true",
    "false",
    "unset",
    "local",
    "declare",
    "readonly",
    "shift",
    "eval",
    "alias",
    "unalias",
    "disown",
    "bind",
    "getopts",
    "type",
    "fc",
    "abbr",
    "complete",
    "set_color",
    "fish_config",
    "source",
    "history",
    "set",
    "enable",
    "shopt",
    "trap",
];

pub fn builtin_names() -> &'static [&'static str] {
    BUILTINS
}

pub fn is_builtin(cmd: Option<&str>) -> bool {
    cmd.is_some_and(|name| BUILTINS.contains(&name))
}

pub fn is_builtin_enabled_map(
    enabled: &std::collections::HashMap<String, bool>,
    cmd: Option<&str>,
) -> bool {
    let Some(name) = cmd else {
        return false;
    };
    if !is_builtin(Some(name)) {
        return false;
    }
    enabled.get(name).copied().unwrap_or(false)
}

pub fn try_execute_compound(
    state: &mut ShellState,
    tokens: &[String],
    display: &str,
) -> io::Result<Option<bool>> {
    if is_brace_group_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::Brace)?;
        execute_brace_group(state, tokens, display)?;
        return Ok(Some(true));
    }
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
    if is_select_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::Select)?;
        execute_select(state, tokens, display)?;
        return Ok(Some(true));
    }
    if is_case_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::Case)?;
        execute_case(state, tokens, display)?;
        return Ok(Some(true));
    }
    if is_coproc_start(tokens) {
        let tokens = read_compound_tokens(state, tokens.to_vec(), CompoundKind::Coproc)?;
        execute_coproc(state, tokens, display)?;
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
    if matches!(name, Some(name) if is_builtin(Some(name)) && state.is_builtin_enabled(name)) {
        let stdin = command_stdin_reader(cmd, None)?;
        let result = execute_builtin_capture(state, cmd, display, stdin)?;
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
    mut stdin: Option<Box<dyn Read>>,
) -> io::Result<CaptureResult> {
    let mut output = String::new();
    let status = execute_builtin_with_output(state, cmd, display, stdin.take(), &mut output)?;
    Ok(CaptureResult {
        output,
        status_code: status,
    })
}

fn execute_builtin_with_output(
    state: &mut ShellState,
    cmd: &CommandSpec,
    _display: &str,
    _stdin: Option<Box<dyn Read>>,
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
                "Built-ins: cd [dir], pwd, jobs, fg [id], bg [id], help, exit [code], hash, echo, true, false, unset, local, declare, readonly, shift, eval, alias, unalias, disown, bind, getopts, type, fc, abbr, complete, enable, shopt, trap"
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
                "Expansion order: quotes/escapes -> command substitution -> vars/tilde -> IFS splitting -> glob."
            );
            state.last_status = 0;
        }
        Some("unset") => {
            if args.len() < 2 {
                state.last_status = 0;
                return Ok(state.last_status);
            }
            let mut failed = false;
            for name in &args[1..] {
                if let Some((arr, idx)) = parse_array_unset(name) {
                    state.unset_array_elem(&arr, idx);
                    continue;
                }
                if let Some((arr, key)) = parse_assoc_unset(name) {
                    state.unset_assoc_elem(&arr, &key);
                    continue;
                }
                if !crate::utils::is_valid_var_name(name) {
                    if let Some(arr_name) = name.strip_suffix("[]") {
                        if crate::utils::is_valid_var_name(arr_name) {
                            state.unset_array(arr_name);
                            continue;
                        }
                    }
                    eprintln!("unset: invalid variable name '{name}'");
                    failed = true;
                    continue;
                }
                if state.readonly_vars.contains(name) {
                    eprintln!("unset: {name}: readonly variable");
                    failed = true;
                    continue;
                }
                state.unset_var(name);
            }
            state.last_status = if failed { 1 } else { 0 };
        }
        Some("local") => {
            if args.len() < 2 {
                state.last_status = 0;
                return Ok(state.last_status);
            }
            let mut failed = false;
            for entry in &args[1..] {
                let (name, value) = match entry.split_once('=') {
                    Some((name, value)) => (name, value),
                    None => (entry.as_str(), ""),
                };
                if !crate::utils::is_valid_var_name(name) {
                    eprintln!("local: invalid variable name '{name}'");
                    failed = true;
                    continue;
                }
                if let Err(err) = state.set_local_var(name, value) {
                    eprintln!("{err}");
                    failed = true;
                }
            }
            state.last_status = if failed { 1 } else { 0 };
        }
        Some("getopts") => {
            state.last_status = handle_getopts(args)?;
        }
        Some("type") => {
            handle_type(state, args, output)?;
        }
        Some("fc") => {
            handle_fc(state, args, output)?;
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
        Some("hash") => {
            handle_hash(state, args, output)?;
        }
        Some("declare") => {
            handle_declare(state, args)?;
        }
        Some("readonly") => {
            handle_readonly(state, args, output)?;
        }
        Some("shift") => {
            handle_shift(state, args)?;
        }
        Some("eval") => {
            handle_eval(state, args)?;
        }
        Some("alias") => {
            handle_alias(state, args, output)?;
        }
        Some("unalias") => {
            handle_unalias(state, args)?;
        }
        Some("disown") => {
            handle_disown(state, args)?;
        }
        Some("bind") => {
            handle_bind(state, args, output)?;
        }
        Some("enable") => {
            handle_enable(state, args, output)?;
        }
        Some("shopt") => {
            handle_shopt(state, args, output)?;
        }
        Some("trap") => {
            handle_trap(state, args, output)?;
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
            } else if args.len() >= 3 && args[1] == "-o" && args[2] == "functrace" {
                state.functrace = true;
                state.last_status = 0;
            } else if args.len() >= 3 && args[1] == "+o" && args[2] == "functrace" {
                state.functrace = false;
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
                    "functrace\t{}",
                    if state.functrace { "on" } else { "off" }
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

#[allow(dead_code)]
pub fn execute_builtin_substitution(pipeline: &[CommandSpec]) -> Result<(String, i32), String> {
    if pipeline.len() != 1 {
        return Err("pipes only work with external commands".to_string());
    }
    let result = execute_builtin_substitution_capture(&pipeline[0], None)?;
    Ok((result.output, result.status_code))
}

pub fn execute_builtin_substitution_capture(
    cmd: &CommandSpec,
    _stdin: Option<Box<dyn Read>>,
) -> Result<CaptureResult, String> {
    let args = &cmd.args;
    match args.first().map(String::as_str) {
        Some("pwd") => {
            let cwd = std::env::current_dir().unwrap_or_else(|_| "/".into());
            Ok(CaptureResult {
                output: cwd.display().to_string(),
                status_code: 0,
            })
        }
        Some("help") => Ok(CaptureResult {
            output: "Built-ins: cd [dir], pwd, jobs, fg [id], bg [id], help, exit [code], hash, echo, true, false, unset, local, declare, readonly, shift, eval, alias, unalias, disown, bind, getopts, type, fc, abbr, complete, enable, shopt, trap"
                .to_string(),
            status_code: 0,
        }),
        Some("echo") => Ok(CaptureResult {
            output: format!("{}\n", args[1..].join(" ")),
            status_code: 0,
        }),
        Some("type") => execute_type_substitution(args),
        Some("true") => Ok(CaptureResult {
            output: String::new(),
            status_code: 0,
        }),
        Some("false") => Ok(CaptureResult {
            output: String::new(),
            status_code: 1,
        }),
        Some("cd") => Err(ShellError::new(
            ErrorKind::Execution,
            "cd is not supported in command substitution".to_string(),
        )
        .with_context("Use '$(pwd)' to get the current directory")
        .to_string()),
        Some("exit") => Err(ShellError::new(
            ErrorKind::Execution,
            "exit is not supported in command substitution".to_string(),
        )
        .with_context("exit is only allowed at the top level, not in subshells")
        .to_string()),
        Some("abbr") => Err(ShellError::new(
            ErrorKind::Execution,
            "abbr is not supported in command substitution".to_string(),
        )
        .with_context("Abbreviations must be defined in the main shell, not in subshells")
        .to_string()),
        Some("complete") => Err(ShellError::new(
            ErrorKind::Execution,
            "complete is not supported in command substitution".to_string(),
        )
        .with_context("Completions must be defined in the main shell, not in subshells")
        .to_string()),
        Some("jobs") | Some("fg") | Some("bg") => {
            Err(ShellError::new(
                ErrorKind::Execution,
                "job control is not supported in command substitution".to_string(),
            )
            .with_context("Jobs exist only in the main shell; subshells have isolated process groups")
            .to_string())
        }
        _ => Err(ShellError::new(
            ErrorKind::Execution,
            "built-in commands are not supported in command substitution".to_string(),
        )
        .with_context("Only external commands can be used in $(...) substitution")
        .to_string()),
    }
}

fn handle_getopts(args: &[String]) -> io::Result<i32> {
    if args.len() < 3 {
        eprintln!("usage: getopts optstring name [args...]");
        return Ok(2);
    }
    let optstring = &args[1];
    let name = &args[2];
    let optargs = &args[3..];
    let mut optind = env::var("OPTIND")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);
    if optind == 0 {
        optind = 1;
    }
    let mut optpos = env::var("OPTPOS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1);

    let mut current = if optind > optargs.len() {
        None
    } else {
        Some(optargs[optind - 1].as_str())
    };

    if let Some(arg) = current {
        if arg == "--" {
            optind += 1;
            env::set_var("OPTIND", optind.to_string());
            env::set_var("OPTPOS", "1");
            env::set_var(name, "?");
            return Ok(1);
        }
    }

    while let Some(arg) = current {
        if !arg.starts_with('-') || arg == "-" {
            env::set_var(name, "?");
            return Ok(1);
        }
        let chars: Vec<char> = arg[1..].chars().collect();
        if optpos > chars.len() {
            optind += 1;
            optpos = 1;
            current = if optind > optargs.len() {
                None
            } else {
                Some(optargs[optind - 1].as_str())
            };
            continue;
        }
        let opt = chars[optpos - 1];
        optpos += 1;
        let opt_entry = optstring.find(opt);
        let needs_arg = opt_entry
            .and_then(|idx| optstring.as_bytes().get(idx + 1))
            .map(|b| *b == b':')
            .unwrap_or(false);
        if opt_entry.is_none() || opt == ':' {
            env::set_var(name, if optstring.starts_with(':') { ":" } else { "?" });
            env::set_var("OPTARG", opt.to_string());
            env::set_var("OPTIND", optind.to_string());
            env::set_var("OPTPOS", optpos.to_string());
            return Ok(1);
        }
        if needs_arg {
            if optpos <= chars.len() {
                let arg_val: String = chars[optpos - 1..].iter().collect();
                optind += 1;
                optpos = 1;
                env::set_var("OPTARG", arg_val);
            } else if optind < optargs.len() {
                optind += 1;
                let arg_val = optargs[optind - 1].clone();
                optind += 1;
                optpos = 1;
                env::set_var("OPTARG", arg_val);
            } else {
                env::set_var(name, if optstring.starts_with(':') { ":" } else { "?" });
                env::set_var("OPTARG", opt.to_string());
                env::set_var("OPTIND", optind.to_string());
                env::set_var("OPTPOS", optpos.to_string());
                return Ok(1);
            }
        } else {
            env::remove_var("OPTARG");
        }
        env::set_var(name, opt.to_string());
        env::set_var("OPTIND", optind.to_string());
        env::set_var("OPTPOS", optpos.to_string());
        return Ok(0);
    }

    env::set_var(name, "?");
    Ok(1)
}

fn handle_type(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("usage: type [-a|-t] name...");
        state.last_status = 2;
        return Ok(());
    }
    let mut show_all = false;
    let mut type_only = false;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-a" => show_all = true,
            "-t" => type_only = true,
            "--" => {
                idx += 1;
                break;
            }
            _ if args[idx].starts_with('-') => {
                eprintln!("type: unsupported option '{}'", args[idx]);
                state.last_status = 2;
                return Ok(());
            }
            _ => break,
        }
        idx += 1;
    }
    if idx >= args.len() {
        state.last_status = 2;
        return Ok(());
    }
    let mut ok = true;
    for name in &args[idx..] {
        let mut entries = Vec::new();
        if let Some(value) = state.aliases.get(name) {
            entries.push(("alias", format!("{}={}", name, value.join(" "))));
        }
        if state.functions.contains_key(name) {
            entries.push(("function", name.to_string()));
        }
        if is_builtin(Some(name)) {
            entries.push(("builtin", name.to_string()));
        }
        if let Some(path) = find_in_path(name) {
            entries.push(("file", path));
        }
        if entries.is_empty() {
            ok = false;
            eprintln!("type: {name} not found");
            continue;
        }
        if !show_all {
            entries.truncate(1);
        }
        for (kind, detail) in entries {
            if type_only {
                let _ = writeln!(output, "{kind}");
            } else {
                match kind {
                    "alias" => {
                        let _ = writeln!(output, "{name} is an alias for {detail}");
                    }
                    "function" => {
                        let _ = writeln!(output, "{name} is a shell function");
                    }
                    "builtin" => {
                        let _ = writeln!(output, "{name} is a shell builtin");
                    }
                    "file" => {
                        let _ = writeln!(output, "{name} is {detail}");
                    }
                    _ => {
                        let _ = writeln!(output, "{name} is {detail}");
                    }
                }
            }
        }
    }
    state.last_status = if ok { 0 } else { 1 };
    Ok(())
}

fn handle_fc(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    let mut _list_only = false;
    let mut no_numbers = false;
    let mut reverse = false;
    let mut reexecute = false;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-l" => _list_only = true,
            "-n" => no_numbers = true,
            "-r" => reverse = true,
            "-s" => reexecute = true,
            "--" => {
                idx += 1;
                break;
            }
            _ if args[idx].starts_with('-') => {
                eprintln!("fc: unsupported option '{}'", args[idx]);
                state.last_status = 2;
                return Ok(());
            }
            _ => break,
        }
        idx += 1;
    }

    let history_len = state.editor.history().len();
    if reexecute {
        if history_len == 0 {
            eprintln!("fc: history is empty");
            state.last_status = 1;
            return Ok(());
        }
        let mut entries: Vec<String> = state
            .editor
            .history()
            .iter()
            .map(|s| s.to_string())
            .collect();
        if let Some(last) = entries.last() {
            if last == args.join(" ").as_str() && entries.len() > 1 {
                entries.pop();
            }
        }
        let command = if idx < args.len() {
            let prefix = &args[idx];
            let mut found = None;
            for entry in entries.iter().rev() {
                if (*entry).starts_with(prefix) {
                    found = Some(entry.clone());
                    break;
                }
            }
            match found {
                Some(cmd) => cmd,
                None => {
                    eprintln!("fc: event not found: {prefix}");
                    state.last_status = 1;
                    return Ok(());
                }
            }
        } else {
            entries.last().cloned().unwrap_or_default()
        };
        let _ = writeln!(output, "{command}");
        let tokens = match parse_line_lenient(&command) {
            Ok(tokens) => tokens,
            Err(msg) => {
                eprintln!("fc: parse error: {msg}");
                state.last_status = 2;
                return Ok(());
            }
        };
        execute_segment(state, tokens, &command)?;
        return Ok(());
    }

    let mut start = history_len.saturating_sub(16);
    let mut end = history_len.saturating_sub(1);
    if idx < args.len() {
        if let Ok(val) = args[idx].parse::<isize>() {
            start = resolve_history_index(history_len, val);
        } else {
            eprintln!("fc: invalid history index");
            state.last_status = 2;
            return Ok(());
        }
        idx += 1;
    }
    if idx < args.len() {
        if let Ok(val) = args[idx].parse::<isize>() {
            end = resolve_history_index(history_len, val);
        } else {
            eprintln!("fc: invalid history index");
            state.last_status = 2;
            return Ok(());
        }
    }

    if start > end {
        std::mem::swap(&mut start, &mut end);
    }

    let range: Vec<usize> = (start..=end).collect();
    let iter: Box<dyn Iterator<Item = usize>> = if reverse {
        Box::new(range.into_iter().rev())
    } else {
        Box::new(range.into_iter())
    };
    for i in iter {
        if let Ok(Some(entry)) = state.editor.history().get(i, SearchDirection::Forward) {
            if no_numbers {
                let _ = writeln!(output, "{}", entry.entry);
            } else {
                let _ = writeln!(output, "{} {}", entry.idx, entry.entry);
            }
        }
    }
    state.last_status = 0;
    Ok(())
}

fn resolve_history_index(history_len: usize, value: isize) -> usize {
    if history_len == 0 {
        return 0;
    }
    if value < 0 {
        let idx = history_len as isize + value;
        if idx < 0 {
            0
        } else {
            idx as usize
        }
    } else {
        let idx = value as usize;
        if idx >= history_len {
            history_len.saturating_sub(1)
        } else {
            idx
        }
    }
}

pub(crate) fn find_in_path(name: &str) -> Option<String> {
    if name.contains('/') {
        let path = Path::new(name);
        if path.exists() {
            return Some(name.to_string());
        }
        return None;
    }
    let path_var = env::var("PATH").ok()?;
    for part in path_var.split(':') {
        if part.is_empty() {
            continue;
        }
        let candidate = Path::new(part).join(name);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(path) {
            return meta.is_file() && (meta.permissions().mode() & 0o111 != 0);
        }
        false
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn parse_array_unset(input: &str) -> Option<(String, usize)> {
    let open = input.find('[')?;
    if !input.ends_with(']') {
        return None;
    }
    let name = input[..open].to_string();
    let idx_str = &input[open + 1..input.len() - 1];
    let idx = idx_str.parse::<usize>().ok()?;
    Some((name, idx))
}

fn parse_assoc_unset(input: &str) -> Option<(String, String)> {
    let open = input.find('[')?;
    if !input.ends_with(']') {
        return None;
    }
    let name = input[..open].to_string();
    let key = &input[open + 1..input.len() - 1];
    if key.is_empty() {
        return None;
    }
    if key.parse::<usize>().is_ok() {
        return None;
    }
    Some((name, key.to_string()))
}

fn handle_declare(state: &mut ShellState, args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("declare: missing option");
        state.last_status = 2;
        return Ok(());
    }
    if args[1] != "-A" {
        eprintln!("declare: only -A is supported");
        state.last_status = 2;
        return Ok(());
    }
    if args.len() == 2 {
        eprintln!("declare: missing name");
        state.last_status = 2;
        return Ok(());
    }

    let rest = &args[2..];
    if let Some((name, values)) = parse_assoc_array_literal(rest) {
        if !crate::utils::is_valid_var_name(&name) {
            eprintln!("declare: invalid name '{name}'");
            state.last_status = 2;
            return Ok(());
        }
        state.set_assoc_array(&name, values);
        if let Err(err) = save_assoc_arrays(&state.assoc_arrays) {
            eprintln!("declare: failed to save arrays: {err}");
            state.last_status = 1;
            return Ok(());
        }
        state.last_status = 0;
        return Ok(());
    }

    let mut failed = false;
    for name in rest {
        if !crate::utils::is_valid_var_name(name) {
            eprintln!("declare: invalid name '{name}'");
            failed = true;
            continue;
        }
        state.assoc_arrays.entry(name.to_string()).or_default();
    }
    if let Err(err) = save_assoc_arrays(&state.assoc_arrays) {
        eprintln!("declare: failed to save arrays: {err}");
        state.last_status = 1;
        return Ok(());
    }
    state.last_status = if failed { 2 } else { 0 };
    Ok(())
}

fn handle_enable(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    let mut disable = false;
    let mut print = false;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-n" => disable = true,
            "-p" => print = true,
            "--" => {
                idx += 1;
                break;
            }
            _ if args[idx].starts_with('-') => {
                eprintln!("enable: unsupported option '{}'", args[idx]);
                state.last_status = 2;
                return Ok(());
            }
            _ => break,
        }
        idx += 1;
    }

    if args.len() == 1 {
        print = true;
    }

    if print {
        for name in builtin_names() {
            let enabled = state.builtin_enabled.get(*name).copied().unwrap_or(false);
            if enabled {
                let _ = writeln!(output, "enable {name}");
            } else {
                let _ = writeln!(output, "enable -n {name}");
            }
        }
        state.last_status = 0;
        return Ok(());
    }

    if idx >= args.len() {
        eprintln!("enable: missing builtin name");
        state.last_status = 2;
        return Ok(());
    }

    let mut failed = false;
    for name in &args[idx..] {
        if !is_builtin(Some(name)) {
            eprintln!("enable: not a builtin: {name}");
            failed = true;
            continue;
        }
        if name == "enable" && disable {
            eprintln!("enable: cannot disable 'enable'");
            failed = true;
            continue;
        }
        state
            .builtin_enabled
            .insert(name.to_string(), !disable);
    }
    state.last_status = if failed { 1 } else { 0 };
    Ok(())
}

fn handle_shopt(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    let mut set = None;
    let mut print = false;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-s" => set = Some(true),
            "-u" => set = Some(false),
            "-p" => print = true,
            "--" => {
                idx += 1;
                break;
            }
            _ if args[idx].starts_with('-') => {
                eprintln!("shopt: unsupported option '{}'", args[idx]);
                state.last_status = 2;
                return Ok(());
            }
            _ => break,
        }
        idx += 1;
    }

    if args.len() == 1 {
        print = true;
    }

    if print {
        let status = |value: bool| if value { "on" } else { "off" };
        let _ = writeln!(output, "extglob\t{}", status(state.extglob));
        let _ = writeln!(output, "nullglob\t{}", status(state.nullglob));
        let _ = writeln!(output, "failglob\t{}", status(state.failglob));
        let _ = writeln!(output, "dotglob\t{}", status(state.dotglob));
        let _ = writeln!(output, "nocaseglob\t{}", status(state.nocaseglob));
        let _ = writeln!(output, "dirspell\t{}", status(state.dirspell));
        state.last_status = 0;
        return Ok(());
    }

    if idx >= args.len() {
        eprintln!("shopt: missing option name");
        state.last_status = 2;
        return Ok(());
    }

    let mut failed = false;
    for name in &args[idx..] {
        match name.as_str() {
            "extglob" => {
                if let Some(value) = set {
                    state.extglob = value;
                } else {
                    state.extglob = true;
                }
            }
            "nullglob" => {
                if let Some(value) = set {
                    state.nullglob = value;
                } else {
                    state.nullglob = true;
                }
            }
            "failglob" => {
                if let Some(value) = set {
                    state.failglob = value;
                } else {
                    state.failglob = true;
                }
            }
            "dotglob" => {
                if let Some(value) = set {
                    state.dotglob = value;
                } else {
                    state.dotglob = true;
                }
            }
            "nocaseglob" => {
                if let Some(value) = set {
                    state.nocaseglob = value;
                } else {
                    state.nocaseglob = true;
                }
            }
            "dirspell" => {
                if let Some(value) = set {
                    state.dirspell = value;
                } else {
                    state.dirspell = true;
                }
            }
            _ => {
                eprintln!("shopt: unsupported option '{name}'");
                failed = true;
            }
        }
    }
    state.last_status = if failed { 1 } else { 0 };
    Ok(())
}

fn handle_trap(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    if args.len() == 1 || (args.len() == 2 && args[1] == "-p") {
        for (name, cmd) in state.traps.iter() {
            let _ = writeln!(output, "trap '{}' {}", cmd, name);
        }
        state.last_status = 0;
        return Ok(());
    }

    if args[1] == "-p" {
        if args.len() < 3 {
            state.last_status = 0;
            return Ok(());
        }
        for name in &args[2..] {
            if let Some(cmd) = state.traps.get(name) {
                let _ = writeln!(output, "trap '{}' {}", cmd, name);
            }
        }
        state.last_status = 0;
        return Ok(());
    }

    if args[1] == "-" {
        if args.len() < 3 {
            eprintln!("trap: missing signal");
            state.last_status = 2;
            return Ok(());
        }
        for name in &args[2..] {
            state.traps.remove(name);
        }
        state.last_status = 0;
        return Ok(());
    }

    if args.len() < 3 {
        eprintln!("trap: missing signal");
        state.last_status = 2;
        return Ok(());
    }

    let cmd = &args[1];
    for name in &args[2..] {
        match name.as_str() {
            "DEBUG" | "RETURN" => {
                state.traps.insert(name.to_string(), cmd.to_string());
            }
            _ => {
                eprintln!("trap: unsupported signal '{name}'");
                state.last_status = 2;
                return Ok(());
            }
        }
    }
    state.last_status = 0;
    Ok(())
}

fn handle_hash(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    let mut clear = false;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-r" => clear = true,
            "--" => {
                idx += 1;
                break;
            }
            _ if args[idx].starts_with('-') => {
                eprintln!("hash: unsupported option '{}'", args[idx]);
                state.last_status = 2;
                return Ok(());
            }
            _ => break,
        }
        idx += 1;
    }

    if clear {
        state.command_hash.clear();
        state.last_status = 0;
        return Ok(());
    }

    if idx >= args.len() {
        let mut entries: Vec<_> = state.command_hash.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        for (name, path) in entries {
            let _ = writeln!(output, "{name}={path}");
        }
        state.last_status = 0;
        return Ok(());
    }

    let mut failed = false;
    for name in &args[idx..] {
        if let Some(path) = find_in_path(name) {
            state.command_hash.insert(name.to_string(), path);
        } else {
            eprintln!("hash: {name}: not found");
            failed = true;
        }
    }
    state.last_status = if failed { 1 } else { 0 };
    Ok(())
}

fn handle_readonly(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    if args.len() == 1 || (args.len() == 2 && args[1] == "-p") {
        let mut entries: Vec<_> = state.readonly_vars.iter().collect();
        entries.sort();
        for name in entries {
            let _ = writeln!(output, "readonly {name}");
        }
        state.last_status = 0;
        return Ok(());
    }

    let mut idx = 1usize;
    if args[1] == "-p" {
        idx += 1;
    }
    let mut failed = false;
    for entry in &args[idx..] {
        let (name, value) = match entry.split_once('=') {
            Some((name, value)) => (name, Some(value)),
            None => (entry.as_str(), None),
        };
        if !crate::utils::is_valid_var_name(name) {
            eprintln!("readonly: invalid name '{name}'");
            failed = true;
            continue;
        }
        if let Some(value) = value {
            if state.readonly_vars.contains(name) {
                eprintln!("readonly: {name}: readonly variable");
                failed = true;
                continue;
            }
            std::env::set_var(name, value);
        }
        state.readonly_vars.insert(name.to_string());
    }
    state.last_status = if failed { 1 } else { 0 };
    Ok(())
}

fn handle_shift(state: &mut ShellState, args: &[String]) -> io::Result<()> {
    if !state.in_local_scope() || state.positional_stack.is_empty() {
        eprintln!("shift: only valid inside a function");
        state.last_status = 2;
        return Ok(());
    }
    let count = if args.len() >= 2 {
        match args[1].parse::<usize>() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("shift: invalid count");
                state.last_status = 2;
                return Ok(());
            }
        }
    } else {
        1
    };
    let args_vec = state.positional_stack.last_mut().unwrap();
    if count > args_vec.len() {
        eprintln!("shift: count out of range");
        state.last_status = 1;
        return Ok(());
    }
    args_vec.drain(0..count);
    state.last_status = 0;
    Ok(())
}

fn handle_eval(state: &mut ShellState, args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        state.last_status = 0;
        return Ok(());
    }
    let joined = args[1..].join(" ");
    let tokens = parse_line_lenient(&joined)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    if tokens.is_empty() {
        state.last_status = 0;
        return Ok(());
    }
    execute_script_tokens(state, tokens)?;
    Ok(())
}

fn handle_alias(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    if args.len() == 1 || (args.len() == 2 && args[1] == "-p") {
        let mut entries: Vec<_> = state.aliases.iter().collect();
        entries.sort_by_key(|(name, _)| *name);
        for (name, tokens) in entries {
            let value = tokens
                .iter()
                .map(|t| shell_quote(t))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(output, "alias {name}={}", shell_quote(&value));
        }
        state.last_status = 0;
        return Ok(());
    }
    let mut idx = 1usize;
    if args[1] == "-p" {
        idx += 1;
    }
    let mut failed = false;
    for entry in &args[idx..] {
        if let Some((name, value)) = entry.split_once('=') {
            if !crate::utils::is_valid_var_name(name) {
                eprintln!("alias: invalid name '{name}'");
                failed = true;
                continue;
            }
            let tokens = parse_line_lenient(value).unwrap_or_default();
            if tokens.is_empty() {
                eprintln!("alias: empty value for '{name}'");
                failed = true;
                continue;
            }
            state.aliases.insert(name.to_string(), tokens);
        } else if let Some(tokens) = state.aliases.get(entry) {
            let value = tokens
                .iter()
                .map(|t| shell_quote(t))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(output, "alias {entry}={}", shell_quote(&value));
        } else {
            eprintln!("alias: {entry}: not found");
            failed = true;
        }
    }
    state.last_status = if failed { 1 } else { 0 };
    Ok(())
}

fn handle_unalias(state: &mut ShellState, args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("unalias: missing name");
        state.last_status = 2;
        return Ok(());
    }
    let mut failed = false;
    for name in &args[1..] {
        if state.aliases.remove(name).is_none() {
            eprintln!("unalias: {name}: not found");
            failed = true;
        }
    }
    state.last_status = if failed { 1 } else { 0 };
    Ok(())
}

fn handle_disown(state: &mut ShellState, args: &[String]) -> io::Result<()> {
    let id = parse_job_id(args.get(1))?;
    if take_job(&mut state.jobs, id).is_none() {
        eprintln!("disown: no such job");
        state.last_status = 1;
        return Ok(());
    }
    state.last_status = 0;
    Ok(())
}

fn handle_bind(state: &mut ShellState, args: &[String], output: &mut String) -> io::Result<()> {
    if args.len() == 1 || (args.len() == 2 && args[1] == "-p") {
        let mut entries: Vec<_> = state.bindings.iter().collect();
        entries.sort_by_key(|(k, _)| *k);
        for (key, action) in entries {
            let _ = writeln!(output, "{key} {action}");
        }
        state.last_status = 0;
        return Ok(());
    }
    let mut idx = 1usize;
    if args[1] == "-p" {
        idx += 1;
    }
    if idx + 1 >= args.len() {
        eprintln!("bind: expected key and command");
        state.last_status = 2;
        return Ok(());
    }
    let key = &args[idx];
    let action = &args[idx + 1];
    let key_event = match parse_key_event(key) {
        Some(ev) => ev,
        None => {
            eprintln!("bind: unsupported key '{key}'");
            state.last_status = 2;
            return Ok(());
        }
    };
    let cmd = match parse_bind_cmd(action) {
        Some(cmd) => cmd,
        None => {
            eprintln!("bind: unsupported action '{action}'");
            state.last_status = 2;
            return Ok(());
        }
    };
    state.editor.bind_sequence(key_event, cmd);
    state.bindings.insert(key.to_string(), action.to_string());
    state.last_status = 0;
    Ok(())
}

fn parse_key_event(input: &str) -> Option<KeyEvent> {
    let mut mods = Modifiers::NONE;
    let mut key = input.to_string();
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() > 1 {
        for part in &parts[..parts.len() - 1] {
            match part.to_ascii_uppercase().as_str() {
                "C" | "CTRL" => mods |= Modifiers::CTRL,
                "M" | "ALT" => mods |= Modifiers::ALT,
                "S" | "SHIFT" => mods |= Modifiers::SHIFT,
                _ => return None,
            }
        }
        key = parts[parts.len() - 1].to_string();
    }
    let key_upper = key.to_ascii_uppercase();
    let code = match key_upper.as_str() {
        "TAB" => KeyCode::Tab,
        "ENTER" => KeyCode::Enter,
        "ESC" | "ESCAPE" => KeyCode::Esc,
        "BACKSPACE" => KeyCode::Backspace,
        _ => {
            let ch = key.chars().next()?;
            if key.len() == 1 {
                return Some(KeyEvent::new(ch, mods));
            }
            return None;
        }
    };
    Some(KeyEvent(code, mods))
}

fn parse_bind_cmd(input: &str) -> Option<Cmd> {
    match input {
        "history-search-backward" => Some(Cmd::HistorySearchBackward),
        "history-search-forward" => Some(Cmd::HistorySearchForward),
        "previous-history" => Some(Cmd::PreviousHistory),
        "next-history" => Some(Cmd::NextHistory),
        "backward-char" => Some(Cmd::Move(Movement::BackwardChar(1))),
        "forward-char" => Some(Cmd::Move(Movement::ForwardChar(1))),
        "beginning-of-line" => Some(Cmd::Move(Movement::BeginningOfLine)),
        "end-of-line" => Some(Cmd::Move(Movement::EndOfLine)),
        "complete" => Some(Cmd::Complete),
        "accept-line" => Some(Cmd::AcceptLine),
        _ => None,
    }
}

fn shell_quote(token: &str) -> String {
    if token.is_empty() || token.chars().any(needs_quotes) {
        let mut out = String::from("'");
        for ch in token.chars() {
            if ch == '\'' {
                out.push_str("'\\''");
            } else {
                out.push(ch);
            }
        }
        out.push('\'');
        out
    } else {
        token.to_string()
    }
}

fn needs_quotes(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '\'' | '"' | '\\' | '$' | '`' | '#' | '|' | '&' | ';' | '<' | '>'
        )
}

fn parse_assoc_array_literal(
    tokens: &[String],
) -> Option<(String, std::collections::HashMap<String, String>)> {
    let first = tokens.first()?;
    let eq_pos = first.find("=(")?;
    let name = first[..eq_pos].to_string();
    let mut values = std::collections::HashMap::new();
    let mut first_val = first[eq_pos + 2..].to_string();
    if tokens.len() == 1 {
        if first_val.ends_with(')') {
            first_val.pop();
            if !first_val.is_empty() {
                parse_assoc_literal_item(&first_val, &mut values)?;
            }
            return Some((name, values));
        }
        return None;
    }
    if !first_val.is_empty() {
        parse_assoc_literal_item(&first_val, &mut values)?;
    }
    for token in tokens.iter().skip(1).take(tokens.len() - 2) {
        parse_assoc_literal_item(token, &mut values)?;
    }
    let mut last = tokens.last()?.clone();
    if !last.ends_with(')') {
        return None;
    }
    last.pop();
    if !last.is_empty() {
        parse_assoc_literal_item(&last, &mut values)?;
    }
    Some((name, values))
}

fn parse_assoc_literal_item(
    token: &str,
    values: &mut std::collections::HashMap<String, String>,
) -> Option<()> {
    if !token.starts_with('[') {
        return None;
    }
    let close = token.find("]=")?;
    let key = &token[1..close];
    if key.is_empty() {
        return None;
    }
    if key.parse::<usize>().is_ok() {
        return None;
    }
    let value = &token[close + 2..];
    values.insert(key.to_string(), value.to_string());
    Some(())
}

fn execute_type_substitution(args: &[String]) -> Result<CaptureResult, String> {
    if args.len() < 2 {
        return Err(ShellError::new(
            ErrorKind::Execution,
            "type: missing name".to_string(),
        )
        .to_string());
    }
    let mut output = String::new();
    let mut ok = true;
    for name in &args[1..] {
        if is_builtin(Some(name)) {
            output.push_str(&format!("{name} is a shell builtin\n"));
            continue;
        }
        if let Some(path) = find_in_path(name) {
            output.push_str(&format!("{name} is {path}\n"));
            continue;
        }
        ok = false;
    }
    Ok(CaptureResult {
        output,
        status_code: if ok { 0 } else { 1 },
    })
}

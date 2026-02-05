mod config_cmds;
mod control_flow;
mod job_cmds;
mod scripting;

pub(crate) use scripting::execute_function;

use std::fmt::Write;
use std::io::{self, Read};
use std::path::Path;
use std::{env, fs};

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
    execute_brace_group, execute_case, execute_for, execute_if, execute_select, execute_while,
    is_brace_group_start, is_case_start, is_for_start, is_if_start, is_select_start,
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
                | "unset"
                | "local"
                | "getopts"
                | "type"
                | "fc"
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
                "Built-ins: cd [dir], pwd, jobs, fg [id], bg [id], help, exit [code], echo, true, false, unset, local, getopts, type, fc, abbr, complete"
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
    let result = execute_builtin_substitution_capture(&pipeline[0], None)?;
    Ok((result.output, result.status_code))
}

pub fn execute_builtin_substitution_capture(
    cmd: &CommandSpec,
    _stdin: Option<&mut dyn Read>,
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
            output: "Built-ins: cd [dir], pwd, jobs, fg [id], bg [id], help, exit [code], echo, true, false, unset, local, getopts, type, fc, abbr, complete"
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

fn handle_type(state: &ShellState, args: &[String], output: &mut String) -> io::Result<()> {
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
        if is_builtin(Some(name)) || name == "set" {
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
    let mut list_only = false;
    let mut no_numbers = false;
    let mut reverse = false;
    let mut idx = 1usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "-l" => list_only = true,
            "-n" => no_numbers = true,
            "-r" => reverse = true,
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

    if !list_only {
        list_only = true;
    }

    let history_len = state.editor.history().len();
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
        if let Some(entry) = state.editor.history().get(i) {
            if no_numbers {
                let _ = writeln!(output, "{entry}");
            } else {
                let _ = writeln!(output, "{i} {entry}");
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

fn find_in_path(name: &str) -> Option<String> {
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

fn execute_type_substitution(args: &[String]) -> Result<CaptureResult, String> {
    if args.len() < 2 {
        return Err(ShellError::new(
            ErrorKind::Execution,
            "type: missing name".to_string(),
        )
        .into());
    }
    let mut output = String::new();
    let mut ok = true;
    for name in &args[1..] {
        if is_builtin(Some(name)) || name == "set" {
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

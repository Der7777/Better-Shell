use rustyline::history::DefaultHistory;
use rustyline::{Config, EditMode, Editor};
use signal_hook::consts::signal::SIGCHLD;
use signal_hook::flag;
use std::collections::HashMap;
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicI32, Ordering},
    Arc,
};

mod builtins;
mod colors;
mod completion;
mod completions;
mod config;
mod execution;
mod expansion;
mod heredoc;
mod io_helpers;
mod job_control;
mod parse;
mod prompt;
mod signals;
mod utils;

use builtins::{execute_builtin, execute_builtin_substitution, is_builtin, try_execute_compound};
use colors::ColorConfig;
use completion::LineHelper;
use completions::{default_completions, load_completion_files, suggest_command, CompletionSet};
use config::{apply_abbreviations, apply_aliases, build_prompt, load_config};
use execution::{
    apply_sandbox_directive, build_command, run_pipeline, run_pipeline_capture,
    sandbox_options_for_command, spawn_command_background, spawn_pipeline_background,
    status_from_error, SandboxConfig,
};
use expansion::{expand_globs, expand_tokens, ExpansionContext};
use io_helpers::{normalize_command_output, read_input_line};
use job_control::{add_job_with_status, reap_jobs, Job, JobStatus, WaitOutcome};
use prompt::PromptTheme;
use signals::{init_session, install_signal_handlers};

use parse::{
    parse_line, parse_sandbox_value, split_pipeline, split_sequence, CommandSpec, SandboxDirective,
    SeqOp,
};

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
    let fg_pgid = Arc::new(AtomicI32::new(0));
    let interactive = unsafe { libc::isatty(libc::STDIN_FILENO) == 1 };
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
    let edit_mode = match env::var("MINISHELL_EDITMODE").ok().as_deref() {
        Some("vi") | Some("VI") => EditMode::Vi,
        _ => EditMode::Emacs,
    };
    let config = Config::builder()
        .auto_add_history(true)
        .edit_mode(edit_mode)
        .build();
    let mut editor = match Editor::with_config(config) {
        Ok(editor) => editor,
        Err(err) => {
            eprintln!("error: {err}");
            return;
        }
    };
    editor.set_helper(Some(LineHelper::new()));

    let history_path = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".custom_shell_history");
    let _ = editor.load_history(&history_path);

    let mut state = ShellState {
        editor,
        fg_pgid,
        sigchld_flag: Arc::new(AtomicBool::new(false)),
        shell_pgid,
        aliases: HashMap::new(),
        prompt_template: None,
        prompt_function: None,
        prompt_theme: PromptTheme::Fish,
        colors: ColorConfig::default(),
        functions: HashMap::new(),
        abbreviations: HashMap::new(),
        completions: CompletionSet::default(),
        jobs: Vec::new(),
        next_job_id: 1,
        last_status: 0,
        pipefail: false,
        interactive,
        trace,
        sandbox: SandboxConfig::default(),
    };
    if let Err(err) = load_config(
        &mut state.aliases,
        &mut state.prompt_template,
        &mut state.prompt_function,
        &mut state.prompt_theme,
        &mut state.colors,
        &mut state.sandbox,
        &mut state.abbreviations,
    ) {
        eprintln!("config error: {err}");
    }
    state.completions = default_completions();
    if let Err(err) = load_completion_files(&mut state.completions) {
        eprintln!("completion load error: {err}");
    }
    if let Some(directive) = sandbox_override {
        apply_sandbox_directive(&mut state.sandbox, directive);
    }
    apply_sandbox_env(&mut state.sandbox);
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

fn run_once(state: &mut ShellState) -> io::Result<()> {
    if state.sigchld_flag.swap(false, Ordering::SeqCst) {
        reap_jobs(&mut state.jobs);
    }
    reap_jobs(&mut state.jobs);
    if state.interactive {
        completion::update_completion_context(
            &mut state.editor,
            &state.aliases,
            &state.functions,
            &state.abbreviations,
            &state.completions,
            &state.colors,
            &state.jobs,
        );
    }
    let cwd = env::current_dir().unwrap_or_else(|_| "/".into());
    let prompt = build_prompt(
        state.interactive,
        &state.prompt_template,
        &state.prompt_function,
        state.prompt_theme,
        &state.colors,
        state.last_status,
        &cwd,
    );
    let prompt = if let Some(name) = state.prompt_function.clone() {
        run_prompt_function(state, &name).unwrap_or(prompt)
    } else {
        prompt
    };

    let line = match read_input_line(&mut state.editor, state.interactive, &prompt)? {
        Some(line) => line,
        None => {
            if state.interactive {
                println!();
            }
            let history_path = env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".custom_shell_history");
            let _ = state.editor.save_history(&history_path);
            std::process::exit(0);
        }
    };

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    let tokens = match parse_line(trimmed) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("parse error: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };
    trace_tokens(state, "parsed tokens", &tokens);

    if tokens.is_empty() {
        return Ok(());
    }

    if let Some(handled) = try_execute_compound(state, &tokens, trimmed)? {
        if handled {
            return Ok(());
        }
    }

    let ctx = build_expansion_context(
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
    );
    let expanded = match expand_tokens(tokens, &ctx) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("parse error: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };
    trace_tokens(state, "expanded tokens", &expanded);

    if expanded.is_empty() {
        return Ok(());
    }

    let expanded = match expand_globs(expanded) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("parse error: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };
    trace_tokens(state, "globbed tokens", &expanded);

    if expanded.is_empty() {
        return Ok(());
    }

    let segments = match split_sequence(expanded) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("parse error: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };

    for segment in segments {
        let should_run = match segment.op {
            SeqOp::Always => true,
            SeqOp::And => state.last_status == 0,
            SeqOp::Or => state.last_status != 0,
        };
        if should_run {
            execute_segment(state, segment.tokens, &segment.display)?;
        }
    }

    Ok(())
}

pub(crate) fn execute_segment(
    state: &mut ShellState,
    tokens: Vec<String>,
    display: &str,
) -> io::Result<()> {
    let tokens = apply_abbreviations(tokens, &state.abbreviations);
    let tokens = apply_aliases(tokens, &state.aliases);
    trace_tokens(state, "segment tokens", &tokens);
    let (mut pipeline, background) = match split_pipeline(tokens) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("parse error: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };
    if let Err(msg) = heredoc::fill_heredocs(&mut pipeline, state.interactive, &mut state.editor) {
        eprintln!("parse error: {msg}");
        state.last_status = 2;
        return Ok(());
    }
    trace_command_specs(state, &pipeline);

    if background {
        if pipeline
            .iter()
            .any(|cmd| is_builtin(cmd.args.first().map(String::as_str)))
        {
            eprintln!("background jobs only work with external commands");
            state.last_status = 2;
            return Ok(());
        }
        let job_count = pipeline.len();
        let (job_pgid, last_pid) = if pipeline.len() > 1 {
            spawn_pipeline_background(&pipeline, state.trace, &state.sandbox)?
        } else {
            let mut command = build_command(&pipeline[0])?;
            let sandbox = sandbox_options_for_command(&pipeline[0], &state.sandbox, state.trace);
            spawn_command_background(&mut command, state.trace, sandbox)?
        };
        let job_id = add_job_with_status(
            &mut state.jobs,
            &mut state.next_job_id,
            job_pgid,
            last_pid,
            job_count,
            display,
            JobStatus::Running,
        );
        println!("[{job_id}] {job_pgid}");
        state.last_status = 0;
        return Ok(());
    }

    if pipeline.len() > 1 {
        if pipeline
            .iter()
            .any(|cmd| is_builtin(cmd.args.first().map(String::as_str)))
        {
            eprintln!("pipes only work with external commands");
            state.last_status = 2;
            return Ok(());
        }
        match run_pipeline(
            &pipeline,
            &state.fg_pgid,
            state.shell_pgid,
            state.trace,
            &state.sandbox,
        ) {
            Ok(result) => {
                if matches!(result.outcome, WaitOutcome::Stopped) {
                    let job_id = add_job_with_status(
                        &mut state.jobs,
                        &mut state.next_job_id,
                        result.pgid,
                        result.last_pid,
                        pipeline.len(),
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
                        &pipeline[0].args[0],
                        &state.aliases,
                        &state.functions,
                        &state.abbreviations,
                        &state.completions,
                    ) {
                        if suggestion != pipeline[0].args[0] {
                            eprintln!("Command not found—did you mean '{suggestion}'?");
                        }
                    }
                }
                state.last_status = status_from_error(&err);
            }
        }
        return Ok(());
    }

    let cmd = &pipeline[0];
    execute_builtin(state, cmd, display)
}

pub(crate) fn trace_tokens(state: &ShellState, label: &str, tokens: &[String]) {
    if state.trace {
        eprintln!("trace: {label}: {tokens:?}");
    }
}

fn trace_command_specs(state: &ShellState, pipeline: &[CommandSpec]) {
    if !state.trace {
        return;
    }
    for (idx, cmd) in pipeline.iter().enumerate() {
        eprintln!("trace: argv[{idx}]: {:?}", cmd.args);
        if let Some(directive) = cmd.sandbox {
            eprintln!("trace: sandbox {directive:?}");
        }
        if let Some(ref path) = cmd.stdin {
            eprintln!("trace: redirect stdin < {}", path);
        }
        if let Some(ref heredoc) = cmd.heredoc {
            if let Some(ref content) = heredoc.content {
                eprintln!("trace: redirect stdin << heredoc ({} bytes)", content.len());
            } else {
                eprintln!("trace: redirect stdin << {}", heredoc.delimiter);
            }
        }
        if let Some(ref out) = cmd.stdout {
            let mode = if out.append { ">>" } else { ">" };
            eprintln!("trace: redirect stdout {mode} {}", out.path);
        }
    }
}

fn execute_command_substitution(
    inner: &str,
    fg_pgid: &Arc<AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
) -> Result<String, String> {
    let tokens = parse_line(inner)?;
    if tokens.is_empty() {
        return Ok(String::new());
    }
    let ctx = build_expansion_context(Arc::clone(fg_pgid), trace, sandbox.clone());
    let expanded = expand_tokens(tokens, &ctx)?;
    if expanded.is_empty() {
        return Ok(String::new());
    }
    let expanded = expand_globs(expanded)?;
    if expanded.is_empty() {
        return Ok(String::new());
    }
    let segments = split_sequence(expanded)?;
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
            return Err("background jobs not allowed in command substitution".to_string());
        }
        if pipeline
            .iter()
            .any(|cmd| is_builtin(cmd.args.first().map(String::as_str)))
        {
            let (text, status) = execute_builtin_substitution(&pipeline)?;
            output.push_str(&text);
            last_status = status;
            continue;
        }
        let result = run_pipeline_capture(&pipeline, fg_pgid, trace, &sandbox)
            .map_err(|err| format!("command substitution failed: {err}"))?;
        output.push_str(&result.output);
        last_status = result.status_code;
    }

    Ok(normalize_command_output(output))
}

fn run_prompt_function(state: &mut ShellState, name: &str) -> Option<String> {
    let tokens = state.functions.get(name)?.clone();
    let saved_status = state.last_status;
    let result = execute_tokens_capture(
        tokens,
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
    )
    .ok();
    state.last_status = saved_status;
    result
}

fn execute_tokens_capture(
    tokens: Vec<String>,
    fg_pgid: Arc<AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
) -> Result<String, String> {
    let ctx = build_expansion_context(Arc::clone(&fg_pgid), trace, sandbox.clone());
    let expanded = expand_tokens(tokens, &ctx)?;
    if expanded.is_empty() {
        return Ok(String::new());
    }
    let expanded = expand_globs(expanded)?;
    if expanded.is_empty() {
        return Ok(String::new());
    }
    let segments = split_sequence(expanded)?;
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
            return Err("background jobs not allowed in prompt function".to_string());
        }
        if pipeline
            .iter()
            .any(|cmd| is_builtin(cmd.args.first().map(String::as_str)))
        {
            let (text, status) = execute_builtin_substitution(&pipeline)?;
            output.push_str(&text);
            last_status = status;
            continue;
        }
        let result = run_pipeline_capture(&pipeline, &fg_pgid, trace, &sandbox)
            .map_err(|err| format!("prompt function failed: {err}"))?;
        output.push_str(&result.output);
        last_status = result.status_code;
    }

    Ok(normalize_command_output(output))
}

fn apply_sandbox_env(sandbox: &mut SandboxConfig) {
    if let Ok(path) = env::var("MINISHELL_BWRAP_PATH") {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            sandbox.bubblewrap_path = None;
        } else {
            sandbox.bubblewrap_path = Some(trimmed.to_string());
        }
    }
    if let Ok(args) = env::var("MINISHELL_BWRAP_ARGS") {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            sandbox.bubblewrap_args.clear();
        } else {
            match parse_line(trimmed) {
                Ok(tokens) => sandbox.bubblewrap_args = tokens,
                Err(err) => {
                    eprintln!("config error: invalid MINISHELL_BWRAP_ARGS: {err}");
                }
            }
        }
    }
}

pub(crate) fn build_expansion_context(
    fg_pgid: Arc<AtomicI32>,
    trace: bool,
    sandbox: SandboxConfig,
) -> ExpansionContext<'static> {
    ExpansionContext {
        lookup_var: Box::new(|name| env::var(name).ok()),
        command_subst: Box::new(move |inner| {
            execute_command_substitution(inner, &fg_pgid, trace, sandbox.clone())
        }),
    }
}

struct ShellState {
    editor: Editor<LineHelper, DefaultHistory>,
    fg_pgid: Arc<AtomicI32>,
    sigchld_flag: Arc<AtomicBool>,
    shell_pgid: i32,
    aliases: HashMap<String, Vec<String>>,
    prompt_template: Option<String>,
    prompt_function: Option<String>,
    prompt_theme: PromptTheme,
    colors: ColorConfig,
    functions: HashMap<String, Vec<String>>,
    abbreviations: HashMap<String, Vec<String>>,
    completions: CompletionSet,
    jobs: Vec<Job>,
    next_job_id: usize,
    last_status: i32,
    pipefail: bool,
    interactive: bool,
    trace: bool,
    sandbox: SandboxConfig,
}

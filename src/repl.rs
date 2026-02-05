use rustyline::history::DefaultHistory;
use rustyline::{Config, EditMode, Editor};
use std::collections::HashMap;
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicI32, Ordering},
    Arc,
};

use crate::builtins::{
    builtin_names, execute_builtin, execute_builtin_capture, execute_function, find_in_path,
    is_builtin, is_builtin_enabled_map, load_assoc_arrays, try_execute_compound,
};
use crate::completion::LineHelper;
use crate::completions::{default_completions, load_completion_files, suggest_command, CompletionSet};
use crate::config::sandbox::apply_sandbox_env;
use crate::config::{apply_abbreviations, apply_aliases, build_prompt, load_config};
use crate::execution::{
    apply_sandbox_directive, build_command, builtin_pipe, run_pipeline,
    sandbox_options_for_command, spawn_command_background, spawn_pipeline_background,
    status_from_error, SandboxConfig,
};
use crate::expansion::{expand_globs_with, expand_tokens};
use crate::expansion::GlobOptions;
use crate::expansion_runner::execute_tokens_capture;
use crate::heredoc;
use crate::io_helpers::read_input_line;
use crate::job_control::{add_job_with_status, reap_coprocs, reap_jobs, Coprocess, Job, JobStatus, WaitOutcome};
use crate::parse::{
    parse_line, parse_line_lenient, split_pipeline, split_pipeline_lenient, split_sequence,
    split_sequence_lenient, tokenize_history, CommandSpec, HistoryDesignator, HistoryToken,
    SandboxDirective, SeqOp, OPERATOR_TOKEN_MARKER,
};
use crate::prompt::PromptTheme;
use crate::build_expansion_context;
use crate::process_subst::{apply_process_subst, FdGuard, ProcessSubstResult};
use crate::arithmetic::eval_arithmetic;

pub(crate) struct ShellState {
    pub(crate) editor: Editor<LineHelper, DefaultHistory>,
    // Shared across job control and signal handling to track the foreground group.
    pub(crate) fg_pgid: Arc<AtomicI32>,
    // SIGCHLD handler flips this; reaping happens in the main loop.
    pub(crate) sigchld_flag: Arc<AtomicBool>,
    // Used to restore terminal control after fg jobs stop/exit.
    pub(crate) shell_pgid: i32,
    pub(crate) aliases: HashMap<String, Vec<String>>,
    pub(crate) prompt_template: Option<String>,
    pub(crate) prompt_function: Option<String>,
    pub(crate) prompt_theme: PromptTheme,
    pub(crate) colors: crate::colors::ColorConfig,
    pub(crate) functions: HashMap<String, Vec<String>>,
    pub(crate) abbreviations: HashMap<String, Vec<String>>,
    pub(crate) completions: CompletionSet,
    pub(crate) arrays: HashMap<String, Vec<String>>,
    pub(crate) assoc_arrays: HashMap<String, HashMap<String, String>>,
    pub(crate) builtin_enabled: HashMap<String, bool>,
    pub(crate) command_hash: HashMap<String, String>,
    pub(crate) readonly_vars: std::collections::HashSet<String>,
    pub(crate) positional_stack: Vec<Vec<String>>,
    pub(crate) bindings: HashMap<String, String>,
    pub(crate) coprocs: HashMap<String, Coprocess>,
    pub(crate) jobs: Vec<Job>,
    pub(crate) next_job_id: usize,
    pub(crate) next_coproc_id: usize,
    pub(crate) last_status: i32,
    // Mirrors bash-like pipefail behavior for pipelines.
    pub(crate) pipefail: bool,
    pub(crate) interactive: bool,
    pub(crate) trace: bool,
    pub(crate) extglob: bool,
    pub(crate) nullglob: bool,
    pub(crate) failglob: bool,
    pub(crate) dotglob: bool,
    pub(crate) nocaseglob: bool,
    pub(crate) dirspell: bool,
    pub(crate) functrace: bool,
    pub(crate) lineno: usize,
    pub(crate) traps: HashMap<String, String>,
    pub(crate) in_debug_trap: bool,
    pub(crate) in_return_trap: bool,
    pub(crate) sandbox: SandboxConfig,
    pub(crate) local_scopes: Vec<HashMap<String, Option<String>>>,
}

pub(crate) fn init_state(
    trace: bool,
    interactive: bool,
    shell_pgid: i32,
    sandbox_override: Option<SandboxDirective>,
) -> io::Result<ShellState> {
    let edit_mode = match env::var("MINISHELL_EDITMODE").ok().as_deref() {
        Some("vi") | Some("VI") => EditMode::Vi,
        _ => EditMode::Emacs,
    };
    let config = Config::builder()
        .auto_add_history(true)
        .edit_mode(edit_mode)
        .build();
    let mut editor = Editor::with_config(config).map_err(io::Error::other)?;
    editor.set_helper(Some(LineHelper::new()));

    let history_path = env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".custom_shell_history");
    let _ = editor.load_history(&history_path);

    let mut state = ShellState {
        editor,
        fg_pgid: Arc::new(AtomicI32::new(0)),
        sigchld_flag: Arc::new(AtomicBool::new(false)),
        shell_pgid,
        aliases: HashMap::new(),
        prompt_template: None,
        prompt_function: None,
        prompt_theme: PromptTheme::Fish,
        colors: crate::colors::ColorConfig::default(),
        functions: HashMap::new(),
        abbreviations: HashMap::new(),
        completions: CompletionSet::default(),
        arrays: HashMap::new(),
        assoc_arrays: HashMap::new(),
        builtin_enabled: builtin_names()
            .iter()
            .map(|name| (name.to_string(), true))
            .collect(),
        command_hash: HashMap::new(),
        readonly_vars: std::collections::HashSet::new(),
        positional_stack: Vec::new(),
        bindings: HashMap::new(),
        coprocs: HashMap::new(),
        jobs: Vec::new(),
        next_job_id: 1,
        next_coproc_id: 1,
        last_status: 0,
        pipefail: false,
        interactive,
        trace,
        extglob: false,
        nullglob: false,
        failglob: false,
        dotglob: false,
        nocaseglob: false,
        dirspell: false,
        functrace: false,
        lineno: 0,
        traps: HashMap::new(),
        in_debug_trap: false,
        in_return_trap: false,
        sandbox: SandboxConfig::default(),
        local_scopes: Vec::new(),
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
    if let Err(err) = load_assoc_arrays(&mut state) {
        eprintln!("assoc load error: {err}");
    }
    state.completions = default_completions();
    if let Err(err) = load_completion_files(&mut state.completions) {
        eprintln!("completion load error: {err}");
    }
    if let Some(directive) = sandbox_override {
        apply_sandbox_directive(&mut state.sandbox, directive);
    }
    apply_sandbox_env(&mut state.sandbox);

    Ok(state)
}

impl ShellState {
    pub(crate) fn in_local_scope(&self) -> bool {
        !self.local_scopes.is_empty()
    }

    pub(crate) fn push_local_scope(&mut self) {
        self.local_scopes.push(HashMap::new());
    }

    pub(crate) fn pop_local_scope(&mut self) {
        if let Some(scope) = self.local_scopes.pop() {
            for (name, prior) in scope {
                match prior {
                    Some(value) => env::set_var(&name, value),
                    None => env::remove_var(&name),
                }
            }
        }
    }

    pub(crate) fn set_local_var(&mut self, name: &str, value: &str) -> io::Result<()> {
        if !self.in_local_scope() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "local: only valid inside a function",
            ));
        }
        if self.readonly_vars.contains(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("readonly: {name}"),
            ));
        }
        if let Some(scope) = self.local_scopes.last_mut() {
            if !scope.contains_key(name) {
                scope.insert(name.to_string(), env::var(name).ok());
            }
        }
        env::set_var(name, value);
        Ok(())
    }

    pub(crate) fn unset_var(&mut self, name: &str) {
        if self.readonly_vars.contains(name) {
            return;
        }
        if let Some(scope) = self.local_scopes.last_mut() {
            if !scope.contains_key(name) {
                scope.insert(name.to_string(), env::var(name).ok());
            }
        }
        env::remove_var(name);
    }

    pub(crate) fn set_array(&mut self, name: &str, values: Vec<String>) {
        self.arrays.insert(name.to_string(), values);
    }

    pub(crate) fn set_array_elem(&mut self, name: &str, index: usize, value: String) {
        let entry = self.arrays.entry(name.to_string()).or_default();
        if index >= entry.len() {
            entry.resize(index + 1, String::new());
        }
        entry[index] = value;
    }

    pub(crate) fn unset_array(&mut self, name: &str) {
        self.arrays.remove(name);
    }

    pub(crate) fn unset_array_elem(&mut self, name: &str, index: usize) {
        if let Some(values) = self.arrays.get_mut(name) {
            if index < values.len() {
                values[index].clear();
            }
        }
    }

    pub(crate) fn set_assoc_array(&mut self, name: &str, values: HashMap<String, String>) {
        self.assoc_arrays.insert(name.to_string(), values);
    }

    pub(crate) fn set_assoc_elem(&mut self, name: &str, key: String, value: String) {
        let entry = self.assoc_arrays.entry(name.to_string()).or_default();
        entry.insert(key, value);
    }

    pub(crate) fn unset_assoc_array(&mut self, name: &str) {
        self.assoc_arrays.remove(name);
    }

    pub(crate) fn unset_assoc_elem(&mut self, name: &str, key: &str) {
        if let Some(values) = self.assoc_arrays.get_mut(name) {
            values.remove(key);
        }
    }

    pub(crate) fn is_builtin_enabled(&self, name: &str) -> bool {
        self.builtin_enabled.get(name).copied().unwrap_or(false)
    }

    pub(crate) fn current_positional(&self) -> &[String] {
        self.positional_stack
            .last()
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub(crate) fn push_positional(&mut self, args: Vec<String>) {
        self.positional_stack.push(args);
    }

    pub(crate) fn pop_positional(&mut self) {
        self.positional_stack.pop();
    }
}

pub(crate) fn run_once(state: &mut ShellState) -> io::Result<()> {
    if state.sigchld_flag.swap(false, Ordering::SeqCst) {
        reap_jobs(&mut state.jobs);
        let removed = reap_coprocs(&mut state.coprocs);
        for name in removed {
            state.unset_assoc_array(&name);
        }
    }
    if state.interactive {
        crate::completion::update_completion_context(
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

    let line = match expand_history_line(state, &line) {
        Ok(expanded) => expanded,
        Err(msg) => {
            eprintln!("history: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };

    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    state.lineno = state.lineno.saturating_add(1);

    let tokens = if state.interactive {
        match parse_line_lenient(trimmed) {
            Ok(v) => v,
            Err(msg) => {
                eprintln!("parse error: {msg}");
                state.last_status = 2;
                return Ok(());
            }
        }
    } else {
        match parse_line(trimmed) {
            Ok(v) => v,
            Err(msg) => {
                eprintln!("parse error: {msg}");
                state.last_status = 2;
                return Ok(());
            }
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
        !state.interactive,
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

    let ProcessSubstResult { tokens: expanded, keep_fds } = match apply_process_subst(
        expanded,
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        state.assoc_arrays.clone(),
        state.builtin_enabled.clone(),
        glob_options,
        !state.interactive,
    ) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("process substitution error: {err}");
            state.last_status = 2;
            return Ok(());
        }
    };
    let _fd_guard = FdGuard(keep_fds);

    let expanded = match expand_globs_with(
        expanded,
        GlobOptions {
            extglob: state.extglob,
            nullglob: state.nullglob,
            failglob: state.failglob,
            dotglob: state.dotglob,
            nocaseglob: state.nocaseglob,
            dirspell: state.dirspell,
        },
    ) {
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

    let segments = if state.interactive {
        split_sequence_lenient(expanded)
    } else {
        match split_sequence(expanded) {
            Ok(v) => v,
            Err(msg) => {
                eprintln!("parse error: {msg}");
                state.last_status = 2;
                return Ok(());
            }
        }
    };

    for segment in segments {
        let should_run = match segment.op {
            SeqOp::Always => true,
            SeqOp::And => state.last_status == 0,
            SeqOp::Or => state.last_status != 0,
        };
        if should_run {
            if state.interactive {
                execute_segment_lenient(state, segment.tokens, &segment.display)?;
            } else {
                execute_segment(state, segment.tokens, &segment.display)?;
            }
        }
    }

    Ok(())
}

pub(crate) fn execute_segment(
    state: &mut ShellState,
    tokens: Vec<String>,
    display: &str,
) -> io::Result<()> {
    run_debug_trap(state)?;
    let tokens = apply_abbreviations(tokens, &state.abbreviations);
    let tokens = apply_aliases(tokens, &state.aliases);
    trace_tokens(state, "segment tokens", &tokens);
    if try_handle_array_assignment(state, &tokens)? {
        return Ok(());
    }
    let (mut pipeline, background) = match split_pipeline(tokens) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("parse error: {msg}");
            state.last_status = 2;
            return Ok(());
        }
    };
    apply_command_hash(state, &mut pipeline);
    if let Err(msg) = heredoc::fill_heredocs(&mut pipeline, state.interactive, &mut state.editor) {
        eprintln!("parse error: {msg}");
        state.last_status = 2;
        return Ok(());
    }
    trace_command_specs(state, &pipeline);

    if pipeline.len() == 1 {
        if let Some(expr) = extract_arithmetic_expr(&pipeline[0]) {
            match eval_arithmetic(&expr) {
                Ok(value) => {
                    state.last_status = if value == 0 { 1 } else { 0 };
                }
                Err(err) => {
                    eprintln!("arithmetic error: {err}");
                    state.last_status = 2;
                }
            }
            return Ok(());
        }
    }

    if background {
        if pipeline.iter().any(|cmd| {
            cmd.args
                .first()
                .map(String::as_str)
                .is_some_and(|name| is_builtin(Some(name)) && state.is_builtin_enabled(name))
        })
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
        let has_builtin = pipeline.iter().any(|cmd| {
            let name = cmd.args.first().map(String::as_str);
            name.is_some_and(|name| is_builtin(Some(name)) && state.is_builtin_enabled(name))
        });
        if has_builtin {
            let builtin_enabled = state.builtin_enabled.clone();
            let trace = state.trace;
            let sandbox = state.sandbox.clone();
            match builtin_pipe(
                &pipeline,
                |cmd| {
                    let name = cmd.args.first().map(String::as_str);
                    name.is_some_and(|name| {
                        is_builtin_enabled_map(&builtin_enabled, Some(name))
                    })
                },
                |cmd, stdin| execute_builtin_capture(state, cmd, display, stdin),
                trace,
                &sandbox,
            ) {
                Ok(result) => {
                    let last = result.status_code;
                    let pipefail = if result.pipefail_status == 0 {
                        last
                    } else {
                        result.pipefail_status
                    };
                    state.last_status = if state.pipefail { pipefail } else { last };
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
        } else {
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
        }
        return Ok(());
    }

    let cmd = &pipeline[0];
    if let Some(func_tokens) = state.functions.get(&cmd.args[0]) {
        execute_function(state, func_tokens.clone(), &cmd.args[1..])
    } else {
        execute_builtin(state, cmd, display)
    }
}

fn execute_segment_lenient(
    state: &mut ShellState,
    tokens: Vec<String>,
    display: &str,
) -> io::Result<()> {
    run_debug_trap(state)?;
    let tokens = apply_abbreviations(tokens, &state.abbreviations);
    let tokens = apply_aliases(tokens, &state.aliases);
    trace_tokens(state, "segment tokens", &tokens);
    if try_handle_array_assignment(state, &tokens)? {
        return Ok(());
    }
    let (mut pipeline, background) = split_pipeline_lenient(tokens);
    if pipeline.is_empty() {
        return Ok(());
    }
    apply_command_hash(state, &mut pipeline);
    if let Err(msg) = heredoc::fill_heredocs(&mut pipeline, state.interactive, &mut state.editor) {
        eprintln!("parse error: {msg}");
        state.last_status = 2;
        return Ok(());
    }
    trace_command_specs(state, &pipeline);

    if pipeline.len() == 1 {
        if let Some(expr) = extract_arithmetic_expr(&pipeline[0]) {
            match eval_arithmetic(&expr) {
                Ok(value) => {
                    state.last_status = if value == 0 { 1 } else { 0 };
                }
                Err(err) => {
                    eprintln!("arithmetic error: {err}");
                    state.last_status = 2;
                }
            }
            return Ok(());
        }
    }

    if background {
        if pipeline.iter().any(|cmd| {
            cmd.args
                .first()
                .map(String::as_str)
                .is_some_and(|name| is_builtin(Some(name)) && state.is_builtin_enabled(name))
        })
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
        let has_builtin = pipeline.iter().any(|cmd| {
            let name = cmd.args.first().map(String::as_str);
            name.is_some_and(|name| is_builtin(Some(name)) && state.is_builtin_enabled(name))
        });
        if has_builtin {
            let builtin_enabled = state.builtin_enabled.clone();
            let trace = state.trace;
            let sandbox = state.sandbox.clone();
            match builtin_pipe(
                &pipeline,
                |cmd| {
                    let name = cmd.args.first().map(String::as_str);
                    name.is_some_and(|name| {
                        is_builtin_enabled_map(&builtin_enabled, Some(name))
                    })
                },
                |cmd, stdin| execute_builtin_capture(state, cmd, display, stdin),
                trace,
                &sandbox,
            ) {
                Ok(result) => {
                    let last = result.status_code;
                    let pipefail = if result.pipefail_status == 0 {
                        last
                    } else {
                        result.pipefail_status
                    };
                    state.last_status = if state.pipefail { pipefail } else { last };
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
        } else {
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
        }
        return Ok(());
    }

    let cmd = &pipeline[0];
    if let Some(func_tokens) = state.functions.get(&cmd.args[0]) {
        execute_function(state, func_tokens.clone(), &cmd.args[1..])
    } else {
        execute_builtin(state, cmd, display)
    }
}

pub(crate) fn trace_tokens(state: &ShellState, label: &str, tokens: &[String]) {
    if state.trace {
        eprintln!("{}trace: {label}: {tokens:?}", trace_prefix(state));
    }
}

fn trace_command_specs(state: &ShellState, pipeline: &[CommandSpec]) {
    if !state.trace {
        return;
    }
    for (idx, cmd) in pipeline.iter().enumerate() {
        eprintln!("{}trace: argv[{idx}]: {:?}", trace_prefix(state), cmd.args);
        if let Some(directive) = cmd.sandbox {
            eprintln!("{}trace: sandbox {directive:?}", trace_prefix(state));
        }
        if let Some(ref path) = cmd.stdin {
            eprintln!("{}trace: redirect stdin < {}", trace_prefix(state), path);
        }
        if let Some(ref heredoc) = cmd.heredoc {
            if let Some(ref content) = heredoc.content {
                eprintln!(
                    "{}trace: redirect stdin << heredoc ({} bytes)",
                    trace_prefix(state),
                    content.len()
                );
            } else {
                eprintln!(
                    "{}trace: redirect stdin << {}",
                    trace_prefix(state),
                    heredoc.delimiter
                );
            }
        }
        if let Some(ref content) = cmd.herestring {
            eprintln!(
                "{}trace: redirect stdin <<< ({} bytes)",
                trace_prefix(state),
                content.as_bytes().len()
            );
        }
        if let Some(ref out) = cmd.stdout {
            let mode = if out.append { ">>" } else { ">" };
            eprintln!(
                "{}trace: redirect stdout {mode} {}",
                trace_prefix(state),
                out.path
            );
        }
        if cmd.stderr_to_stdout {
            eprintln!("{}trace: redirect stderr >&1", trace_prefix(state));
        } else if cmd.stderr_close {
            eprintln!("{}trace: redirect stderr >&-", trace_prefix(state));
        } else if let Some(ref err) = cmd.stderr {
            let mode = if err.append { ">>" } else { ">" };
            eprintln!(
                "{}trace: redirect stderr 2{mode} {}",
                trace_prefix(state),
                err.path
            );
        }
    }
}

fn try_handle_array_assignment(state: &mut ShellState, tokens: &[String]) -> io::Result<bool> {
    if tokens.is_empty() {
        return Ok(false);
    }
    if tokens.iter().any(|t| t.starts_with(crate::parse::OPERATOR_TOKEN_MARKER)) {
        return Ok(false);
    }
    if tokens.len() == 1 {
        if let Some((name, idx, value)) = parse_array_elem_assignment(&tokens[0]) {
            if !crate::utils::is_valid_var_name(&name) {
                eprintln!("array: invalid name '{name}'");
                state.last_status = 2;
                return Ok(true);
            }
            state.set_array_elem(&name, idx, value);
            state.last_status = 0;
            return Ok(true);
        }
        if let Some((name, key, value)) = parse_assoc_elem_assignment(&tokens[0]) {
            if !crate::utils::is_valid_var_name(&name) {
                eprintln!("array: invalid name '{name}'");
                state.last_status = 2;
                return Ok(true);
            }
            state.set_assoc_elem(&name, key, value);
            state.last_status = 0;
            return Ok(true);
        }
        if let Some((name, values)) = parse_array_literal(tokens) {
            if !crate::utils::is_valid_var_name(&name) {
                eprintln!("array: invalid name '{name}'");
                state.last_status = 2;
                return Ok(true);
            }
            state.set_array(&name, values);
            state.last_status = 0;
            return Ok(true);
        }
        if let Some((name, values)) = parse_assoc_array_literal(tokens) {
            if !crate::utils::is_valid_var_name(&name) {
                eprintln!("array: invalid name '{name}'");
                state.last_status = 2;
                return Ok(true);
            }
            state.set_assoc_array(&name, values);
            state.last_status = 0;
            return Ok(true);
        }
        return Ok(false);
    }
    if let Some((name, values)) = parse_array_literal(tokens) {
        if !crate::utils::is_valid_var_name(&name) {
            eprintln!("array: invalid name '{name}'");
            state.last_status = 2;
            return Ok(true);
        }
        state.set_array(&name, values);
        state.last_status = 0;
        return Ok(true);
    }
    if let Some((name, values)) = parse_assoc_array_literal(tokens) {
        if !crate::utils::is_valid_var_name(&name) {
            eprintln!("array: invalid name '{name}'");
            state.last_status = 2;
            return Ok(true);
        }
        state.set_assoc_array(&name, values);
        state.last_status = 0;
        return Ok(true);
    }
    Ok(false)
}

fn parse_array_elem_assignment(token: &str) -> Option<(String, usize, String)> {
    let (left, value) = token.split_once('=')?;
    let open = left.find('[')?;
    if !left.ends_with(']') {
        return None;
    }
    let name = left[..open].to_string();
    let idx_str = &left[open + 1..left.len() - 1];
    let idx = idx_str.parse::<usize>().ok()?;
    Some((name, idx, value.to_string()))
}

fn parse_assoc_elem_assignment(token: &str) -> Option<(String, String, String)> {
    let (left, value) = token.split_once('=')?;
    let open = left.find('[')?;
    if !left.ends_with(']') {
        return None;
    }
    let name = left[..open].to_string();
    let key = &left[open + 1..left.len() - 1];
    if key.is_empty() {
        return None;
    }
    if key.parse::<usize>().is_ok() {
        return None;
    }
    Some((name, key.to_string(), value.to_string()))
}

fn parse_array_literal(tokens: &[String]) -> Option<(String, Vec<String>)> {
    let first = tokens.first()?;
    let eq_pos = first.find("=(")?;
    let name = first[..eq_pos].to_string();
    let mut values = Vec::new();
    let mut first_val = first[eq_pos + 2..].to_string();
    if tokens.len() == 1 {
        if first_val.ends_with(')') {
            first_val.pop();
            if !first_val.is_empty() {
                values.push(first_val);
            }
            return Some((name, values));
        }
        return None;
    }
    if !first_val.is_empty() {
        values.push(first_val);
    }
    for token in tokens.iter().skip(1).take(tokens.len() - 2) {
        values.push(token.clone());
    }
    let mut last = tokens.last()?.clone();
    if !last.ends_with(')') {
        return None;
    }
    last.pop();
    if !last.is_empty() {
        values.push(last);
    }
    Some((name, values))
}

fn parse_assoc_array_literal(tokens: &[String]) -> Option<(String, HashMap<String, String>)> {
    let first = tokens.first()?;
    let eq_pos = first.find("=(")?;
    let name = first[..eq_pos].to_string();
    let mut values = HashMap::new();
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
    values: &mut HashMap<String, String>,
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

fn extract_arithmetic_expr(cmd: &CommandSpec) -> Option<String> {
    if cmd.args.is_empty() {
        return None;
    }
    let combined = cmd.args.join(" ");
    let trimmed = combined.trim();
    if !trimmed.starts_with("((") || !trimmed.ends_with("))") || trimmed.len() < 4 {
        return None;
    }
    let inner = trimmed[2..trimmed.len() - 2].trim();
    if inner.is_empty() {
        return None;
    }
    Some(inner.to_string())
}

fn run_prompt_function(state: &mut ShellState, name: &str) -> Option<String> {
    let tokens = state.functions.get(name)?.clone();
    let saved_status = state.last_status;
    let glob_options = GlobOptions {
        extglob: state.extglob,
        nullglob: state.nullglob,
        failglob: state.failglob,
        dotglob: state.dotglob,
        nocaseglob: state.nocaseglob,
        dirspell: state.dirspell,
    };
    let result = execute_tokens_capture(
        tokens,
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        state.assoc_arrays.clone(),
        state.builtin_enabled.clone(),
        glob_options,
        true,
    )
    .ok();
    state.last_status = saved_status;
    result
}

fn trace_prefix(state: &ShellState) -> String {
    let ps4 = std::env::var("PS4").unwrap_or_else(|_| "+ ".to_string());
    ps4.replace("$LINENO", &state.lineno.to_string())
}

fn run_debug_trap(state: &mut ShellState) -> io::Result<()> {
    if state.in_debug_trap || state.in_return_trap {
        return Ok(());
    }
    if state.in_local_scope() && !state.functrace {
        return Ok(());
    }
    let Some(cmd) = state.traps.get("DEBUG").cloned() else {
        return Ok(());
    };
    let prior = std::env::var("LINENO").ok();
    std::env::set_var("LINENO", state.lineno.to_string());
    state.in_debug_trap = true;
    let result = run_trap_command(state, &cmd);
    state.in_debug_trap = false;
    match prior {
        Some(val) => std::env::set_var("LINENO", val),
        None => std::env::remove_var("LINENO"),
    }
    result
}

pub(crate) fn run_return_trap(state: &mut ShellState) -> io::Result<()> {
    if state.in_return_trap || state.in_debug_trap {
        return Ok(());
    }
    if !state.functrace || !state.in_local_scope() {
        return Ok(());
    }
    let Some(cmd) = state.traps.get("RETURN").cloned() else {
        return Ok(());
    };
    let prior = std::env::var("LINENO").ok();
    std::env::set_var("LINENO", state.lineno.to_string());
    state.in_return_trap = true;
    let result = run_trap_command(state, &cmd);
    state.in_return_trap = false;
    match prior {
        Some(val) => std::env::set_var("LINENO", val),
        None => std::env::remove_var("LINENO"),
    }
    result
}

fn run_trap_command(state: &mut ShellState, cmd: &str) -> io::Result<()> {
    let tokens = match parse_line_lenient(cmd) {
        Ok(tokens) => tokens,
        Err(msg) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("trap parse error: {msg}"),
            ));
        }
    };
    if tokens.is_empty() {
        return Ok(());
    }
    execute_segment_lenient(state, tokens, cmd)
}

fn apply_command_hash(state: &mut ShellState, pipeline: &mut [CommandSpec]) {
    for cmd in pipeline.iter_mut() {
        let Some(name) = cmd.args.first().cloned() else {
            continue;
        };
        if name.contains('/') {
            continue;
        }
        if is_builtin(Some(&name)) && state.is_builtin_enabled(&name) {
            continue;
        }
        if state.functions.contains_key(&name) {
            continue;
        }
        if let Some(path) = state.command_hash.get(&name).cloned() {
            cmd.args[0] = path;
            continue;
        }
        if let Some(path) = find_in_path(&name) {
            state.command_hash.insert(name.clone(), path.clone());
            cmd.args[0] = path;
        }
    }
}

fn expand_history_line(state: &ShellState, line: &str) -> Result<String, String> {
    let tokens = tokenize_history(line)?;
    let mut entries: Vec<String> = state
        .editor
        .history()
        .iter()
        .map(|s| s.to_string())
        .collect();
    if entries.last().is_some_and(|last| last == line) && entries.len() > 1 {
        entries.pop();
    }
    if entries.is_empty() {
        if tokens.iter().any(|t| matches!(t, HistoryToken::Designator(_))) {
            return Err("history is empty".to_string());
        }
        return Ok(line.to_string());
    }

    let mut out = String::new();
    for token in tokens {
        match token {
            HistoryToken::Literal(text) => out.push_str(&text),
            HistoryToken::Designator(designator) => {
                let expanded = match designator {
                    HistoryDesignator::LastCommand => entries.last().cloned().unwrap_or_default(),
                    HistoryDesignator::LastArg => {
                        let args = history_args(entries.last().map(String::as_str).unwrap_or(""));
                        if args.len() > 1 {
                            args.last().cloned().unwrap_or_default()
                        } else {
                            String::new()
                        }
                    }
                    HistoryDesignator::FirstArg => {
                        let args = history_args(entries.last().map(String::as_str).unwrap_or(""));
                        if args.len() > 1 {
                            args[1].clone()
                        } else {
                            String::new()
                        }
                    }
                    HistoryDesignator::AllArgs => {
                        let args = history_args(entries.last().map(String::as_str).unwrap_or(""));
                        if args.len() > 1 {
                            args[1..].join(" ")
                        } else {
                            String::new()
                        }
                    }
                    HistoryDesignator::Relative(n) => {
                        if n == 0 || n > entries.len() {
                            return Err(format!("event not found: -{n}"));
                        }
                        entries[entries.len() - n].clone()
                    }
                    HistoryDesignator::Prefix(prefix) => {
                        let mut found = None;
                        for entry in entries.iter().rev() {
                            if entry.starts_with(&prefix) {
                                found = Some(entry.clone());
                                break;
                            }
                        }
                        found.ok_or_else(|| format!("event not found: {prefix}"))?
                    }
                };
                out.push_str(&expanded);
            }
        }
    }

    Ok(out)
}

fn history_args(command: &str) -> Vec<String> {
    let tokens = parse_line_lenient(command).unwrap_or_default();
    tokens
        .into_iter()
        .filter(|token| !token.starts_with(OPERATOR_TOKEN_MARKER))
        .collect()
}

use std::io;
use std::fmt::Write;

use crate::colors::{apply_color_setting, format_color_lines, resolve_color, save_colors};
use crate::completions::{
    apply_completion_tokens, format_completion_lines, save_completion_file,
};
use crate::config::{format_abbreviation_line, save_abbreviations};
use crate::parse::parse_line;
use crate::utils::is_valid_var_name;
use crate::ShellState;

use super::scripting::execute_script_tokens;

pub(crate) fn handle_abbr(
    state: &mut ShellState,
    args: &[String],
    output: &mut String,
) -> io::Result<()> {
    // Abbreviations expand at command position, unlike aliases which replace commands.
    if args.len() == 1 {
        let mut entries: Vec<_> = state.abbreviations.iter().collect();
        entries.sort_by_key(|(name, _)| *name);
        for (name, tokens) in entries {
            let _ = writeln!(output, "{}", format_abbreviation_line(name, tokens));
        }
        state.last_status = 0;
        return Ok(());
    }
    if args[1] == "-e" || args[1] == "--erase" {
        let Some(name) = args.get(2) else {
            eprintln!("abbr: missing name to erase");
            state.last_status = 2;
            return Ok(());
        };
        if state.abbreviations.remove(name).is_none() {
            eprintln!("abbr: no such abbreviation '{name}'");
            state.last_status = 1;
            return Ok(());
        }
        if let Err(err) = save_abbreviations(&state.abbreviations) {
            eprintln!("abbr: failed to save abbreviations: {err}");
            state.last_status = 1;
            return Ok(());
        }
        state.last_status = 0;
        return Ok(());
    }
    if args.len() < 3 {
        eprintln!("usage: abbr name expansion...");
        eprintln!("       abbr -e name");
        state.last_status = 2;
        return Ok(());
    }
    let name = &args[1];
    if !is_valid_var_name(name) {
        eprintln!("abbr: invalid name '{name}'");
        state.last_status = 2;
        return Ok(());
    }
    let expansion = args[2..].iter().cloned().collect::<Vec<_>>();
    state.abbreviations.insert(name.to_string(), expansion);
    if let Err(err) = save_abbreviations(&state.abbreviations) {
        eprintln!("abbr: failed to save abbreviations: {err}");
        state.last_status = 1;
        return Ok(());
    }
    state.last_status = 0;
    Ok(())
}

pub(crate) fn handle_complete(
    state: &mut ShellState,
    args: &[String],
    output: &mut String,
) -> io::Result<()> {
    // Completions can come from user and fish-compatible files.
    if args.len() == 1 {
        for line in format_completion_lines(&state.completions) {
            let _ = writeln!(output, "{line}");
        }
        state.last_status = 0;
        return Ok(());
    }
    match apply_completion_tokens(args, &mut state.completions) {
        Ok(()) => {
            if let Err(err) = save_completion_file(&state.completions) {
                eprintln!("complete: failed to save completions: {err}");
                state.last_status = 1;
                return Ok(());
            }
            state.last_status = 0;
        }
        Err(err) => {
            eprintln!("{err}");
            eprintln!("usage: complete -c cmd -a 'items...'");
            eprintln!("       complete -c cmd -x 'script'");
            eprintln!("       complete -c cmd -r");
            state.last_status = 2;
        }
    }
    Ok(())
}

pub(crate) fn handle_set_color(
    state: &mut ShellState,
    args: &[String],
    output: &mut String,
) -> io::Result<()> {
    // Persist colors so prompt theme changes survive restarts.
    if args.len() == 1 {
        for line in format_color_lines(&state.colors) {
            let _ = writeln!(output, "{line}");
        }
        state.last_status = 0;
        return Ok(());
    }
    if args.len() < 3 {
        eprintln!("usage: set_color key value");
        eprintln!("       set_color");
        state.last_status = 2;
        return Ok(());
    }
    let key = args[1].trim().trim_start_matches("color.");
    let value = args[2..].join(" ");
    match apply_color_setting(&mut state.colors, key, value.trim()) {
        Ok(()) => {
            if let Err(err) = save_colors(&state.colors) {
                eprintln!("set_color: failed to save colors: {err}");
                state.last_status = 1;
                return Ok(());
            }
            state.last_status = 0;
        }
        Err(err) => {
            eprintln!("set_color: {err}");
            state.last_status = 2;
        }
    }
    Ok(())
}

pub(crate) fn handle_fish_config(state: &mut ShellState, output: &mut String) -> io::Result<()> {
    let _ = writeln!(output, "Custom shell config (TUI placeholder).");
    let _ = writeln!(output, "Current colors:");
    for line in format_color_lines(&state.colors) {
        let mut parts = line.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        let color = resolve_color(value);
        if color.is_empty() {
            let _ = writeln!(output, "{key}={value}");
        } else {
            let _ = writeln!(output, "{key}={color}{value}\x1b[0m");
        }
    }
    let _ = writeln!(output, "Use: set_color key value");
    let _ = writeln!(
        output,
        "Keys: prompt_status, prompt_cwd, prompt_git, prompt_symbol, hint"
    );
    state.last_status = 0;
    Ok(())
}

pub(crate) fn handle_source(
    state: &mut ShellState,
    args: &[String],
    _output: &mut String,
) -> io::Result<()> {
    if let Some(file) = args.get(1) {
        match std::fs::read_to_string(file) {
            Ok(content) => {
                let tokens = match parse_line(&content) {
                    Ok(t) => t,
                    Err(msg) => {
                        eprintln!("parse error: {msg}");
                        state.last_status = 2;
                        return Ok(());
                    }
                };
                execute_script_tokens(state, tokens)?;
            }
            Err(err) => {
                eprintln!("source: {err}");
                state.last_status = 1;
            }
        }
    } else {
        eprintln!("source: missing file");
        state.last_status = 2;
    }
    Ok(())
}

pub(crate) fn handle_history(
    state: &mut ShellState,
    args: &[String],
    output: &mut String,
) -> io::Result<()> {
    if let Some(count_str) = args.get(1) {
        if let Ok(count) = count_str.parse::<usize>() {
            let history_len = state.editor.history().len();
            for i in (history_len.saturating_sub(count)..history_len).rev() {
                if let Some(entry) = state.editor.history().get(i) {
                    let _ = writeln!(output, "{} {}", i, entry);
                }
            }
        } else {
            eprintln!("history: invalid number");
            state.last_status = 2;
            return Ok(());
        }
    } else {
        for (i, entry) in state.editor.history().iter().enumerate() {
            let _ = writeln!(output, "{} {}", i, entry);
        }
    }
    state.last_status = 0;
    Ok(())
}

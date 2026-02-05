use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::Path;

mod parser;
pub mod sandbox;

use crate::colors::ColorConfig;
use crate::parse::OPERATOR_TOKEN_MARKER;
use crate::prompt::{render_prompt_template, render_prompt_theme, PromptTheme};

pub use parser::load_config;

pub fn build_prompt(
    interactive: bool,
    prompt_template: &Option<String>,
    prompt_function: &Option<String>,
    prompt_theme: PromptTheme,
    colors: &ColorConfig,
    last_status: i32,
    cwd: &Path,
) -> String {
    if !interactive {
        return String::new();
    }
    if prompt_function.is_some() {
        return String::new();
    }
    if let Some(ref template) = prompt_template {
        render_prompt_template(template, last_status, cwd)
    } else {
        render_prompt_theme(prompt_theme, colors, last_status, cwd)
    }
}

pub fn apply_aliases(tokens: Vec<String>, aliases: &HashMap<String, Vec<String>>) -> Vec<String> {
    let Some(first) = tokens.first() else {
        return tokens;
    };
    if first.starts_with(OPERATOR_TOKEN_MARKER) {
        return tokens;
    }
    let Some(repl) = aliases.get(first) else {
        return tokens;
    };
    let mut out = Vec::with_capacity(repl.len() + tokens.len());
    out.extend(repl.iter().cloned());
    out.extend(tokens.into_iter().skip(1));
    out
}

pub fn apply_abbreviations(
    tokens: Vec<String>,
    abbreviations: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut command_pos = true;
    let mut iter = tokens.into_iter();
    while let Some(token) = iter.next() {
        if token.starts_with(OPERATOR_TOKEN_MARKER) {
            if is_command_delimiter(&token) {
                command_pos = true;
            }
            out.push(token);
            continue;
        }
        if command_pos {
            if let Some(expansion) = abbreviations.get(&token) {
                out.extend(expansion.iter().cloned());
                command_pos = false;
                continue;
            }
        }
        out.push(token);
        command_pos = false;
    }
    out
}

fn is_command_delimiter(token: &str) -> bool {
    let op = token.trim_start_matches(OPERATOR_TOKEN_MARKER);
    matches!(op, "|" | "||" | "&&" | ";" | "&")
}

pub fn save_abbreviations(abbreviations: &HashMap<String, Vec<String>>) -> io::Result<()> {
    let Some(home) = env::var("HOME").ok() else {
        return Ok(());
    };
    let path = format!("{home}/.minishell_abbr");
    let mut entries: Vec<_> = abbreviations.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    let mut out = String::new();
    for (name, tokens) in entries {
        out.push_str(&format_abbreviation_line(name, tokens));
        out.push('\n');
    }
    fs::write(path, out)
}

pub fn format_abbreviation_line(name: &str, tokens: &[String]) -> String {
    let value = tokens
        .iter()
        .map(|token| parser::shell_quote(token))
        .collect::<Vec<_>>()
        .join(" ");
    let mut out = String::from("abbr ");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value);
    out
}

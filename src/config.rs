use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::Path;

use crate::colors::{load_color_lines, ColorConfig};
use crate::execution::{apply_sandbox_directive, SandboxConfig};
use crate::parse::{parse_line, parse_sandbox_value, OPERATOR_TOKEN_MARKER};
use crate::prompt::{parse_prompt_theme, render_prompt_template, render_prompt_theme, PromptTheme};
use crate::utils::is_valid_var_name;

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

pub fn load_config(
    aliases: &mut HashMap<String, Vec<String>>,
    prompt_template: &mut Option<String>,
    prompt_function: &mut Option<String>,
    prompt_theme: &mut PromptTheme,
    colors: &mut ColorConfig,
    sandbox: &mut SandboxConfig,
    abbreviations: &mut HashMap<String, Vec<String>>,
) -> io::Result<()> {
    let Some(home) = env::var("HOME").ok() else {
        return Ok(());
    };
    let path = format!("{home}/.minishellrc");
    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };

    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("alias ") {
            if let Err(err) = parse_alias(aliases, rest, idx + 1) {
                eprintln!("config:{}: {err}", idx + 1);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("abbr ") {
            if let Err(err) = parse_abbreviation(abbreviations, rest, idx + 1) {
                eprintln!("config:{}: {err}", idx + 1);
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            if let Err(err) = parse_assignment(rest, idx + 1) {
                eprintln!("config:{}: {err}", idx + 1);
            }
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = strip_quotes(value.trim());
            if key.eq_ignore_ascii_case("prompt") || key == "PROMPT" {
                *prompt_template = Some(value.to_string());
                continue;
            }
            if key.eq_ignore_ascii_case("prompt_function")
                || key.eq_ignore_ascii_case("prompt_func")
            {
                if value.trim().is_empty() {
                    *prompt_function = None;
                } else {
                    *prompt_function = Some(value.trim().to_string());
                }
                continue;
            }
            if key.eq_ignore_ascii_case("prompt_theme") || key.eq_ignore_ascii_case("theme") {
                if let Some(theme) = parse_prompt_theme(value) {
                    *prompt_theme = theme;
                } else {
                    eprintln!("config:{}: unknown theme '{value}'", idx + 1);
                }
                continue;
            }
            if let Some(color_key) = key.strip_prefix("color.") {
                load_color_lines(colors, &format!("color.{color_key}={value}"));
                continue;
            }
            if key.eq_ignore_ascii_case("sandbox") {
                match parse_sandbox_value(value) {
                    Ok(directive) => apply_sandbox_directive(sandbox, directive),
                    Err(err) => eprintln!("config:{}: {err}", idx + 1),
                }
                continue;
            }
            if let Err(err) = parse_assignment(line, idx + 1) {
                eprintln!("config:{}: {err}", idx + 1);
            }
            continue;
        }
        eprintln!("config:{}: unrecognized directive", idx + 1);
    }

    let abbr_path = format!("{home}/.minishell_abbr");
    if let Ok(content) = fs::read_to_string(&abbr_path) {
        for (idx, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("abbr ") {
                if let Err(err) = parse_abbreviation(abbreviations, rest, idx + 1) {
                    eprintln!("abbr:{}: {err}", idx + 1);
                }
            }
        }
    }

    let colors_path = format!("{home}/.minishell_colors");
    if let Ok(content) = fs::read_to_string(&colors_path) {
        load_color_lines(colors, &content);
    }

    Ok(())
}

fn parse_alias(
    aliases: &mut HashMap<String, Vec<String>>,
    input: &str,
    line: usize,
) -> Result<(), String> {
    let (name, value) = input
        .split_once('=')
        .ok_or_else(|| format!("alias missing '=' on line {line}"))?;
    let name = name.trim();
    if !is_valid_var_name(name) {
        return Err(format!("invalid alias name '{name}' on line {line}"));
    }
    let value = strip_quotes(value.trim());
    let tokens =
        parse_line(value).map_err(|err| format!("alias parse error on line {line}: {err}"))?;
    if tokens.is_empty() {
        return Err(format!("alias '{name}' empty on line {line}"));
    }
    aliases.insert(name.to_string(), tokens);
    Ok(())
}

fn parse_assignment(input: &str, line: usize) -> Result<(), String> {
    let trimmed = input.trim();
    let (name, value) = trimmed
        .split_once('=')
        .ok_or_else(|| format!("assignment missing '=' on line {line}"))?;
    let name = name.trim();
    if !is_valid_var_name(name) {
        return Err(format!("invalid variable name '{name}' on line {line}"));
    }
    let value = strip_quotes(value.trim());
    env::set_var(name, value);
    Ok(())
}

fn parse_abbreviation(
    abbreviations: &mut HashMap<String, Vec<String>>,
    input: &str,
    line: usize,
) -> Result<(), String> {
    let trimmed = input.trim();
    let split_at = trimmed
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace())
        .map(|(idx, _)| idx)
        .ok_or_else(|| format!("abbr missing value on line {line}"))?;
    let name = trimmed[..split_at].trim();
    let value = trimmed[split_at..].trim();
    if !is_valid_var_name(name) {
        return Err(format!("invalid abbr name '{name}' on line {line}"));
    }
    let value = strip_quotes(value);
    let tokens =
        parse_line(value).map_err(|err| format!("abbr parse error on line {line}: {err}"))?;
    if tokens.is_empty() {
        return Err(format!("abbr '{name}' empty on line {line}"));
    }
    abbreviations.insert(name.to_string(), tokens);
    Ok(())
}

fn strip_quotes(input: &str) -> &str {
    let bytes = input.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &input[1..bytes.len() - 1];
        }
    }
    input
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
        .map(|token| shell_quote(token))
        .collect::<Vec<_>>()
        .join(" ");
    let mut out = String::from("abbr ");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value);
    out
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
            '\'' | '"'
                | '\\'
                | '$'
                | '`'
                | '#'
                | '|'
                | '&'
                | ';'
                | '<'
                | '>'
                | '('
                | ')'
                | '{'
                | '}'
        )
}

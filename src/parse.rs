//! Sentinel markers preserve intent across parsing and expansion.
//!
//! - `OPERATOR_TOKEN_MARKER` prefixes operator tokens so they survive expansion unchanged.
//! - `NOGLOB_MARKER` tags characters that must not be globbed (from quotes/escapes).
//! - `ESCAPE_MARKER` records escaped literals so they stay literal through expansion.
use crate::error::{ErrorKind, ShellError};

pub const OPERATOR_TOKEN_MARKER: char = '\x1e';
pub const NOGLOB_MARKER: char = '\x1d';
pub const ESCAPE_MARKER: char = '\x1f';

mod command_parser;
mod redirection_parser;
mod tokenizer;

#[allow(unused_imports)]
pub use command_parser::{
    SeqOp, SeqSegment, split_pipeline, split_pipeline_lenient, split_sequence,
    split_sequence_lenient,
};
#[allow(unused_imports)]
pub use tokenizer::{
    parse_line, parse_line_lenient, tokenize_history, HistoryDesignator, HistoryToken,
};

pub fn token_str(token: &str) -> &str {
    command_parser::token_str(token)
}
pub use tokenizer::{parse_command_substitution, parse_command_substitution_lenient};

#[derive(Debug, Clone)]
pub struct OutputRedirection {
    pub path: String,
    pub append: bool,
}

#[derive(Debug, Clone)]
pub struct HeredocSpec {
    pub delimiter: String,
    #[allow(dead_code)]
    pub quoted: bool,
    pub content: Option<String>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SandboxDirective {
    Enable,
    Disable,
    Bubblewrap,
    Native,
}

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub args: Vec<String>,
    pub stdin: Option<String>,
    pub heredoc: Option<HeredocSpec>,
    pub herestring: Option<String>,
    pub stdout: Option<OutputRedirection>,
    pub stderr: Option<OutputRedirection>,
    pub stderr_to_stdout: bool,
    pub stderr_close: bool,
    pub close_fds: Vec<i32>,
    pub sandbox: Option<SandboxDirective>,
}

impl CommandSpec {
    pub fn new() -> Self {
        Self {
            args: Vec::new(),
            stdin: None,
            heredoc: None,
            herestring: None,
            stdout: None,
            stderr: None,
            stderr_to_stdout: false,
            stderr_close: false,
            close_fds: Vec::new(),
            sandbox: None,
        }
    }
}

impl Default for CommandSpec {
    fn default() -> Self {
        Self::new()
    }
}

pub fn parse_sandbox_value(value: &str) -> Result<SandboxDirective, String> {
    let value = value.trim();
    match value.to_ascii_lowercase().as_str() {
        "1" | "yes" | "true" | "on" => Ok(SandboxDirective::Enable),
        "0" | "no" | "false" | "off" => Ok(SandboxDirective::Disable),
        "bwrap" | "bubblewrap" => Ok(SandboxDirective::Bubblewrap),
        "native" => Ok(SandboxDirective::Native),
        _ => Err(ShellError::new(
            ErrorKind::Config,
            format!("Invalid sandbox value: {}", value),
        )
        .with_context("Valid values: 1/yes/true/on, 0/no/false/off, bwrap, native")
        .to_string()),
    }
}

fn try_parse_sandbox_directive(token: &str) -> Result<Option<SandboxDirective>, String> {
    let Some((key, value)) = token.split_once('=') else {
        return Ok(None);
    };
    if !key.eq_ignore_ascii_case("sandbox") {
        return Ok(None);
    }
    let value = strip_markers(value);
    let directive = parse_sandbox_value(&value)?;
    Ok(Some(directive))
}

pub fn strip_markers(input: &str) -> String {
    input
        .chars()
        .filter(|ch| *ch != ESCAPE_MARKER && *ch != NOGLOB_MARKER)
        .collect()
}

#[cfg(test)]
pub fn strip_all_markers(input: &str) -> String {
    let mut chars = input.chars();
    let mut out = String::new();
    if let Some(first) = chars.next() {
        if first != OPERATOR_TOKEN_MARKER && first != ESCAPE_MARKER && first != NOGLOB_MARKER {
            out.push(first);
        }
    }
    for ch in chars {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            continue;
        }
        out.push(ch);
    }
    out
}

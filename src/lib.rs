//! Parser and expansion helpers for the shell.
//!
//! This crate exposes a minimal API so fuzz targets and unit tests can link
//! only parsing and expansion logic without pulling in interactive deps.

#[cfg(feature = "expansion")]
mod expansion;
mod parse;
mod utils;

pub use parse::{CommandSpec, HeredocSpec, OutputRedirection, SandboxDirective, SeqOp, SeqSegment};

/// Tokenize a shell command line into raw tokens.
pub fn parse_tokens(input: &str) -> Result<Vec<String>, String> {
    parse::parse_line(input)
}

/// Split a token stream into a sequence of command segments.
pub fn parse_sequence(tokens: Vec<String>) -> Result<Vec<SeqSegment>, String> {
    parse::split_sequence(tokens)
}

/// Split a token stream into a pipeline and background flag.
pub fn parse_pipeline(tokens: Vec<String>) -> Result<(Vec<CommandSpec>, bool), String> {
    parse::split_pipeline(tokens)
}

/// Fuzz helper for parser-only targets.
pub fn fuzz_parse_bytes(data: &[u8]) {
    let input = String::from_utf8_lossy(data);
    if let Ok(tokens) = parse::parse_line(&input) {
        let _ = parse::split_sequence(tokens.clone());
        let _ = parse::split_pipeline(tokens);
    }
}

#[cfg(feature = "expansion")]
pub use expansion::{expand_globs, expand_token, expand_tokens, glob_pattern, ExpansionContext};

/// Fuzz helper for parser+expansion targets.
#[cfg(feature = "expansion")]
pub fn fuzz_expand_bytes(data: &[u8]) {
    let input = String::from_utf8_lossy(data);
    let ctx = ExpansionContext {
        lookup_var: Box::new(|_| Some(String::new())),
        command_subst: Box::new(|_| Ok(String::new())),
    };
    if let Ok(tokens) = parse::parse_line(&input) {
        if let Ok(tokens) = expansion::expand_tokens(tokens, &ctx) {
            let _ = expansion::expand_globs(tokens);
        }
    }
}

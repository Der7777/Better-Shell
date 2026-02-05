//! Expansion runs in two phases: parameter/command substitution, then globbing.
//! This ordering avoids accidental globbing inside variable values.
use crate::error::{ErrorKind, ShellError};
use crate::parse::{
    parse_command_substitution, parse_command_substitution_lenient, strip_markers, ESCAPE_MARKER,
    NOGLOB_MARKER, OPERATOR_TOKEN_MARKER,
};
use crate::utils::is_valid_var_name;

mod glob;

pub use glob::{expand_globs, glob_pattern};
type LookupVar<'a> = Box<dyn Fn(&str) -> Option<String> + 'a>;
type CommandSubst<'a> = Box<dyn Fn(&str) -> Result<String, String> + 'a>;

pub struct ExpansionContext<'a> {
    pub lookup_var: LookupVar<'a>,
    pub command_subst: CommandSubst<'a>,
    // Separate positional slice for function-style parameters.
    pub positional: &'a [String],
    pub strict: bool,
}

pub fn expand_tokens(
    tokens: Vec<String>,
    ctx: &ExpansionContext<'_>,
) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    for token in tokens {
        if token.starts_with(OPERATOR_TOKEN_MARKER) {
            expanded.push(token);
            continue;
        }
        for brace_token in expand_braces(&token) {
            let value = expand_token(&brace_token, ctx)?;
            expanded.push(value);
        }
    }
    Ok(expanded)
}

pub fn expand_token(token: &str, ctx: &ExpansionContext<'_>) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = token.chars().peekable();
    // Tilde expansion only applies at the start of a token.
    let mut at_start = true;

    while let Some(ch) = chars.next() {
        if ch == ESCAPE_MARKER {
            if let Some(next) = chars.next() {
                out.push(next);
                at_start = false;
            }
            continue;
        }
        if ch == NOGLOB_MARKER {
            // Double-quoted segments mark bytes as non-globbable.
            if let Some(next) = chars.next() {
                if next == '$' {
                    let expanded = match expand_dollar(&mut chars, ctx)? {
                        Some(value) => value,
                        None => "$".to_string(),
                    };
                    out.push_str(&enforce_no_glob(&expanded));
                    at_start = false;
                    continue;
                }
                out.push(NOGLOB_MARKER);
                out.push(next);
                at_start = false;
            }
            continue;
        }

        if at_start && ch == '~' {
            let next = chars.peek().copied();
            if next.is_none() || next == Some('/') {
                if let Some(home) = (ctx.lookup_var)("HOME") {
                    out.push_str(&home);
                } else {
                    out.push('~');
                }
                at_start = false;
                continue;
            }
        }

        if ch == '$' {
            if let Some(expanded) = expand_dollar(&mut chars, ctx)? {
                out.push_str(&expanded);
                at_start = false;
                continue;
            }
        }

        out.push(ch);
        at_start = false;
    }

    Ok(out)
}

fn expand_dollar<I>(
    chars: &mut std::iter::Peekable<I>,
    ctx: &ExpansionContext<'_>,
) -> Result<Option<String>, String>
where
    I: Iterator<Item = char>,
{
    match chars.peek().copied() {
        Some('(') => {
            chars.next();
            if ctx.strict {
                let inner = parse_command_substitution(chars)?;
                let output = (ctx.command_subst)(&inner)?;
                Ok(Some(output))
            } else {
                let (inner, closed) = parse_command_substitution_lenient(chars)?;
                if !closed {
                    return Ok(Some(format!("$({inner}")));
                }
                let output = (ctx.command_subst)(&inner)?;
                Ok(Some(output))
            }
        }
        Some('{') => {
            chars.next();
            let mut inner = String::new();
            let mut found = false;
            while let Some(ch) = chars.next() {
                if ch == ESCAPE_MARKER {
                    if let Some(next) = chars.next() {
                        inner.push(ESCAPE_MARKER);
                        inner.push(next);
                    }
                    continue;
                }
                if ch == NOGLOB_MARKER {
                    if let Some(next) = chars.next() {
                        inner.push(NOGLOB_MARKER);
                        inner.push(next);
                    }
                    continue;
                }
                if ch == '}' {
                    found = true;
                    break;
                }
                inner.push(ch);
            }
            if !found {
                if ctx.strict {
                    return Err(ShellError::new(
                        ErrorKind::Expansion,
                        "Unterminated parameter expansion ${}".to_string(),
                    )
                    .with_context("Missing closing brace: ${variable}")
                    .into());
                }
                return Ok(Some(format!("${{{inner}")));
            }
            let (name, fallback) = split_parameter(&inner)?;
            let name = strip_markers(name);
            if !is_valid_var_name(&name) {
                if ctx.strict {
                    return Err(ShellError::new(
                        ErrorKind::Expansion,
                        format!("Invalid variable name: {}", name),
                    )
                    .with_context("Variable names must start with a letter or underscore, followed by letters, digits, or underscores")
                    .into());
                }
                return Ok(Some(format!("${{{inner}}}")));
            }
            let value = (ctx.lookup_var)(&name).filter(|v| !v.is_empty());
            if let Some(val) = value {
                return Ok(Some(val));
            }
            if let Some(fallback) = fallback {
                return Ok(Some(expand_token(&fallback, ctx)?));
            }
            Ok(Some(String::new()))
        }
        Some(ch) if is_var_start(ch) => {
            let mut name = String::new();
            name.push(ch);
            chars.next();
            while let Some(next) = chars.peek().copied() {
                if is_var_char(next) {
                    name.push(next);
                    chars.next();
                } else {
                    break;
                }
            }
            let value = (ctx.lookup_var)(&name).unwrap_or_default();
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}

fn split_parameter(input: &str) -> Result<(&str, Option<String>), String> {
    if let Some((name, fallback)) = input.split_once(":-") {
        Ok((name, Some(fallback.to_string())))
    } else {
        Ok((input, None))
    }
}

fn is_var_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_var_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

fn enforce_no_glob(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            continue;
        }
        out.push(NOGLOB_MARKER);
        out.push(ch);
    }
    out
}

fn expand_braces(token: &str) -> Vec<String> {
    if let Some((start, end, alts)) = find_expandable_brace(token) {
        let mut expanded = Vec::new();
        let prefix = &token[..start];
        let suffix = &token[end + 1..];
        for alt in alts {
            let mut combined = String::with_capacity(prefix.len() + alt.len() + suffix.len());
            combined.push_str(prefix);
            combined.push_str(&alt);
            combined.push_str(suffix);
            expanded.extend(expand_braces(&combined));
        }
        expanded
    } else {
        vec![token.to_string()]
    }
}

fn find_expandable_brace(token: &str) -> Option<(usize, usize, Vec<String>)> {
    let mut iter = token.char_indices().peekable();
    let mut depth = 0usize;
    let mut start = None;

    while let Some((idx, ch)) = iter.next() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            iter.next();
            continue;
        }
        if ch == '{' {
            if depth == 0 {
                start = Some(idx);
            }
            depth += 1;
            continue;
        }
        if ch == '}' && depth > 0 {
            depth -= 1;
            if depth == 0 {
                let open = start?;
                let inner = &token[open + 1..idx];
                if let Some(alts) = parse_brace_alternatives(inner) {
                    return Some((open, idx, alts));
                }
                start = None;
            }
        }
    }
    None
}

fn parse_brace_alternatives(inner: &str) -> Option<Vec<String>> {
    let (items, had_comma) = split_top_level_commas(inner);
    if had_comma {
        return Some(items);
    }
    parse_brace_range(inner)
}

fn split_top_level_commas(inner: &str) -> (Vec<String>, bool) {
    let mut iter = inner.char_indices().peekable();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();
    let mut had_comma = false;

    while let Some((idx, ch)) = iter.next() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            iter.next();
            continue;
        }
        match ch {
            '{' => depth += 1,
            '}' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            ',' if depth == 0 => {
                had_comma = true;
                parts.push(inner[start..idx].to_string());
                start = idx + 1;
            }
            _ => {}
        }
    }

    if had_comma {
        parts.push(inner[start..].to_string());
    } else {
        parts.push(inner.to_string());
    }

    (parts, had_comma)
}

fn parse_brace_range(inner: &str) -> Option<Vec<String>> {
    if inner.contains(ESCAPE_MARKER) || inner.contains(NOGLOB_MARKER) {
        return None;
    }
    let parts = split_top_level_ranges(inner)?;
    if parts.len() < 2 || parts.len() > 3 {
        return None;
    }
    let start = parts[0].trim();
    let end = parts[1].trim();
    let step = if parts.len() == 3 {
        Some(parts[2].trim())
    } else {
        None
    };

    if start.is_empty() || end.is_empty() {
        return None;
    }

    if let (Ok(start_num), Ok(end_num)) = (start.parse::<i64>(), end.parse::<i64>()) {
        let step_val = if let Some(step) = step {
            step.parse::<i64>().ok()?
        } else if start_num <= end_num {
            1
        } else {
            -1
        };
        if step_val == 0 {
            return None;
        }
        if (end_num - start_num) != 0 && (end_num - start_num).signum() != step_val.signum() {
            return None;
        }
        let mut values = Vec::new();
        let mut current = start_num;
        if step_val > 0 {
            while current <= end_num {
                values.push(current.to_string());
                current += step_val;
            }
        } else {
            while current >= end_num {
                values.push(current.to_string());
                current += step_val;
            }
        }
        return Some(values);
    }

    let start_char: Vec<char> = start.chars().collect();
    let end_char: Vec<char> = end.chars().collect();
    if start_char.len() == 1 && end_char.len() == 1 {
        let start_val = start_char[0] as i64;
        let end_val = end_char[0] as i64;
        let step_val = if let Some(step) = step {
            step.parse::<i64>().ok()?
        } else if start_val <= end_val {
            1
        } else {
            -1
        };
        if step_val == 0 {
            return None;
        }
        if (end_val - start_val) != 0 && (end_val - start_val).signum() != step_val.signum() {
            return None;
        }
        let mut values = Vec::new();
        let mut current = start_val;
        if step_val > 0 {
            while current <= end_val {
                values.push(char::from_u32(current as u32)?.to_string());
                current += step_val;
            }
        } else {
            while current >= end_val {
                values.push(char::from_u32(current as u32)?.to_string());
                current += step_val;
            }
        }
        return Some(values);
    }

    None
}

fn split_top_level_ranges(inner: &str) -> Option<Vec<String>> {
    let mut iter = inner.char_indices().peekable();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut parts = Vec::new();

    while let Some((idx, ch)) = iter.next() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            iter.next();
            continue;
        }
        match ch {
            '{' => depth += 1,
            '}' => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            '.' if depth == 0 => {
                if let Some((next_idx, next_ch)) = iter.peek().copied() {
                    if next_ch == '.' {
                        parts.push(inner[start..idx].to_string());
                        iter.next();
                        start = next_idx + 1;
                    }
                }
            }
            _ => {}
        }
    }

    if parts.is_empty() {
        return None;
    }
    parts.push(inner[start..].to_string());
    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn with_env_var<F: FnOnce()>(key: &str, value: &str, f: F) {
        let prior = env::var(key).ok();
        env::set_var(key, value);
        f();
        match prior {
            Some(val) => env::set_var(key, val),
            None => env::remove_var(key),
        }
    }

    fn ctx_no_subst() -> ExpansionContext<'static> {
        ExpansionContext {
            lookup_var: Box::new(|name| env::var(name).ok()),
            command_subst: Box::new(|_| Ok(String::new())),
            positional: &[],
            strict: true,
        }
    }

    #[test]
    fn expand_parameter_defaulting() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_EMPTY";
        env::remove_var(key);
        let token = format!("${{{key}:-fallback}}");
        assert_eq!(expand_token(&token, &ctx).unwrap(), "fallback");

        with_env_var(key, "value", || {
            let token = format!("${{{key}:-fallback}}");
            assert_eq!(expand_token(&token, &ctx).unwrap(), "value");
        });
    }

    #[test]
    fn escaped_operator_is_literal() {
        let ctx = ctx_no_subst();
        let token = format!("foo{ESCAPE_MARKER}|bar");
        assert_eq!(expand_token(&token, &ctx).unwrap(), "foo|bar");
    }

    #[test]
    fn ifs_is_not_used_for_splitting() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_IFS";
        with_env_var(key, "a:b", || {
            let tokens = vec![format!("${key}")];
            let expanded = expand_tokens(tokens, &ctx).unwrap();
            assert_eq!(expanded, vec!["a:b"]);
        });
    }

    #[test]
    fn brace_expansion_lists() {
        let ctx = ctx_no_subst();
        let tokens = vec!["a{b,c}d".to_string()];
        let expanded = expand_tokens(tokens, &ctx).unwrap();
        assert_eq!(expanded, vec!["abd", "acd"]);
    }

    #[test]
    fn brace_expansion_numeric_range() {
        let ctx = ctx_no_subst();
        let tokens = vec!["{1..3}".to_string()];
        let expanded = expand_tokens(tokens, &ctx).unwrap();
        assert_eq!(expanded, vec!["1", "2", "3"]);
    }

    #[test]
    fn brace_expansion_alpha_range() {
        let ctx = ctx_no_subst();
        let tokens = vec!["{a..c}".to_string()];
        let expanded = expand_tokens(tokens, &ctx).unwrap();
        assert_eq!(expanded, vec!["a", "b", "c"]);
    }

    #[test]
    fn brace_expansion_ignores_quoted_braces() {
        let ctx = ctx_no_subst();
        let token = format!(
            "{ESCAPE_MARKER}{{{ESCAPE_MARKER}a{ESCAPE_MARKER},{ESCAPE_MARKER}b{ESCAPE_MARKER}}"
        );
        let expanded = expand_tokens(vec![token], &ctx).unwrap();
        assert_eq!(strip_markers(&expanded[0]), "{a,b}");
    }

    use tempfile::tempdir;
}

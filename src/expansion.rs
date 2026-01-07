use glob::glob;

use crate::parse::{
    parse_command_substitution, strip_markers, ESCAPE_MARKER, NOGLOB_MARKER, OPERATOR_TOKEN_MARKER,
};
use crate::utils::is_valid_var_name;

type LookupVar<'a> = Box<dyn Fn(&str) -> Option<String> + 'a>;
type CommandSubst<'a> = Box<dyn Fn(&str) -> Result<String, String> + 'a>;

pub struct ExpansionContext<'a> {
    pub lookup_var: LookupVar<'a>,
    pub command_subst: CommandSubst<'a>,
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
        let value = expand_token(&token, ctx)?;
        expanded.push(value);
    }
    Ok(expanded)
}

pub fn expand_token(token: &str, ctx: &ExpansionContext<'_>) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = token.chars().peekable();
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
            let inner = parse_command_substitution(chars)?;
            let output = (ctx.command_subst)(&inner)?;
            Ok(Some(output))
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
                return Err("unterminated ${...}".to_string());
            }
            let (name, fallback) = split_parameter(&inner)?;
            let name = strip_markers(name);
            if !is_valid_var_name(&name) {
                return Err("invalid variable name".to_string());
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

pub fn expand_globs(tokens: Vec<String>) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    for token in tokens {
        if token.starts_with(OPERATOR_TOKEN_MARKER) {
            expanded.push(token);
            continue;
        }
        let (pattern, has_glob) = glob_pattern(&token);
        if has_glob {
            let mut matches = Vec::new();
            for entry in glob(&pattern).map_err(|err| format!("glob error: {err}"))? {
                match entry {
                    Ok(path) => matches.push(path.display().to_string()),
                    Err(err) => return Err(format!("glob error: {err}")),
                }
            }
            if matches.is_empty() {
                expanded.push(strip_markers(&token));
            } else {
                matches.sort();
                expanded.extend(matches);
            }
        } else {
            expanded.push(strip_markers(&token));
        }
    }
    Ok(expanded)
}

pub fn glob_pattern(token: &str) -> (String, bool) {
    let mut pattern = String::new();
    let mut has_glob = false;
    let mut chars = token.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            if let Some(next) = chars.next() {
                pattern.push(next);
            }
            continue;
        }
        if ch == '*' || ch == '?' {
            has_glob = true;
        }
        pattern.push(ch);
    }

    (pattern, has_glob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::env;
    use tempfile::tempdir;

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
    fn expand_globs_matches_and_sorts() {
        let dir = tempdir().unwrap();
        let p1 = dir.path().join("a.rs");
        let p2 = dir.path().join("b.rs");
        let p3 = dir.path().join("c.txt");
        std::fs::write(&p1, "a").unwrap();
        std::fs::write(&p2, "b").unwrap();
        std::fs::write(&p3, "c").unwrap();

        let pattern = format!("{}/{}.rs", dir.path().display(), "*");
        let expanded = expand_globs(vec![pattern]).unwrap();
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0], p1.display().to_string());
        assert_eq!(expanded[1], p2.display().to_string());
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

    proptest! {
        #[test]
        fn glob_pattern_no_wildcards_no_glob(s in "[^\u{1d}\u{1e}\u{1f}*?]{0,32}") {
            let (pattern, has_glob) = glob_pattern(&s);
            prop_assert_eq!(pattern, s);
            prop_assert!(!has_glob);
        }

        #[test]
        fn glob_pattern_detects_wildcards(prefix in "[^\u{1d}\u{1e}\u{1f}]{0,16}", suffix in "[^\u{1d}\u{1e}\u{1f}]{0,16}", wildcard in prop_oneof![Just('*'), Just('?')]) {
            let mut input = prefix;
            input.push(wildcard);
            input.push_str(&suffix);
            let (_, has_glob) = glob_pattern(&input);
            prop_assert!(has_glob);
        }
    }
}

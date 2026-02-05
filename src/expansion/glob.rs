use glob::{glob_with, MatchOptions};
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};

use crate::parse::{strip_markers, ESCAPE_MARKER, NOGLOB_MARKER, OPERATOR_TOKEN_MARKER};

#[derive(Copy, Clone, Debug)]
pub struct GlobOptions {
    pub extglob: bool,
    pub nullglob: bool,
    pub failglob: bool,
    pub dotglob: bool,
    pub nocaseglob: bool,
    pub dirspell: bool,
}

pub fn expand_globs(tokens: Vec<String>) -> Result<Vec<String>, String> {
    expand_globs_with(
        tokens,
        GlobOptions {
            extglob: false,
            nullglob: false,
            failglob: false,
            dotglob: false,
            nocaseglob: false,
            dirspell: false,
        },
    )
}

pub fn expand_globs_with(tokens: Vec<String>, options: GlobOptions) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    for token in tokens {
        if token.starts_with(OPERATOR_TOKEN_MARKER) {
            expanded.push(token);
            continue;
        }
        let (pattern, has_glob) = glob_pattern(&token);
        if has_glob {
            let mut matches = Vec::new();
            if options.extglob && contains_extglob(&pattern) {
                matches = match_extglob(&pattern)?;
            } else {
                let options = MatchOptions {
                    require_literal_separator: false,
                    require_literal_leading_dot: !options.dotglob,
                    case_sensitive: !options.nocaseglob,
                    ..Default::default()
                };
                for entry in
                    glob_with(&pattern, options).map_err(|err| format!("glob error: {err}"))?
                {
                    match entry {
                        Ok(path) => matches.push(path.display().to_string()),
                        Err(err) => return Err(format!("glob error: {err}")),
                    }
                }
            }
            if matches.is_empty() {
                if options.failglob {
                    return Err(format!("glob error: no matches: {pattern}"));
                }
                if !options.nullglob {
                    expanded.push(strip_markers(&token));
                }
            } else {
                matches.sort();
                expanded.extend(matches);
            }
        } else {
            let literal = strip_markers(&token);
            if options.dirspell {
                if let Some(corrected) = dirspell_correct(&literal) {
                    expanded.push(corrected);
                } else {
                    expanded.push(literal);
                }
            } else {
                expanded.push(literal);
            }
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
        if ch == '*' || ch == '?' || ch == '[' {
            has_glob = true;
        }
        if matches!(ch, '@' | '!' | '+' | '?') {
            if matches!(chars.peek(), Some('(')) {
                has_glob = true;
            }
        }
        pattern.push(ch);
    }

    (pattern, has_glob)
}

fn contains_extglob(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    let mut idx = 0usize;
    while idx + 1 < bytes.len() {
        let ch = bytes[idx] as char;
        if matches!(ch, '@' | '!' | '+' | '?' | '*') && bytes[idx + 1] == b'(' {
            return true;
        }
        idx += 1;
    }
    false
}

fn dirspell_correct(input: &str) -> Option<String> {
    let path = Path::new(input);
    if path.exists() {
        return None;
    }
    let is_absolute = path.is_absolute();
    let mut current = if is_absolute {
        PathBuf::from("/")
    } else {
        std::env::current_dir().ok()?
    };
    let components: Vec<_> = path
        .components()
        .filter_map(|comp| match comp {
            std::path::Component::Normal(name) => name.to_str().map(|s| s.to_string()),
            _ => None,
        })
        .collect();
    if components.is_empty() {
        return None;
    }
    for (idx, comp) in components.iter().enumerate() {
        let entries = fs::read_dir(&current).ok()?;
        let mut matches = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let Ok(name) = file_name.into_string() else {
                continue;
            };
            if name.eq_ignore_ascii_case(comp) {
                if entry.file_type().ok().is_some_and(|t| t.is_dir()) {
                    matches.push(name);
                }
            }
        }
        if matches.len() != 1 {
            return None;
        }
        current = current.join(&matches[0]);
        if idx + 1 == components.len() {
            if current.exists() {
                let result = if is_absolute {
                    current.display().to_string()
                } else {
                    current
                        .strip_prefix(std::env::current_dir().ok()?)
                        .ok()
                        .map(|p| p.display().to_string())?
                };
                return Some(result);
            }
        }
    }
    None
}

fn match_extglob(pattern: &str) -> Result<Vec<String>, String> {
    let regex = extglob_to_regex(pattern)?;
    let cwd = std::env::current_dir().map_err(|err| format!("glob error: {err}"))?;
    let base = extglob_base_dir(pattern, &cwd);
    let mut matches = Vec::new();
    let mut stack = vec![base.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if is_dir {
                stack.push(path.clone());
            }
            if let Some(candidate) = path_to_match(&path, &cwd, pattern.starts_with('/')) {
                if regex.is_match(&candidate) {
                    matches.push(path.display().to_string());
                }
            }
        }
    }
    Ok(matches)
}

fn path_to_match(path: &Path, cwd: &Path, absolute: bool) -> Option<String> {
    if absolute {
        return Some(path.display().to_string());
    }
    let rel = path.strip_prefix(cwd).ok()?;
    Some(rel.display().to_string())
}

fn extglob_base_dir(pattern: &str, cwd: &Path) -> PathBuf {
    let mut first_meta = None;
    let bytes = pattern.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let ch = bytes[idx] as char;
        let is_meta = ch == '*' || ch == '?' || ch == '[';
        let is_ext = matches!(ch, '@' | '!' | '+' | '?' | '*')
            && idx + 1 < bytes.len()
            && bytes[idx + 1] == b'(';
        if is_meta || is_ext {
            first_meta = Some(idx);
            break;
        }
        idx += 1;
    }
    let prefix = match first_meta {
        Some(pos) => {
            let slice = &pattern[..pos];
            match slice.rfind('/') {
                Some(idx) => &slice[..idx],
                None => "",
            }
        }
        None => pattern,
    };
    if prefix.is_empty() {
        return cwd.to_path_buf();
    }
    let path = Path::new(prefix);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn extglob_to_regex(pattern: &str) -> Result<Regex, String> {
    let mut chars = pattern.chars().peekable();
    let regex = parse_extglob_pattern(&mut chars, None)?
        .0;
    let full = format!("^{regex}$");
    Regex::new(&full).map_err(|err| format!("glob error: {err}"))
}

fn parse_extglob_pattern<I>(
    chars: &mut std::iter::Peekable<I>,
    stop: Option<char>,
) -> Result<(String, bool), String>
where
    I: Iterator<Item = char>,
{
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if Some(ch) == stop {
            return Ok((out, true));
        }
        if ch == '*' {
            if matches!(chars.peek(), Some('*')) {
                chars.next();
                out.push_str(".*");
            } else {
                out.push_str("[^/]*");
            }
            continue;
        }
        if ch == '?' {
            out.push_str("[^/]");
            continue;
        }
        if matches!(ch, '@' | '!' | '+' | '?' | '*') && matches!(chars.peek(), Some('(')) {
            chars.next();
            let group = parse_extglob_group(chars)?;
            out.push_str(&format_extglob_group(ch, group));
            continue;
        }
        if ch == '[' {
            out.push('[');
            while let Some(next) = chars.next() {
                out.push(next);
                if next == ']' {
                    break;
                }
            }
            continue;
        }
        out.push_str(&escape_regex_literal(ch));
    }
    Ok((out, false))
}

fn parse_extglob_group<I>(chars: &mut std::iter::Peekable<I>) -> Result<Vec<String>, String>
where
    I: Iterator<Item = char>,
{
    let mut alts = Vec::new();
    let mut current = String::new();
    let mut depth = 0i32;
    let mut closed = false;
    while let Some(ch) = chars.next() {
        if ch == '(' {
            depth += 1;
            current.push(ch);
            continue;
        }
        if ch == ')' {
            if depth == 0 {
                if !current.is_empty() {
                    let mut iter = current.chars().peekable();
                    let (part, _) = parse_extglob_pattern(&mut iter, None)?;
                    alts.push(part);
                } else {
                    alts.push(String::new());
                }
                closed = true;
                break;
            }
            depth -= 1;
            current.push(ch);
            continue;
        }
        if ch == '|' && depth == 0 {
            let mut iter = current.chars().peekable();
            let (part, _) = parse_extglob_pattern(&mut iter, None)?;
            alts.push(part);
            current.clear();
            continue;
        }
        current.push(ch);
    }
    if alts.is_empty() {
        return Err("glob error: empty extglob group".to_string());
    }
    if !closed {
        return Err("glob error: unterminated extglob group".to_string());
    }
    Ok(alts)
}

fn format_extglob_group(op: char, alts: Vec<String>) -> String {
    let inner = alts.join("|");
    match op {
        '@' => format!("(?:{inner})"),
        '?' => format!("(?:{inner})?"),
        '*' => format!("(?:{inner})*"),
        '+' => format!("(?:{inner})+"),
        '!' => format!("(?:(?!{inner})[^/]*)"),
        _ => inner,
    }
}

fn escape_regex_literal(ch: char) -> String {
    match ch {
        '.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '\\' => format!("\\{ch}"),
        _ => ch.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

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
    fn expand_globs_globstar_recursive() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let f1 = root.join("root.rs");
        let f2 = nested.join("deep.rs");
        std::fs::write(&f1, "root").unwrap();
        std::fs::write(&f2, "deep").unwrap();

        let pattern = format!("{}/**/*.rs", root.display());
        let expanded = expand_globs(vec![pattern]).unwrap();
        assert!(expanded.contains(&f1.display().to_string()));
        assert!(expanded.contains(&f2.display().to_string()));
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

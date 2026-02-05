//! Expansion runs in two phases: parameter/command substitution, then globbing.
//! This ordering avoids accidental globbing inside variable values.
use crate::error::{ErrorKind, ShellError};
use crate::parse::{
    parse_command_substitution, parse_command_substitution_lenient, strip_markers, ESCAPE_MARKER,
    NOGLOB_MARKER, OPERATOR_TOKEN_MARKER,
};
use ::glob::Pattern;
use crate::utils::is_valid_var_name;

mod glob;

#[allow(unused_imports)]
pub use glob::{expand_globs_with, GlobOptions};

type LookupVar<'a> = Box<dyn Fn(&str) -> Option<String> + 'a>;
type CommandSubst<'a> = Box<dyn Fn(&str) -> Result<String, String> + 'a>;

pub struct ExpansionContext<'a> {
    pub lookup_var: LookupVar<'a>,
    pub lookup_array: Box<dyn Fn(&str) -> Option<Vec<String>> + 'a>,
    pub lookup_assoc: Box<dyn Fn(&str) -> Option<std::collections::HashMap<String, String>> + 'a>,
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
    let ifs = ctx
        .lookup_var
        .as_ref()("IFS")
        .unwrap_or_else(|| " \t\n".to_string());
    let ifs_chars: Vec<char> = ifs.chars().collect();
    for token in tokens {
        if token.starts_with(OPERATOR_TOKEN_MARKER) {
            expanded.push(token);
            continue;
        }
        for brace_token in expand_braces(&token) {
            let value = expand_token(&brace_token, ctx)?;
            let fields = split_ifs_token(&value, &ifs_chars);
            if fields.is_empty() {
                continue;
            }
            expanded.extend(fields);
        }
    }
    Ok(expanded)
}

fn split_ifs_token(token: &str, ifs: &[char]) -> Vec<String> {
    if ifs.is_empty() {
        return vec![token.to_string()];
    }
    let mut fields = Vec::new();
    let mut buf = String::new();
    let mut chars = token.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            if let Some(next) = chars.next() {
                buf.push(ch);
                buf.push(next);
            } else {
                buf.push(ch);
            }
            continue;
        }
        if ifs.contains(&ch) {
            if !buf.is_empty() {
                fields.push(buf);
                buf = String::new();
            }
            continue;
        }
        buf.push(ch);
    }

    if !buf.is_empty() {
        fields.push(buf);
    }

    fields
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
                    return Ok(Some(format!("$({inner})")));
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
                    .to_string());
                }
                return Ok(Some(format!("${{{inner}")));
            }
            let param = parse_parameter(&inner)?;
            let name = strip_markers(param.name());
            let needs_validation = !matches!(param, Parameter::PrefixVars { .. });
            if needs_validation && !is_valid_var_name(&name) {
                if ctx.strict {
                    return Err(ShellError::new(
                        ErrorKind::Expansion,
                        format!("Invalid variable name: {}", name),
                    )
                    .with_context("Variable names must start with a letter or underscore, followed by letters, digits, or underscores")
                    .to_string());
                }
                return Ok(Some(format!("${{{inner}}}")));
            }
            match param {
                Parameter::Default { fallback, .. } => {
                    let value = (ctx.lookup_var)(&name).unwrap_or_default();
                    if !value.is_empty() {
                        return Ok(Some(value));
                    }
                    if let Some(fallback) = fallback {
                        return Ok(Some(expand_token(&fallback, ctx)?));
                    }
                    Ok(Some(String::new()))
                }
                Parameter::Pattern { op, pattern, .. } => {
                    let value = (ctx.lookup_var)(&name).unwrap_or_default();
                    let pattern = strip_markers(&pattern);
                    if pattern.is_empty() {
                        return Ok(Some(value));
                    }
                    let stripped = match op {
                        ParamOp::Prefix => remove_prefix_pattern(&value, &pattern)?,
                        ParamOp::Suffix => remove_suffix_pattern(&value, &pattern)?,
                    };
                    Ok(Some(stripped))
                }
                Parameter::Subst {
                    pattern,
                    replacement,
                    ..
                } => {
                    let value = (ctx.lookup_var)(&name).unwrap_or_default();
                    let pattern = strip_markers(&pattern);
                    let replacement = strip_markers(&replacement);
                    if pattern.is_empty() {
                        return Ok(Some(value));
                    }
                    let replaced = replace_first_pattern(&value, &pattern, &replacement)?;
                    Ok(Some(replaced))
                }
                Parameter::Array { index, length, .. } => {
                    let arr = (ctx.lookup_array)(&name);
                    if let Some(value) =
                        expand_array_ref(&name, index.as_deref(), length, ctx, arr)
                    {
                        return Ok(Some(value));
                    }
                    if let Some(map) = (ctx.lookup_assoc)(&name) {
                        if let Some(value) =
                            expand_assoc_ref(index.as_deref(), length, ctx, &map)
                        {
                            return Ok(Some(value));
                        }
                    }
                    Ok(Some(String::new()))
                }
                Parameter::Assoc { key, length, .. } => {
                    if let Some(map) = (ctx.lookup_assoc)(&name) {
                        if let Some(value) = expand_assoc_ref(Some(&key), length, ctx, &map) {
                            return Ok(Some(value));
                        }
                    }
                    Ok(Some(String::new()))
                }
                Parameter::AssocKeys { .. } => {
                    if let Some(map) = (ctx.lookup_assoc)(&name) {
                        let value = expand_assoc_keys(ctx, &map);
                        return Ok(Some(value));
                    }
                    Ok(Some(String::new()))
                }
                Parameter::PrefixVars { prefix } => {
                    let ifs = (ctx.lookup_var)("IFS").unwrap_or_else(|| " \t\n".to_string());
                    let sep = ifs.chars().next().unwrap_or(' ');
                    let mut keys: Vec<String> = std::env::vars()
                        .map(|(k, _)| k)
                        .filter(|k| k.starts_with(&prefix))
                        .collect();
                    keys.sort();
                    Ok(Some(keys.join(&sep.to_string())))
                }
                Parameter::Transform { op, .. } => {
                    let value = (ctx.lookup_var)(&name).unwrap_or_default();
                    Ok(Some(transform_value(&value, op)))
                }
                Parameter::Substring {
                    offset,
                    length,
                    ..
                } => {
                    let value = (ctx.lookup_var)(&name).unwrap_or_default();
                    Ok(Some(substring_value(&value, offset, length)))
                }
                Parameter::Simple { length, .. } => {
                    if length {
                        let value = (ctx.lookup_var)(&name).unwrap_or_default();
                        return Ok(Some(value.chars().count().to_string()));
                    }
                    Ok(Some((ctx.lookup_var)(&name).unwrap_or_default()))
                }
            }
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

enum ParamOp {
    Prefix,
    Suffix,
}

enum Parameter {
    Simple { name: String, length: bool },
    Default { name: String, fallback: Option<String> },
    Pattern { name: String, op: ParamOp, pattern: String },
    Subst {
        name: String,
        pattern: String,
        replacement: String,
    },
    Array { name: String, index: Option<String>, length: bool },
    Assoc { name: String, key: String, length: bool },
    AssocKeys { name: String },
    PrefixVars { prefix: String },
    Transform { name: String, op: TransformOp },
    Substring {
        name: String,
        offset: usize,
        length: Option<usize>,
    },
}

impl Parameter {
    fn name(&self) -> &str {
        match self {
            Parameter::Simple { name, .. } => name,
            Parameter::Default { name, .. } => name,
            Parameter::Pattern { name, .. } => name,
            Parameter::Subst { name, .. } => name,
            Parameter::Array { name, .. } => name,
            Parameter::Assoc { name, .. } => name,
            Parameter::AssocKeys { name, .. } => name,
            Parameter::Transform { name, .. } => name,
            Parameter::Substring { name, .. } => name,
            Parameter::PrefixVars { .. } => "",
        }
    }
}

fn parse_parameter(input: &str) -> Result<Parameter, String> {
    if let Some((name, fallback)) = input.split_once(":-") {
        return Ok(Parameter::Default {
            name: name.to_string(),
            fallback: Some(fallback.to_string()),
        });
    }

    if let Some(inner) = input.strip_prefix('!') {
        if inner.ends_with('*') && !inner.contains('[') {
            let prefix = inner.trim_end_matches('*').to_string();
            return Ok(Parameter::PrefixVars { prefix });
        }
        if let Some((name, idx)) = parse_array_ref(inner) {
            if matches!(idx.as_deref(), Some("@") | Some("*")) {
                return Ok(Parameter::AssocKeys { name });
            }
        }
    }

    let (length, inner) = if let Some(rest) = input.strip_prefix('#') {
        (true, rest)
    } else {
        (false, input)
    };

    if let Some((name, index)) = parse_array_ref(inner) {
        if let Some(ref key) = index {
            if key != "@" && key != "*" && key.parse::<usize>().is_err() {
                return Ok(Parameter::Assoc {
                    name,
                    key: key.clone(),
                    length,
                });
            }
        }
        return Ok(Parameter::Array {
            name,
            index,
            length,
        });
    }

    if let Some((name, offset, length)) = parse_substring(inner) {
        return Ok(Parameter::Substring {
            name,
            offset,
            length,
        });
    }

    if let Some((name, pattern, replacement)) = parse_subst(inner) {
        return Ok(Parameter::Subst {
            name,
            pattern,
            replacement,
        });
    }

    if let Some((name, pattern)) = inner.split_once('#') {
        return Ok(Parameter::Pattern {
            name: name.to_string(),
            op: ParamOp::Prefix,
            pattern: pattern.to_string(),
        });
    }

    if let Some((name, pattern)) = inner.split_once('%') {
        return Ok(Parameter::Pattern {
            name: name.to_string(),
            op: ParamOp::Suffix,
            pattern: pattern.to_string(),
        });
    }

    if let Some((name, op)) = parse_transform(inner) {
        return Ok(Parameter::Transform { name, op });
    }

    Ok(Parameter::Simple {
        name: inner.to_string(),
        length,
    })
}

fn parse_array_ref(input: &str) -> Option<(String, Option<String>)> {
    let open = input.find('[')?;
    if !input.ends_with(']') {
        return None;
    }
    let name = &input[..open];
    let inner = &input[open + 1..input.len() - 1];
    let index = if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    };
    Some((name.to_string(), index))
}

fn parse_subst(input: &str) -> Option<(String, String, String)> {
    let mut parts = input.splitn(3, '/');
    let name = parts.next()?.to_string();
    let pattern = parts.next()?.to_string();
    let replacement = parts.next().unwrap_or("").to_string();
    if name.is_empty() {
        return None;
    }
    Some((name, pattern, replacement))
}

#[derive(Copy, Clone)]
enum TransformOp {
    UpperAll,
    LowerAll,
    UpperFirst,
    LowerFirst,
    Toggle,
}

fn parse_transform(input: &str) -> Option<(String, TransformOp)> {
    if let Some(name) = input.strip_suffix("^^") {
        return Some((name.to_string(), TransformOp::UpperAll));
    }
    if let Some(name) = input.strip_suffix(",,") {
        return Some((name.to_string(), TransformOp::LowerAll));
    }
    if let Some(name) = input.strip_suffix('^') {
        return Some((name.to_string(), TransformOp::UpperFirst));
    }
    if let Some(name) = input.strip_suffix(',') {
        return Some((name.to_string(), TransformOp::LowerFirst));
    }
    if let Some(name) = input.strip_suffix('~') {
        return Some((name.to_string(), TransformOp::Toggle));
    }
    None
}

fn parse_substring(input: &str) -> Option<(String, usize, Option<usize>)> {
    let (name, rest) = input.split_once(':')?;
    if name.is_empty() {
        return None;
    }
    if rest.starts_with('-') {
        return None;
    }
    let (offset_str, len_str) = if let Some((off, len)) = rest.split_once(':') {
        (off, Some(len))
    } else {
        (rest, None)
    };
    let offset = offset_str.parse::<usize>().ok()?;
    let length = match len_str {
        Some(s) if !s.is_empty() => Some(s.parse::<usize>().ok()?),
        Some(_) => None,
        None => None,
    };
    Some((name.to_string(), offset, length))
}

fn expand_array_ref(
    _name: &str,
    index: Option<&str>,
    length: bool,
    ctx: &ExpansionContext<'_>,
    array: Option<Vec<String>>,
) -> Option<String> {
    let values = array?;
    match index {
        Some("@") | Some("*") => {
            if length {
                return Some(values.len().to_string());
            }
            let ifs = (ctx.lookup_var)("IFS").unwrap_or_else(|| " \t\n".to_string());
            let sep = ifs.chars().next().unwrap_or(' ');
            return Some(values.join(&sep.to_string()));
        }
        Some(idx_str) => {
            let idx = idx_str.parse::<usize>().ok()?;
            let value = values.get(idx).cloned().unwrap_or_default();
            if length {
                return Some(value.chars().count().to_string());
            }
            return Some(value);
        }
        None => {
            if length {
                return Some(values.len().to_string());
            }
            let ifs = (ctx.lookup_var)("IFS").unwrap_or_else(|| " \t\n".to_string());
            let sep = ifs.chars().next().unwrap_or(' ');
            return Some(values.join(&sep.to_string()));
        }
    }
}

fn expand_assoc_ref(
    index: Option<&str>,
    length: bool,
    ctx: &ExpansionContext<'_>,
    map: &std::collections::HashMap<String, String>,
) -> Option<String> {
    match index {
        Some("@") | Some("*") | None => {
            if length {
                return Some(map.len().to_string());
            }
            let ifs = (ctx.lookup_var)("IFS").unwrap_or_else(|| " \t\n".to_string());
            let sep = ifs.chars().next().unwrap_or(' ');
            let values: Vec<String> = map.values().cloned().collect();
            Some(values.join(&sep.to_string()))
        }
        Some(key) => {
            let value = map.get(key).cloned().unwrap_or_default();
            if length {
                return Some(value.chars().count().to_string());
            }
            Some(value)
        }
    }
}

fn expand_assoc_keys(ctx: &ExpansionContext<'_>, map: &std::collections::HashMap<String, String>) -> String {
    let ifs = (ctx.lookup_var)("IFS").unwrap_or_else(|| " \t\n".to_string());
    let sep = ifs.chars().next().unwrap_or(' ');
    let keys: Vec<String> = map.keys().cloned().collect();
    keys.join(&sep.to_string())
}

fn transform_value(value: &str, op: TransformOp) -> String {
    match op {
        TransformOp::UpperAll => value.chars().flat_map(|c| c.to_uppercase()).collect(),
        TransformOp::LowerAll => value.chars().flat_map(|c| c.to_lowercase()).collect(),
        TransformOp::UpperFirst => {
            let mut chars = value.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            let mut out: String = first.to_uppercase().collect();
            out.push_str(chars.as_str());
            out
        }
        TransformOp::LowerFirst => {
            let mut chars = value.chars();
            let Some(first) = chars.next() else {
                return String::new();
            };
            let mut out: String = first.to_lowercase().collect();
            out.push_str(chars.as_str());
            out
        }
        TransformOp::Toggle => value
            .chars()
            .map(|c| {
                if c.is_lowercase() {
                    c.to_uppercase().collect::<String>()
                } else if c.is_uppercase() {
                    c.to_lowercase().collect::<String>()
                } else {
                    c.to_string()
                }
            })
            .collect(),
    }
}

fn substring_value(value: &str, offset: usize, length: Option<usize>) -> String {
    let chars: Vec<char> = value.chars().collect();
    if offset >= chars.len() {
        return String::new();
    }
    let end = match length {
        Some(len) => std::cmp::min(chars.len(), offset + len),
        None => chars.len(),
    };
    chars[offset..end].iter().collect()
}

fn replace_first_pattern(value: &str, pattern: &str, replacement: &str) -> Result<String, String> {
    let matcher = Pattern::new(pattern).map_err(|err| format!("invalid pattern: {err}"))?;
    let indices: Vec<usize> = value
        .char_indices()
        .map(|(idx, _)| idx)
        .chain(std::iter::once(value.len()))
        .collect();
    for (i, &start) in indices.iter().enumerate() {
        for &end in indices.iter().skip(i) {
            let slice = &value[start..end];
            if matcher.matches(slice) {
                let mut out = String::new();
                out.push_str(&value[..start]);
                out.push_str(replacement);
                out.push_str(&value[end..]);
                return Ok(out);
            }
        }
    }
    Ok(value.to_string())
}

fn remove_prefix_pattern(value: &str, pattern: &str) -> Result<String, String> {
    let matcher = Pattern::new(pattern).map_err(|err| format!("invalid pattern: {err}"))?;
    let indices: Vec<usize> = value
        .char_indices()
        .map(|(idx, _)| idx)
        .chain(std::iter::once(value.len()))
        .collect();
    for &end in &indices {
        let prefix = &value[..end];
        if matcher.matches(prefix) {
            return Ok(value[end..].to_string());
        }
    }
    Ok(value.to_string())
}

fn remove_suffix_pattern(value: &str, pattern: &str) -> Result<String, String> {
    let matcher = Pattern::new(pattern).map_err(|err| format!("invalid pattern: {err}"))?;
    let indices: Vec<usize> = value
        .char_indices()
        .map(|(idx, _)| idx)
        .chain(std::iter::once(value.len()))
        .collect();
    for &start in indices.iter().rev() {
        let suffix = &value[start..];
        if matcher.matches(suffix) {
            return Ok(value[..start].to_string());
        }
    }
    Ok(value.to_string())
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
    use crate::parse::strip_markers;
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
            lookup_array: Box::new(|_| None),
            lookup_assoc: Box::new(|_| None),
            command_subst: Box::new(|_| Ok(String::new())),
            positional: &[],
            strict: true,
        }
    }

    fn ctx_with_array(name: &'static str, values: Vec<String>) -> ExpansionContext<'static> {
        ExpansionContext {
            lookup_var: Box::new(|_| None),
            lookup_array: Box::new(move |key| {
                if key == name {
                    Some(values.clone())
                } else {
                    None
                }
            }),
            lookup_assoc: Box::new(|_| None),
            command_subst: Box::new(|_| Ok(String::new())),
            positional: &[],
            strict: true,
        }
    }

    fn ctx_with_assoc(
        name: &'static str,
        values: Vec<(&'static str, &'static str)>,
    ) -> ExpansionContext<'static> {
        let mut map = std::collections::HashMap::new();
        for (k, v) in values {
            map.insert(k.to_string(), v.to_string());
        }
        ExpansionContext {
            lookup_var: Box::new(|_| None),
            lookup_array: Box::new(|_| None),
            lookup_assoc: Box::new(move |key| {
                if key == name {
                    Some(map.clone())
                } else {
                    None
                }
            }),
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
    fn expand_parameter_prefix_pattern() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_PATTERN";
        with_env_var(key, "foobar", || {
            let token = format!("${{{key}#foo*}}");
            assert_eq!(expand_token(&token, &ctx).unwrap(), "bar");
        });
    }

    #[test]
    fn expand_parameter_suffix_pattern() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_PATTERN";
        with_env_var(key, "foobar", || {
            let token = format!("${{{key}%*bar}}");
            assert_eq!(expand_token(&token, &ctx).unwrap(), "foo");
        });
    }

    #[test]
    fn expand_array_index() {
        let ctx = ctx_with_array("arr", vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(expand_token("${arr[1]}", &ctx).unwrap(), "b");
    }

    #[test]
    fn expand_array_length() {
        let ctx = ctx_with_array("arr", vec!["a".into(), "bb".into()]);
        assert_eq!(expand_token("${#arr[@]}", &ctx).unwrap(), "2");
        assert_eq!(expand_token("${#arr[1]}", &ctx).unwrap(), "2");
    }

    #[test]
    fn expand_assoc_lookup() {
        let ctx = ctx_with_assoc("map", vec![("k1", "v1"), ("k2", "v2")]);
        assert_eq!(expand_token("${map[k1]}", &ctx).unwrap(), "v1");
    }

    #[test]
    fn expand_assoc_keys() {
        let ctx = ctx_with_assoc("map", vec![("k1", "v1"), ("k2", "v2")]);
        let expanded = expand_token("${!map[@]}", &ctx).unwrap();
        let parts: Vec<_> = expanded.split_whitespace().collect();
        assert_eq!(parts.len(), 2);
        assert!(parts.contains(&"k1"));
        assert!(parts.contains(&"k2"));
    }

    #[test]
    fn expand_transform_upper_lower() {
        let ctx = ctx_no_subst();
        with_env_var("CS_TEST_CASE", "abC", || {
            assert_eq!(expand_token("${CS_TEST_CASE^^}", &ctx).unwrap(), "ABC");
            assert_eq!(expand_token("${CS_TEST_CASE,,}", &ctx).unwrap(), "abc");
            assert_eq!(expand_token("${CS_TEST_CASE^}", &ctx).unwrap(), "AbC");
            assert_eq!(expand_token("${CS_TEST_CASE,}", &ctx).unwrap(), "abC");
        });
    }

    #[test]
    fn expand_substring_offsets() {
        let ctx = ctx_no_subst();
        with_env_var("CS_TEST_SUB", "abcdef", || {
            assert_eq!(expand_token("${CS_TEST_SUB:2}", &ctx).unwrap(), "cdef");
            assert_eq!(expand_token("${CS_TEST_SUB:1:3}", &ctx).unwrap(), "bcd");
        });
    }

    #[test]
    fn expand_prefix_vars() {
        let ctx = ctx_no_subst();
        with_env_var("CS_PREFIX_ONE", "1", || {
            with_env_var("CS_PREFIX_TWO", "2", || {
                let expanded = expand_token("${!CS_PREFIX_*}", &ctx).unwrap();
                let parts: Vec<_> = expanded.split_whitespace().collect();
                assert!(parts.contains(&"CS_PREFIX_ONE"));
                assert!(parts.contains(&"CS_PREFIX_TWO"));
            });
        });
    }

    #[test]
    fn expand_parameter_subst_first_match() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_SUBST";
        with_env_var(key, "foo-bar-baz", || {
            let token = format!("${{{key}/-/_}}");
            assert_eq!(expand_token(&token, &ctx).unwrap(), "foo_bar-baz");
        });
    }

    #[test]
    fn escaped_operator_is_literal() {
        let ctx = ctx_no_subst();
        let token = format!("foo{ESCAPE_MARKER}|bar");
        assert_eq!(expand_token(&token, &ctx).unwrap(), "foo|bar");
    }

    #[test]
    fn ifs_splits_unquoted_fields() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_IFS";
        with_env_var("IFS", ":", || {
            with_env_var(key, "a:b:c", || {
                let tokens = vec![format!("${key}")];
                let expanded = expand_tokens(tokens, &ctx).unwrap();
                assert_eq!(expanded, vec!["a", "b", "c"]);
            });
        });
    }

    #[test]
    fn ifs_does_not_split_quoted_segments() {
        let ctx = ctx_no_subst();
        let key = "CS_TEST_IFS";
        with_env_var("IFS", ":", || {
            with_env_var(key, "a:b", || {
                let tokens = vec![format!("\"${key}\"")];
                let expanded = expand_tokens(tokens, &ctx).unwrap();
                assert_eq!(strip_markers(&expanded[0]), "a:b");
                assert_eq!(expanded.len(), 1);
            });
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
            "{ESCAPE_MARKER}{{{{ESCAPE_MARKER}}a{ESCAPE_MARKER},{ESCAPE_MARKER}b{ESCAPE_MARKER}}}}}"
        );
        let expanded = expand_tokens(vec![token], &ctx).unwrap();
    assert_eq!(strip_markers(&expanded[0]), "{a,b}");
    }
}

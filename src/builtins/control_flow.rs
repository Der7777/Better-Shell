use std::io;
use std::sync::Arc;

use glob::Pattern;

use crate::expansion::{expand_globs, expand_tokens};
use crate::io_helpers::read_input_line;
use crate::parse::{parse_line, token_str, OPERATOR_TOKEN_MARKER};
use crate::process_subst::{apply_process_subst, FdGuard, ProcessSubstResult};
use crate::{build_expansion_context, trace_tokens, ShellState};

use super::scripting::execute_script_tokens;

#[derive(Copy, Clone)]
pub(crate) enum CompoundKind {
    If,
    While,
    For,
    Select,
    Case,
    Function,
    Brace,
}

pub(crate) fn is_if_start(tokens: &[String]) -> bool {
    tokens.first().map(String::as_str) == Some("if")
}

pub(crate) fn is_while_start(tokens: &[String]) -> bool {
    tokens.first().map(String::as_str) == Some("while")
}

pub(crate) fn is_for_start(tokens: &[String]) -> bool {
    tokens.first().map(String::as_str) == Some("for")
}

pub(crate) fn is_select_start(tokens: &[String]) -> bool {
    tokens.first().map(String::as_str) == Some("select")
}

pub(crate) fn is_case_start(tokens: &[String]) -> bool {
    tokens.first().map(String::as_str) == Some("case")
}

pub(crate) fn is_brace_group_start(tokens: &[String]) -> bool {
    tokens.first().map(String::as_str) == Some("{")
}

pub(crate) fn read_compound_tokens(
    state: &mut ShellState,
    mut tokens: Vec<String>,
    kind: CompoundKind,
) -> io::Result<Vec<String>> {
    // Interactive loop collects lines until the compound is complete.
    while needs_more_compound(&tokens, kind) {
        let line = match read_input_line(&mut state.editor, state.interactive, "> ")? {
            Some(line) => line,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
        };
        let more = parse_line(line.trim_end()).map_err(|err| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("parse error: {err}"))
        })?;
        if !more.is_empty() {
            tokens.push(format!("{OPERATOR_TOKEN_MARKER};"));
            tokens.extend(more);
        }
    }
    Ok(tokens)
}

fn needs_more_compound(tokens: &[String], kind: CompoundKind) -> bool {
    // Count open/close keywords to handle nesting across multi-line compounds.
    let mut if_count = 0i32;
    let mut while_count = 0i32;
    let mut for_count = 0i32;
    let mut case_count = 0i32;
    let mut select_count = 0i32;
    // Function bodies are delimited by braces, not keywords like "fi".
    let mut brace_count = 0i32;
    for token in tokens {
        let t = token_str(token);
        match t {
            "if" => if_count += 1,
            "fi" => if_count -= 1,
            "while" => while_count += 1,
            "done" => {
                while_count -= 1;
                for_count -= 1;
            }
            "for" => for_count += 1,
            "select" => select_count += 1,
            "case" => case_count += 1,
            "esac" => case_count -= 1,
            "{" => brace_count += 1,
            "}" => brace_count -= 1,
            _ => {}
        }
    }
    match kind {
        CompoundKind::If => if_count > 0,
        CompoundKind::While => while_count > 0,
        CompoundKind::For => for_count > 0,
        CompoundKind::Select => select_count > 0,
        CompoundKind::Case => case_count > 0,
        CompoundKind::Function | CompoundKind::Brace => brace_count > 0,
    }
}

pub(crate) fn execute_if(
    state: &mut ShellState,
    tokens: Vec<String>,
    display: &str,
) -> io::Result<()> {
    let (cond_tokens, then_tokens, else_tokens) = parse_if_tokens(tokens)?;
    execute_script_tokens(state, cond_tokens)?;
    if state.last_status == 0 {
        execute_script_tokens(state, then_tokens)?;
    } else if let Some(tokens) = else_tokens {
        execute_script_tokens(state, tokens)?;
    }
    trace_tokens(state, "if display", &[display.to_string()]);
    Ok(())
}

pub(crate) fn execute_while(
    state: &mut ShellState,
    tokens: Vec<String>,
    _display: &str,
) -> io::Result<()> {
    let (cond_tokens, body_tokens) = parse_while_tokens(tokens)?;
    loop {
        execute_script_tokens(state, cond_tokens.clone())?;
        if state.last_status != 0 {
            break;
        }
        execute_script_tokens(state, body_tokens.clone())?;
    }
    Ok(())
}

pub(crate) fn execute_for(
    state: &mut ShellState,
    tokens: Vec<String>,
    _display: &str,
) -> io::Result<()> {
    let (var, list_tokens, body_tokens) = parse_for_tokens(tokens)?;
    let ctx = build_expansion_context(
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        &[],
        true,
    );
    let list_expanded = expand_tokens(list_tokens, &ctx)?;
    let list = expand_globs(list_expanded)?;
    for item in list {
        std::env::set_var(&var, item);
        execute_script_tokens(state, body_tokens.clone())?;
    }
    Ok(())
}

pub(crate) fn execute_select(
    state: &mut ShellState,
    tokens: Vec<String>,
    _display: &str,
) -> io::Result<()> {
    let (var, list_tokens, body_tokens) = parse_select_tokens(tokens)?;
    let ctx = build_expansion_context(
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        &[],
        true,
    );
    let expanded = expand_tokens(list_tokens, &ctx)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    let ProcessSubstResult { tokens: expanded, keep_fds } = apply_process_subst(
        expanded,
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        true,
    )?;
    let _fd_guard = FdGuard(keep_fds);
    let items = expand_globs(expanded)
        .map_err(|msg| io::Error::new(io::ErrorKind::InvalidInput, msg))?;
    let ps3 = std::env::var("PS3").unwrap_or_else(|_| "#? ".to_string());

    loop {
        for (idx, item) in items.iter().enumerate() {
            println!("{:>2}) {}", idx + 1, item);
        }
        let line = match read_input_line(&mut state.editor, state.interactive, &ps3)? {
            Some(line) => line,
            None => {
                state.last_status = 1;
                return Ok(());
            }
        };
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        std::env::set_var("REPLY", input);
        let selected = input
            .parse::<usize>()
            .ok()
            .and_then(|idx| items.get(idx.saturating_sub(1)).cloned())
            .unwrap_or_default();
        std::env::set_var(&var, selected);
        execute_script_tokens(state, body_tokens.clone())?;
    }
}

pub(crate) fn execute_brace_group(
    state: &mut ShellState,
    tokens: Vec<String>,
    _display: &str,
) -> io::Result<()> {
    if tokens.first().map(String::as_str) != Some("{")
        || tokens.last().map(String::as_str) != Some("}")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid brace group",
        ));
    }
    let mut inner = tokens[1..tokens.len() - 1].to_vec();
    if let Some(last) = inner.last() {
        if token_str(last) == ";" {
            inner.pop();
        }
    }
    if inner.is_empty() {
        state.last_status = 0;
        return Ok(());
    }
    execute_script_tokens(state, inner)
}

struct CaseClause {
    patterns: Vec<Vec<String>>,
    body: Vec<String>,
}

pub(crate) fn execute_case(
    state: &mut ShellState,
    tokens: Vec<String>,
    display: &str,
) -> io::Result<()> {
    let (word_tokens, clauses) = parse_case_tokens(tokens)?;
    let ctx = build_expansion_context(
        Arc::clone(&state.fg_pgid),
        state.trace,
        state.sandbox.clone(),
        state.arrays.clone(),
        &[],
        true,
    );
    let word_expanded = match expand_tokens(word_tokens, &ctx) {
        Ok(v) => v,
        Err(msg) => {
            state.last_status = 2;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("parse error: {msg}"),
            ));
        }
    };
    let word = word_expanded.join(" ");

    for clause in clauses {
        let mut matched = false;
        for pattern_tokens in clause.patterns {
            let pattern_expanded = match expand_tokens(pattern_tokens, &ctx) {
                Ok(v) => v,
                Err(msg) => {
                    state.last_status = 2;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("parse error: {msg}"),
                    ));
                }
            };
            let pattern = pattern_expanded.join(" ");
            let is_match = Pattern::new(&pattern)
                .map(|pat| pat.matches(&word))
                .unwrap_or_else(|_| pattern == word);
            if is_match {
                matched = true;
                break;
            }
        }
        if matched {
            execute_script_tokens(state, clause.body)?;
            trace_tokens(state, "case display", &[display.to_string()]);
            return Ok(());
        }
    }

    state.last_status = 0;
    trace_tokens(state, "case display", &[display.to_string()]);
    Ok(())
}

type IfParts = (Vec<String>, Vec<String>, Option<Vec<String>>);

fn parse_if_tokens(tokens: Vec<String>) -> io::Result<IfParts> {
    let iter = tokens.into_iter().peekable();
    let mut condition = Vec::new();
    let mut then_body = Vec::new();
    let mut else_body = None;
    let mut stage = "if";
    for token in iter {
        let t = token_str(&token).to_string();
        match stage {
            "if" => {
                if t == "then" {
                    stage = "then";
                } else if t == "if" {
                    continue;
                } else {
                    condition.push(token);
                }
            }
            "then" => {
                if t == "else" {
                    stage = "else";
                    else_body = Some(Vec::new());
                } else if t == "fi" {
                    break;
                } else {
                    then_body.push(token);
                }
            }
            "else" => {
                if t == "fi" {
                    break;
                }
                if let Some(ref mut body) = else_body {
                    body.push(token);
                }
            }
            _ => {}
        }
    }
    if condition.is_empty() || then_body.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid if statement",
        ));
    }
    Ok((condition, then_body, else_body))
}

fn parse_while_tokens(tokens: Vec<String>) -> io::Result<(Vec<String>, Vec<String>)> {
    let iter = tokens.into_iter().peekable();
    let mut condition = Vec::new();
    let mut body = Vec::new();
    let mut stage = "while";
    for token in iter {
        let t = token_str(&token).to_string();
        match stage {
            "while" => {
                if t == "do" {
                    stage = "do";
                } else if t == "while" {
                    continue;
                } else {
                    condition.push(token);
                }
            }
            "do" => {
                if t == "done" {
                    break;
                } else {
                    body.push(token);
                }
            }
            _ => {}
        }
    }
    if condition.is_empty() || body.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid while statement",
        ));
    }
    Ok((condition, body))
}

fn parse_for_tokens(tokens: Vec<String>) -> io::Result<(String, Vec<String>, Vec<String>)> {
    let mut iter = tokens.into_iter();
    let mut var = String::new();
    let mut list = Vec::new();
    let mut body = Vec::new();
    let mut stage = "for";
    while let Some(token) = iter.next() {
        let t = token_str(&token).to_string();
        match stage {
            "for" => {
                if t == "for" {
                    continue;
                } else {
                    var = token;
                    stage = "in";
                }
            }
            "in" => {
                if t == "in" {
                    stage = "list";
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "expected 'in' after for variable",
                    ));
                }
            }
            "list" => {
                if t == ";" || t == "do" {
                    if t == "do" {
                        stage = "do";
                    }
                    break;
                } else {
                    list.push(token);
                }
            }
            _ => {}
        }
    }
    if stage == "do" {
        for token in iter {
            let t = token_str(&token).to_string();
            if t == "done" {
                break;
            } else {
                body.push(token);
            }
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected 'do' in for statement",
        ));
    }
    if var.is_empty() || body.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid for statement",
        ));
    }
    Ok((var, list, body))
}

fn parse_select_tokens(tokens: Vec<String>) -> io::Result<(String, Vec<String>, Vec<String>)> {
    let mut iter = tokens.into_iter();
    let mut var = String::new();
    let mut list = Vec::new();
    let mut body = Vec::new();
    let mut stage = "select";
    while let Some(token) = iter.next() {
        let t = token_str(&token).to_string();
        match stage {
            "select" => {
                if t == "select" {
                    continue;
                } else {
                    var = token;
                    stage = "in";
                }
            }
            "in" => {
                if t == "in" {
                    stage = "list";
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "expected 'in' after select variable",
                    ));
                }
            }
            "list" => {
                if t == ";" || t == "do" {
                    if t == "do" {
                        stage = "do";
                    }
                    break;
                } else {
                    list.push(token);
                }
            }
            _ => {}
        }
    }
    if stage == "do" {
        for token in iter {
            let t = token_str(&token).to_string();
            if t == "done" {
                break;
            } else {
                body.push(token);
            }
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected 'do' in select statement",
        ));
    }
    if var.is_empty() || body.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid select statement",
        ));
    }
    Ok((var, list, body))
}

fn parse_case_tokens(tokens: Vec<String>) -> io::Result<(Vec<String>, Vec<CaseClause>)> {
    if tokens.len() < 4 || tokens[0] != "case" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid case statement",
        ));
    }
    let mut idx = 1usize;
    let mut word_tokens = Vec::new();
    while idx < tokens.len() {
        let t = token_str(&tokens[idx]);
        if t == "in" {
            idx += 1;
            break;
        }
        word_tokens.push(tokens[idx].clone());
        idx += 1;
    }
    if word_tokens.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid case statement",
        ));
    }

    let mut clauses = Vec::new();
    let mut saw_esac = false;
    while idx < tokens.len() {
        let t = token_str(&tokens[idx]);
        if t == "esac" {
            saw_esac = true;
            break;
        }

        let mut patterns = Vec::new();
        let mut current_pattern = Vec::new();
        let mut found_paren = false;
        while idx < tokens.len() {
            let raw = tokens[idx].clone();
            let raw_str = token_str(&raw);
            if raw_str == "|" {
                if current_pattern.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid case statement",
                    ));
                }
                patterns.push(current_pattern);
                current_pattern = Vec::new();
                idx += 1;
                continue;
            }
            if raw_str == ")" || raw_str.ends_with(')') {
                let mut trimmed = raw.clone();
                if raw_str == ")" {
                    // No-op; pattern already collected.
                } else if trimmed.pop() != Some(')') {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid case statement",
                    ));
                }
                if !trimmed.is_empty() {
                    current_pattern.push(trimmed);
                }
                if current_pattern.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "invalid case statement",
                    ));
                }
                patterns.push(current_pattern);
                idx += 1;
                found_paren = true;
                break;
            }
            current_pattern.push(raw);
            idx += 1;
        }
        if !found_paren {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid case statement",
            ));
        }

        let mut body = Vec::new();
        while idx < tokens.len() {
            let raw = tokens[idx].clone();
            let raw_str = token_str(&raw);
            if raw_str == "esac" {
                saw_esac = true;
                idx += 1;
                break;
            }
            if raw_str == ";"
                && idx + 1 < tokens.len()
                && token_str(&tokens[idx + 1]) == ";"
            {
                idx += 2;
                break;
            }
            body.push(raw);
            idx += 1;
        }
        if body.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid case statement",
            ));
        }
        clauses.push(CaseClause { patterns, body });

        if saw_esac {
            break;
        }
    }

    if !saw_esac {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid case statement",
        ));
    }

    Ok((word_tokens, clauses))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_line;

    #[test]
    fn parse_case_basic() {
        let tokens = parse_line("case x in foo) echo hi ;; esac").unwrap();
        let (word, clauses) = parse_case_tokens(tokens).unwrap();
        assert_eq!(word, vec!["x"]);
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].patterns.len(), 1);
        assert_eq!(clauses[0].patterns[0], vec!["foo"]);
        assert_eq!(token_str(&clauses[0].body[0]), "echo");
        assert_eq!(token_str(&clauses[0].body[1]), "hi");
    }

    #[test]
    fn parse_case_multi_pattern() {
        let tokens = parse_line("case x in foo | bar ) echo hi ;; esac").unwrap();
        let (_, clauses) = parse_case_tokens(tokens).unwrap();
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].patterns.len(), 2);
        assert_eq!(clauses[0].patterns[0], vec!["foo"]);
        assert_eq!(clauses[0].patterns[1], vec!["bar"]);
    }
}

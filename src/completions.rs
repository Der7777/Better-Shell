use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::process::Command;

use crate::parse::parse_line;

const BUILTIN_COMMANDS: &[&str] = &[
    "cd", "pwd", "jobs", "fg", "bg", "help", "exit", "set", "abbr", "complete",
];

#[derive(Clone, Debug, Default)]
pub struct CompletionSpec {
    pub static_items: Vec<String>,
    pub dynamic_commands: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CompletionSet {
    pub entries: HashMap<String, CompletionSpec>,
}

impl CompletionSet {
    pub fn add_static(&mut self, command: &str, items: Vec<String>) {
        let spec = self.entries.entry(command.to_string()).or_default();
        spec.static_items.extend(items);
        spec.static_items.sort();
        spec.static_items.dedup();
    }

    pub fn add_dynamic(&mut self, command: &str, script: String) {
        let spec = self.entries.entry(command.to_string()).or_default();
        if !spec.dynamic_commands.contains(&script) {
            spec.dynamic_commands.push(script);
        }
    }

    pub fn remove(&mut self, command: &str) -> bool {
        self.entries.remove(command).is_some()
    }
}

pub fn default_completions() -> CompletionSet {
    let mut set = CompletionSet::default();
    set.add_static(
        "git",
        vec![
            "add", "branch", "checkout", "clone", "commit", "diff", "fetch", "init", "log",
            "merge", "pull", "push", "rebase", "reset", "restore", "show", "status", "--help",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect(),
    );
    set.add_dynamic("git", "git branch --format='%(refname:short)'".to_string());
    set.add_static(
        "ls",
        vec![
            "-a",
            "-l",
            "-h",
            "-t",
            "-r",
            "--all",
            "--long",
            "--human-readable",
            "--help",
        ]
        .into_iter()
        .map(|s| s.to_string())
        .collect(),
    );
    set.add_static(
        "cd",
        vec!["-", "~"].into_iter().map(|s| s.to_string()).collect(),
    );
    set
}

pub fn load_completion_files(set: &mut CompletionSet) -> io::Result<()> {
    if let Some(home) = env::var("HOME").ok() {
        let path = format!("{home}/.minishell_completions");
        if let Ok(content) = fs::read_to_string(&path) {
            parse_completion_lines(&content, set);
        }
        let fish_dir = format!("{home}/.config/fish/completions");
        if let Ok(entries) = fs::read_dir(&fish_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|ext| ext.to_str()) != Some("fish") {
                    continue;
                }
                if let Ok(content) = fs::read_to_string(path) {
                    parse_completion_lines(&content, set);
                }
            }
        }
    }
    Ok(())
}

fn parse_completion_lines(content: &str, set: &mut CompletionSet) {
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("complete ") {
            continue;
        }
        if let Ok(tokens) = parse_line(line) {
            let _ = apply_completion_tokens(&tokens, set);
        }
    }
}

pub fn apply_completion_tokens(tokens: &[String], set: &mut CompletionSet) -> Result<(), String> {
    if tokens.is_empty() || tokens[0] != "complete" {
        return Err("not a completion line".to_string());
    }
    let mut command: Option<String> = None;
    let mut static_items: Vec<String> = Vec::new();
    let mut dynamic_items: Vec<String> = Vec::new();
    let mut remove = false;
    let mut i = 1;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "-c" | "--command" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("complete: missing command after -c".to_string());
                }
                command = Some(tokens[i].clone());
            }
            "-a" | "--arguments" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("complete: missing arguments after -a".to_string());
                }
                while i < tokens.len() && !is_completion_flag(&tokens[i]) {
                    static_items.extend(
                        tokens[i]
                            .split_whitespace()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>(),
                    );
                    i += 1;
                }
                if i < tokens.len() {
                    i -= 1;
                }
            }
            "-x" | "--dynamic" => {
                i += 1;
                if i >= tokens.len() {
                    return Err("complete: missing command after -x".to_string());
                }
                dynamic_items.push(tokens[i].clone());
            }
            "-r" | "--remove" => {
                remove = true;
            }
            _ => {}
        }
        i += 1;
    }
    let command = command.ok_or_else(|| "complete: missing -c command".to_string())?;
    if remove {
        set.remove(&command);
        return Ok(());
    }
    if !static_items.is_empty() {
        set.add_static(&command, static_items);
    }
    for script in dynamic_items {
        set.add_dynamic(&command, script);
    }
    Ok(())
}

pub fn format_completion_lines(set: &CompletionSet) -> Vec<String> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = set.entries.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    for (name, spec) in entries {
        if !spec.static_items.is_empty() {
            let items = spec
                .static_items
                .iter()
                .map(|item| shell_quote(item))
                .collect::<Vec<_>>()
                .join(" ");
            out.push(format!("complete -c {name} -a '{items}'"));
        }
        for script in &spec.dynamic_commands {
            out.push(format!("complete -c {name} -x {}", shell_quote(script)));
        }
    }
    out
}

pub fn save_completion_file(set: &CompletionSet) -> io::Result<()> {
    let Some(home) = env::var("HOME").ok() else {
        return Ok(());
    };
    let path = format!("{home}/.minishell_completions");
    let content = format_completion_lines(set).join("\n");
    fs::write(
        path,
        if content.is_empty() {
            content
        } else {
            format!("{content}\n")
        },
    )
}

pub fn completion_candidates(set: &CompletionSet, command: &str) -> Vec<String> {
    let Some(spec) = set.entries.get(command) else {
        return vec!["--help".to_string(), "-h".to_string()];
    };
    let mut out = spec.static_items.clone();
    out.push("--help".to_string());
    out.push("-h".to_string());
    for script in &spec.dynamic_commands {
        if let Ok(output) = Command::new("sh").arg("-c").arg(script).output() {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    if let Some(rest) = trimmed.strip_prefix("* ") {
                        out.push(rest.to_string());
                    } else {
                        out.push(trimmed.to_string());
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

pub fn suggest_command(
    name: &str,
    aliases: &HashMap<String, Vec<String>>,
    functions: &HashMap<String, Vec<String>>,
    abbreviations: &HashMap<String, Vec<String>>,
    completions: &CompletionSet,
) -> Option<String> {
    let mut candidates = Vec::new();
    candidates.extend(BUILTIN_COMMANDS.iter().map(|s| s.to_string()));
    candidates.extend(aliases.keys().cloned());
    candidates.extend(functions.keys().cloned());
    candidates.extend(abbreviations.keys().cloned());
    candidates.extend(completions.entries.keys().cloned());
    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            if let Ok(read) = fs::read_dir(dir) {
                for entry in read.flatten() {
                    if let Ok(name) = entry.file_name().into_string() {
                        candidates.push(name);
                    }
                }
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    best_suggestion(name, &candidates)
}

fn best_suggestion(token: &str, candidates: &[String]) -> Option<String> {
    let mut best_prefix: Option<&String> = None;
    for candidate in candidates {
        if candidate.starts_with(token) {
            best_prefix = match best_prefix {
                Some(current) if current.len() <= candidate.len() => Some(current),
                _ => Some(candidate),
            };
        }
    }
    if let Some(candidate) = best_prefix {
        return Some(candidate.clone());
    }
    let mut best = None;
    let mut best_dist = usize::MAX;
    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }
        let dist = edit_distance(token, candidate, 2);
        if dist <= 2 && dist < best_dist {
            best_dist = dist;
            best = Some(candidate.clone());
        }
    }
    best
}

fn edit_distance(a: &str, b: &str, max: usize) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let alen = a_bytes.len();
    let blen = b_bytes.len();
    if alen == 0 {
        return blen;
    }
    if blen == 0 {
        return alen;
    }
    let mut prev: Vec<usize> = (0..=blen).collect();
    let mut cur = vec![0; blen + 1];
    for i in 1..=alen {
        cur[0] = i;
        let mut row_min = cur[0];
        for j in 1..=blen {
            let cost = if a_bytes[i - 1] == b_bytes[j - 1] {
                0
            } else {
                1
            };
            let insert = cur[j - 1] + 1;
            let delete = prev[j] + 1;
            let replace = prev[j - 1] + cost;
            let value = insert.min(delete).min(replace);
            cur[j] = value;
            if value < row_min {
                row_min = value;
            }
        }
        if row_min > max {
            return row_min;
        }
        prev.clone_from(&cur);
    }
    prev[blen]
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

fn is_completion_flag(token: &str) -> bool {
    matches!(
        token,
        "-c" | "--command" | "-a" | "--arguments" | "-x" | "--dynamic" | "-r" | "--remove"
    )
}

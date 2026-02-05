use std::collections::HashMap;

use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{Highlighter, MatchingBracketHighlighter};
use rustyline::hint::Hinter;
use rustyline::history::SearchDirection;
use rustyline::validate::{MatchingBracketValidator, Validator};
use rustyline::{Context, Helper};

#[cfg(feature = "tree-sitter")]
use tree_sitter::Parser;
#[cfg(feature = "tree-sitter")]
use tree_sitter_bash;
#[cfg(feature = "tree-sitter")]
use tree_sitter_highlight::{HighlightConfiguration, HighlightEvent, Highlighter as TSHighlighter};

use std::cell::RefCell;

use crate::colors::{resolve_color, ColorConfig};
use crate::completions::{completion_candidates, CompletionSet};

pub(crate) mod matching;
mod suggestions;

pub use suggestions::update_completion_context;

use crate::completion::matching::best_suggestion;
use crate::completion::suggestions::{
    command_for_position, complete_from_list, current_token, is_command_position,
};
pub struct SyntaxHighlighter {
    bracket_highlighter: MatchingBracketHighlighter,
    ts_highlighter: RefCell<TSHighlighter>,
    config: HighlightConfiguration,
}

#[cfg(feature = "tree-sitter")]
impl SyntaxHighlighter {
    pub fn new() -> Self {
        let highlight_query = "";
        let mut config =
            HighlightConfiguration::new(tree_sitter_bash::language(), highlight_query, "", "")
                .unwrap();
        config.configure(&[
            "attribute",
            "constant",
            "function.builtin",
            "function",
            "keyword",
            "operator",
            "property",
            "punctuation",
            "punctuation.bracket",
            "punctuation.delimiter",
            "string",
            "string.special",
            "tag",
            "type",
            "type.builtin",
            "variable",
            "variable.builtin",
            "variable.parameter",
        ]);
        Self {
            bracket_highlighter: MatchingBracketHighlighter::new(),
            ts_highlighter: RefCell::new(TSHighlighter::new()),
            config,
        }
    }
}

#[cfg(feature = "tree-sitter")]
impl Highlighter for SyntaxHighlighter {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> std::borrow::Cow<'l, str> {
        let mut parser = Parser::new();
        parser.set_language(tree_sitter_bash::language()).unwrap();
        let _tree = parser.parse(line, None).unwrap();
        let highlights = {
            let mut highlighter = self.ts_highlighter.borrow_mut();
            highlighter
                .highlight(&self.config, line.as_bytes(), None, |_| None)
                .unwrap()
                .collect::<Vec<_>>()
        };
        let mut result = String::new();
        let mut current_highlight: Option<usize> = None;
        for event in highlights {
            match event.unwrap() {
                HighlightEvent::HighlightStart(s) => {
                    current_highlight = Some(s.0);
                }
                HighlightEvent::HighlightEnd => {
                    current_highlight = None;
                }
                HighlightEvent::Source { start, end } => {
                    let text = &line[start..end];
                    if let Some(idx) = current_highlight {
                        let color = match idx {
                            0 => "\x1b[32m",  // green for attribute
                            1 => "\x1b[34m",  // blue for constant
                            2 => "\x1b[35m",  // magenta for function.builtin
                            3 => "\x1b[35m",  // magenta for function
                            4 => "\x1b[31m",  // red for keyword
                            5 => "\x1b[33m",  // yellow for operator
                            6 => "\x1b[36m",  // cyan for property
                            7 => "\x1b[37m",  // white for punctuation
                            8 => "\x1b[37m",  // white for punctuation.bracket
                            9 => "\x1b[37m",  // white for punctuation.delimiter
                            10 => "\x1b[32m", // green for string
                            11 => "\x1b[32m", // green for string.special
                            12 => "\x1b[36m", // cyan for tag
                            13 => "\x1b[36m", // cyan for type
                            14 => "\x1b[36m", // cyan for type.builtin
                            15 => "\x1b[37m", // white for variable
                            16 => "\x1b[37m", // white for variable.builtin
                            17 => "\x1b[37m", // white for variable.parameter
                            _ => "",
                        };
                        result.push_str(color);
                        result.push_str(text);
                        result.push_str("\x1b[0m");
                    } else {
                        result.push_str(text);
                    }
                }
            }
        }
        std::borrow::Cow::Owned(result)
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        default: bool,
    ) -> std::borrow::Cow<'b, str> {
        self.bracket_highlighter.highlight_prompt(prompt, default)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        std::borrow::Cow::Borrowed(hint)
    }

    fn highlight_candidate<'c>(
        &self,
        candidate: &'c str,
        _completion: rustyline::CompletionType,
    ) -> std::borrow::Cow<'c, str> {
        std::borrow::Cow::Borrowed(candidate)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.bracket_highlighter.highlight_char(line, pos)
    }
}

pub struct LineHelper {
    completer: FilenameCompleter,
    hinter: HistoryAutosuggest,
    #[cfg(feature = "tree-sitter")]
    highlighter: SyntaxHighlighter,
    #[cfg(not(feature = "tree-sitter"))]
    highlighter: MatchingBracketHighlighter,
    validator: MatchingBracketValidator,
    commands: Vec<String>,
    vars: Vec<String>,
    jobs: Vec<String>,
    abbreviations: HashMap<String, Vec<String>>,
    completions: CompletionSet,
    hint_color: String,
}

impl LineHelper {
    pub fn new() -> Self {
        Self {
            completer: FilenameCompleter::new(),
            hinter: HistoryAutosuggest,
            #[cfg(feature = "tree-sitter")]
            highlighter: SyntaxHighlighter::new(),
            #[cfg(not(feature = "tree-sitter"))]
            highlighter: MatchingBracketHighlighter::new(),
            validator: MatchingBracketValidator::new(),
            commands: Vec::new(),
            vars: Vec::new(),
            jobs: Vec::new(),
            abbreviations: HashMap::new(),
            completions: CompletionSet::default(),
            hint_color: ColorConfig::default().hint,
        }
    }

    fn update_context(
        &mut self,
        commands: Vec<String>,
        vars: Vec<String>,
        jobs: Vec<String>,
        abbreviations: HashMap<String, Vec<String>>,
        completions: CompletionSet,
        colors: &ColorConfig,
    ) {
        self.commands = commands;
        self.vars = vars;
        self.jobs = jobs;
        self.abbreviations = abbreviations;
        self.completions = completions;
        self.hint_color = colors.hint.clone();
    }

    fn abbreviation_hint(&self, line: &str, pos: usize) -> Option<String> {
        if pos < line.len() {
            return None;
        }
        let (start, token) = current_token(line, pos);
        if token.is_empty() || !is_command_position(line, start) {
            return None;
        }
        let expansion = self.abbreviations.get(&token)?;
        let expansion_text = expansion.join(" ");
        if expansion_text.starts_with(&token) {
            let remainder = expansion_text[token.len()..].to_string();
            if remainder.is_empty() {
                return None;
            }
            return Some(remainder);
        }
        Some(format!(" -> {expansion_text}"))
    }

    fn completion_hint(&self, line: &str, pos: usize) -> Option<String> {
        let (start, token) = current_token(line, pos);
        if token.is_empty() {
            return None;
        }
        let mut candidates = Vec::new();
        if is_command_position(line, start) {
            candidates.extend(self.commands.iter().cloned());
        } else if let Some(command) = command_for_position(line, start) {
            candidates.extend(completion_candidates(&self.completions, &command));
        }
        if candidates.is_empty() {
            return None;
        }
        let suggestion = best_suggestion(&token, &candidates)?;
        if suggestion.starts_with(&token) {
            let remainder = suggestion[token.len()..].to_string();
            if remainder.is_empty() {
                return None;
            }
            return Some(remainder);
        }
        Some(format!(" -> {suggestion}"))
    }
}

struct HistoryAutosuggest;

impl Hinter for HistoryAutosuggest {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        if line.is_empty() || pos < line.len() {
            return None;
        }
        let history = ctx.history();
        let start = if ctx.history_index() == history.len() {
            ctx.history_index().saturating_sub(1)
        } else {
            ctx.history_index()
        };
        let result = history
            .starts_with(line, start, SearchDirection::Reverse)
            .ok()
            .flatten()?;
        if result.entry == line {
            return None;
        }
        let remainder = result.entry[pos..].to_string();
        if remainder.is_empty() {
            return None;
        }
        Some(remainder)
    }
}

impl Helper for LineHelper {}

impl Completer for LineHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        let (start, token) = current_token(line, pos);
        if let Some(rest) = token.strip_prefix("${") {
            let prefix = rest;
            let mut pairs = complete_from_list(prefix, &self.vars, "${");
            for pair in &mut pairs {
                if !pair.replacement.ends_with('}') {
                    pair.replacement.push('}');
                    pair.display.push('}');
                }
            }
            pairs.extend(self.completer.complete(line, pos, ctx)?.1);
            return Ok((start, pairs));
        }
        if token.starts_with('$') {
            let prefix = token.trim_start_matches('$');
            let mut pairs = complete_from_list(prefix, &self.vars, "$");
            pairs.extend(self.completer.complete(line, pos, ctx)?.1);
            return Ok((start, pairs));
        }
        if token.starts_with('%') {
            let prefix = token.trim_start_matches('%');
            let mut pairs = complete_from_list(prefix, &self.jobs, "%");
            pairs.extend(self.completer.complete(line, pos, ctx)?.1);
            return Ok((start, pairs));
        }
        let mut pairs = self.completer.complete(line, pos, ctx)?.1;
        if is_command_position(line, start) || !token.contains('/') {
            pairs.extend(complete_from_list(token.as_str(), &self.commands, ""));
        }
        if let Some(command) = command_for_position(line, start) {
            let candidates = completion_candidates(&self.completions, &command);
            if !candidates.is_empty() {
                pairs.extend(complete_from_list(token.as_str(), &candidates, ""));
            }
        }
        Ok((start, pairs))
    }
}

impl Hinter for LineHelper {
    type Hint = String;

    fn hint(&self, line: &str, pos: usize, ctx: &Context<'_>) -> Option<String> {
        if let Some(hint) = self.abbreviation_hint(line, pos) {
            return Some(hint);
        }
        if let Some(hint) = self.hinter.hint(line, pos, ctx) {
            return Some(hint);
        }
        self.completion_hint(line, pos)
    }
}

impl Highlighter for LineHelper {
    fn highlight<'l>(&self, line: &'l str, pos: usize) -> std::borrow::Cow<'l, str> {
        self.highlighter.highlight(line, pos)
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(
        &'s self,
        prompt: &'p str,
        default: bool,
    ) -> std::borrow::Cow<'b, str> {
        self.highlighter.highlight_prompt(prompt, default)
    }

    fn highlight_hint<'h>(&self, hint: &'h str) -> std::borrow::Cow<'h, str> {
        if hint.is_empty() {
            return std::borrow::Cow::Borrowed(hint);
        }
        let color = resolve_color(&self.hint_color);
        if color.is_empty() {
            return std::borrow::Cow::Borrowed(hint);
        }
        std::borrow::Cow::Owned(format!("{color}{hint}\x1b[0m"))
    }

    fn highlight_candidate<'c>(
        &self,
        candidate: &'c str,
        completion: rustyline::CompletionType,
    ) -> std::borrow::Cow<'c, str> {
        self.highlighter.highlight_candidate(candidate, completion)
    }

    fn highlight_char(&self, line: &str, pos: usize) -> bool {
        self.highlighter.highlight_char(line, pos)
    }
}

impl Validator for LineHelper {
    fn validate(
        &self,
        ctx: &mut rustyline::validate::ValidationContext<'_>,
    ) -> Result<rustyline::validate::ValidationResult, ReadlineError> {
        self.validator.validate(ctx)
    }
}

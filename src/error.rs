//! Error types and reporting for the shell.
//!
//! This module provides structured error reporting with context and position information.
//! Instead of returning bare strings, functions return `ShellError` which includes:
//! - Error kind (parsing, expansion, redirection, etc.)
//! - Human-readable message
//! - Optional context about what input caused the error
//! - Optional character position for pointing to the problem location

use std::fmt;

/// Categorized error types for better diagnostics
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ErrorKind {
    /// Syntax error during tokenization/parsing
    Parse,
    /// Error during variable/glob expansion
    Expansion,
    /// Error with input/output redirections
    #[allow(dead_code)]
    Redirection,
    /// Error executing a command
    #[allow(dead_code)]
    Execution,
    /// Error loading/parsing configuration
    Config,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ErrorKind::Parse => write!(f, "Parse error"),
            ErrorKind::Expansion => write!(f, "Expansion error"),
            ErrorKind::Redirection => write!(f, "Redirection error"),
            ErrorKind::Execution => write!(f, "Execution error"),
            ErrorKind::Config => write!(f, "Config error"),
        }
    }
}

/// Rich error type with context information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ShellError {
    pub kind: ErrorKind,
    pub message: String,
    /// Additional context explaining what was being processed
    pub context: Option<String>,
    /// Character position in input where the error occurred
    pub position: Option<usize>,
}

impl ShellError {
    /// Create a new error with just the kind and message
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        ShellError {
            kind,
            message: message.into(),
            context: None,
            position: None,
        }
    }

    /// Add context string (e.g., "Expected: cmd < filename")
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Add character position in input where error occurred
    pub fn with_position(mut self, pos: usize) -> Self {
        self.position = Some(pos);
        self
    }

    /// Format error with a snippet of the input showing where the problem is
    #[allow(dead_code)]
    pub fn display_with_input(&self, input: &str) -> String {
        let mut msg = format!("{}: {}", self.kind, self.message);

        if let Some(pos) = self.position {
            if pos < input.len() {
                // Show a snippet around the error position
                let start = pos.saturating_sub(15);
                let end = (pos + 15).min(input.len());
                let snippet = &input[start..end];

                msg.push_str(&format!("\n  near: '{}'", snippet.replace('\n', "↵")));
                msg.push('\n');

                // Add a pointer to the exact position
                let offset = pos - start;
                msg.push_str(&format!("  {}{}", " ".repeat(offset + 9), "^"));
            } else {
                msg.push_str(&format!("\n  at position {} (end of input)", pos));
            }
        } else if let Some(context) = &self.context {
            msg.push_str(&format!("\n  hint: {}", context));
        }

        msg
    }

    /// Simplified display without input context
    pub fn display_simple(&self) -> String {
        let mut msg = format!("{}: {}", self.kind, self.message);
        if let Some(context) = &self.context {
            msg.push_str(&format!("\n  hint: {}", context));
        }
        msg
    }
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.display_simple())
    }
}

impl std::error::Error for ShellError {}

/// Convenience type alias for Results with ShellError
#[allow(dead_code)]
pub type ShellResult<T> = Result<T, ShellError>;

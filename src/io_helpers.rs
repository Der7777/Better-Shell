use std::io;

use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::Editor;

use crate::completion::LineHelper;
use crate::error::{ErrorKind, ShellError};

pub fn read_input_line(
    editor: &mut Editor<LineHelper, DefaultHistory>,
    interactive: bool,
    prompt: &str,
) -> io::Result<Option<String>> {
    if interactive {
        let line = match editor.readline(prompt) {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => return Ok(Some(String::new())),
            Err(ReadlineError::Eof) => return Ok(None),
            Err(err) => return Err(io::Error::other(err)),
        };
        Ok(Some(line))
    } else {
        let mut line = String::new();
        let bytes = io::stdin().read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        Ok(Some(line))
    }
}

pub fn read_heredoc(
    mut editor: Option<&mut Editor<LineHelper, DefaultHistory>>,
    interactive: bool,
    delimiter: &str,
) -> Result<String, String> {
    // Heredoc content is collected after parsing to allow interactive input.
    let mut content = String::new();
    loop {
        if interactive {
            let Some(editor) = editor.as_deref_mut() else {
                return Err(ShellError::new(
                    ErrorKind::Parse,
                    "Heredoc reader not available in non-interactive mode".to_string(),
                )
                .with_context("Cannot read heredoc content interactively")
                .to_string());
            };
            match editor.readline("> ") {
                Ok(line) => {
                    if line == delimiter {
                        break;
                    }
                    content.push_str(&line);
                    content.push('\n');
                }
                Err(ReadlineError::Eof) => {
                    return Err(ShellError::new(
                        ErrorKind::Parse,
                        format!("Unexpected EOF while reading heredoc (expected delimiter: {})", delimiter),
                    )
                    .with_context("Heredoc was not terminated with expected delimiter")
                    .to_string());
                }
                Err(ReadlineError::Interrupted) => {
                    return Err(ShellError::new(
                        ErrorKind::Parse,
                        "Heredoc input interrupted (Ctrl-C)".to_string(),
                    )
                    .to_string());
                }
                Err(err) => {
                    return Err(ShellError::new(
                        ErrorKind::Parse,
                        format!("Error reading heredoc: {}", err),
                    )
                    .to_string());
                }
            }
        } else {
            let mut line = String::new();
            let bytes = io::stdin()
                .read_line(&mut line)
                .map_err(|err| {
                    ShellError::new(
                        ErrorKind::Parse,
                        format!("Error reading heredoc from stdin: {}", err),
                    )
                    .to_string()
                })?;
            if bytes == 0 {
                return Err(ShellError::new(
                    ErrorKind::Parse,
                    format!("Unexpected EOF while reading heredoc (expected delimiter: {})", delimiter),
                )
                .with_context("Heredoc was not terminated with expected delimiter")
                .to_string());
            }
            let trimmed = line.trim_end_matches(&['\n', '\r'][..]);
            if trimmed == delimiter {
                break;
            }
            content.push_str(trimmed);
            content.push('\n');
        }
    }
    Ok(content)
}

pub fn normalize_command_output(output: String) -> String {
    let trimmed = output.trim_end_matches(&['\n', '\r'][..]);
    let normalized = trimmed.replace('\n', " ");
    normalized.replace('\r', "")
}

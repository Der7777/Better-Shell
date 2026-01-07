use std::io;

use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::Editor;

use crate::completion::LineHelper;

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
    let mut content = String::new();
    loop {
        if interactive {
            let Some(editor) = editor.as_deref_mut() else {
                return Err("heredoc reader not available".to_string());
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
                    return Err("unexpected EOF while reading heredoc".to_string());
                }
                Err(ReadlineError::Interrupted) => {
                    return Err("heredoc interrupted".to_string());
                }
                Err(err) => {
                    return Err(format!("heredoc error: {err}"));
                }
            }
        } else {
            let mut line = String::new();
            let bytes = io::stdin()
                .read_line(&mut line)
                .map_err(|err| format!("heredoc error: {err}"))?;
            if bytes == 0 {
                return Err("unexpected EOF while reading heredoc".to_string());
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

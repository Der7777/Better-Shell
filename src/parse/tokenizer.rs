//! Tokenizer for shell input.
//!
//! Uses Normal/Single/Double modes to preserve quoting semantics while still
//! emitting a flat token stream for the command parser.
use crate::error::{ErrorKind, ShellError};
use crate::parse::{ESCAPE_MARKER, NOGLOB_MARKER, OPERATOR_TOKEN_MARKER};

#[derive(Copy, Clone, Eq, PartialEq)]
enum ParseMode {
    Normal,
    Single,
    Double,
}

// Bound nesting depth to avoid pathological recursion in command substitution.
const MAX_SUBST_DEPTH: usize = 32;

pub fn parse_line(input: &str) -> Result<Vec<String>, String> {
    parse_line_with_mode(input, false)
}

pub fn parse_line_lenient(input: &str) -> Result<Vec<String>, String> {
    parse_line_with_mode(input, true)
}

fn parse_line_with_mode(input: &str, lenient: bool) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut buf = String::new();
    let mut chars = input.chars().peekable();
    let mut mode = ParseMode::Normal;
    let mut in_token = false;
    // Tracks whether a redirection operator must be followed by a target.
    let mut expect_redir_target = false;

    while let Some(ch) = chars.next() {
        match mode {
            ParseMode::Normal => match ch {
                '&' if expect_redir_target && !in_token => {
                    in_token = true;
                    buf.push('&');
                }
                ' ' | '\t' => {
                    if in_token {
                        args.push(buf.clone());
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                    }
                }
                '#' => {
                    if !in_token {
                        break;
                    }
                    buf.push('#');
                }
                '|' => {
                    if in_token {
                        args.push(buf.clone());
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                    }
                    if matches!(chars.peek(), Some('|')) {
                        chars.next();
                        args.push(format!("{OPERATOR_TOKEN_MARKER}||"));
                    } else {
                        args.push(format!("{OPERATOR_TOKEN_MARKER}|"));
                    }
                }
                '>' if expect_redir_target && !in_token => {
                    in_token = true;
                    buf.push('>');
                }
                '>' => {
                    let fd_prefix = if in_token && buf.chars().all(|c| c.is_ascii_digit()) {
                        let prefix = buf.clone();
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                        Some(prefix)
                    } else {
                        None
                    };
                    if in_token {
                        args.push(buf.clone());
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                    }
                    if matches!(chars.peek(), Some('>')) {
                        chars.next();
                        let op = if let Some(prefix) = fd_prefix {
                            format!("{prefix}>>")
                        } else {
                            ">>".to_string()
                        };
                        args.push(format!("{OPERATOR_TOKEN_MARKER}{op}"));
                    } else {
                        let op = if let Some(prefix) = fd_prefix {
                            format!("{prefix}>")
                        } else {
                            ">".to_string()
                        };
                        args.push(format!("{OPERATOR_TOKEN_MARKER}{op}"));
                    }
                    expect_redir_target = true;
                }
                '<' if expect_redir_target && !in_token => {
                    in_token = true;
                    buf.push('<');
                }
                '<' => {
                    let fd_prefix = if in_token && buf.chars().all(|c| c.is_ascii_digit()) {
                        let prefix = buf.clone();
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                        Some(prefix)
                    } else {
                        None
                    };
                    if in_token {
                        args.push(buf.clone());
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                    }
                    if matches!(chars.peek(), Some('<')) {
                        chars.next();
                        if matches!(chars.peek(), Some('<')) {
                            chars.next();
                            let op = if let Some(prefix) = fd_prefix {
                                format!("{prefix}<<<")
                            } else {
                                "<<<".to_string()
                            };
                            args.push(format!("{OPERATOR_TOKEN_MARKER}{op}"));
                        } else {
                            let op = if let Some(prefix) = fd_prefix {
                                format!("{prefix}<<")
                            } else {
                                "<<".to_string()
                            };
                            args.push(format!("{OPERATOR_TOKEN_MARKER}{op}"));
                        }
                    } else {
                        let op = if let Some(prefix) = fd_prefix {
                            format!("{prefix}<")
                        } else {
                            "<".to_string()
                        };
                        args.push(format!("{OPERATOR_TOKEN_MARKER}{op}"));
                    }
                    expect_redir_target = true;
                }
                '&' => {
                    if in_token {
                        args.push(buf.clone());
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                    }
                    if matches!(chars.peek(), Some('>')) {
                        chars.next();
                        if matches!(chars.peek(), Some('>')) {
                            chars.next();
                            args.push(format!("{OPERATOR_TOKEN_MARKER}&>>"));
                        } else {
                            args.push(format!("{OPERATOR_TOKEN_MARKER}&>"));
                        }
                        expect_redir_target = true;
                    } else if matches!(chars.peek(), Some('&')) {
                        chars.next();
                        args.push(format!("{OPERATOR_TOKEN_MARKER}&&"));
                    } else {
                        args.push(format!("{OPERATOR_TOKEN_MARKER}&"));
                    }
                }
                ';' => {
                    if in_token {
                        args.push(buf.clone());
                        buf.clear();
                        in_token = false;
                        expect_redir_target = false;
                    }
                    args.push(format!("{OPERATOR_TOKEN_MARKER};"));
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        in_token = true;
                        push_escaped_normal(&mut buf, next);
                    } else {
                        in_token = true;
                        buf.push('\\');
                    }
                }
                '\'' => {
                    in_token = true;
                    mode = ParseMode::Single;
                }
                '"' => {
                    in_token = true;
                    mode = ParseMode::Double;
                }
                '$' => {
                    // $() keeps nesting state to validate balanced substitutions.
                    in_token = true;
                    if matches!(chars.peek(), Some('(')) {
                        chars.next();
                        if lenient {
                            let (inner, closed) =
                                parse_command_substitution_lenient(&mut chars)?;
                            buf.push_str("$(");
                            buf.push_str(&inner);
                            if closed {
                                buf.push(')');
                            }
                        } else {
                            let inner = parse_command_substitution(&mut chars)?;
                            buf.push_str("$(");
                            buf.push_str(&inner);
                            buf.push(')');
                        }
                    } else {
                        buf.push('$');
                    }
                }
                '`' => {
                    // Backticks are parsed separately for compatibility with legacy syntax.
                    in_token = true;
                    if lenient {
                        let (inner, closed) = parse_backticks_lenient(&mut chars)?;
                        buf.push_str("$(");
                        buf.push_str(&inner);
                        if closed {
                            buf.push(')');
                        }
                    } else {
                        let inner = parse_backticks(&mut chars)?;
                        buf.push_str("$(");
                        buf.push_str(&inner);
                        buf.push(')');
                    }
                }
                _ => {
                    in_token = true;
                    buf.push(ch);
                }
            },
            ParseMode::Single => {
                if ch == '\'' {
                    mode = ParseMode::Normal;
                } else {
                    in_token = true;
                    buf.push(ESCAPE_MARKER);
                    buf.push(ch);
                }
            }
            ParseMode::Double => match ch {
                '"' => mode = ParseMode::Normal,
                '\\' => {
                    if let Some(next) = chars.next() {
                        in_token = true;
                        push_escaped_double(&mut buf, next);
                    } else {
                        in_token = true;
                        buf.push('\\');
                    }
                }
                '$' => {
                    in_token = true;
                    if matches!(chars.peek(), Some('(')) {
                        chars.next();
                        if lenient {
                            let (inner, closed) =
                                parse_command_substitution_lenient(&mut chars)?;
                            buf.push(NOGLOB_MARKER);
                            buf.push_str("$(");
                            buf.push_str(&inner);
                            if closed {
                                buf.push(')');
                            }
                        } else {
                            let inner = parse_command_substitution(&mut chars)?;
                            buf.push(NOGLOB_MARKER);
                            buf.push_str("$(");
                            buf.push_str(&inner);
                            buf.push(')');
                        }
                    } else {
                        buf.push(NOGLOB_MARKER);
                        buf.push('$');
                    }
                }
                '`' => {
                    in_token = true;
                    if lenient {
                        let (inner, closed) = parse_backticks_lenient(&mut chars)?;
                        buf.push(NOGLOB_MARKER);
                        buf.push_str("$(");
                        buf.push_str(&inner);
                        if closed {
                            buf.push(')');
                        }
                    } else {
                        let inner = parse_backticks(&mut chars)?;
                        buf.push(NOGLOB_MARKER);
                        buf.push_str("$(");
                        buf.push_str(&inner);
                        buf.push(')');
                    }
                }
                _ => {
                    in_token = true;
                    buf.push(NOGLOB_MARKER);
                    buf.push(ch);
                }
            },
        }
    }

    if mode != ParseMode::Normal {
        if !lenient {
            let quote_char = match mode {
                ParseMode::Single => "'",
                ParseMode::Double => "\"",
                ParseMode::Normal => unreachable!(),
            };
            return Err(ShellError::new(
                ErrorKind::Parse,
                format!("Unterminated {} quote", quote_char),
            )
            .with_position(input.len() - 1)
            .into());
        }
        mode = ParseMode::Normal;
    }

    if in_token {
        args.push(buf);
        expect_redir_target = false;
    }

    if expect_redir_target && !lenient {
        return Err(ShellError::new(
            ErrorKind::Parse,
            "Expected redirection target (filename or file descriptor)".to_string(),
        )
        .with_context("After >, >>, <, etc.")
        .with_position(input.len() - 1)
        .into());
    }

    Ok(args)
}

pub fn parse_command_substitution<I>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<String, String>
where
    I: Iterator<Item = char>,
{
    let (inner, closed) = parse_command_substitution_inner(chars, false)?;
    if closed {
        Ok(inner)
    } else {
        Err(ShellError::new(
            ErrorKind::Parse,
            "Unterminated command substitution $(...)",
        )
        .with_context("Missing closing parenthesis for command substitution")
        .into())
    }
}

fn parse_backticks<I>(chars: &mut std::iter::Peekable<I>) -> Result<String, String>
where
    I: Iterator<Item = char>,
{
    let (inner, closed) = parse_backticks_inner(chars, false)?;
    if closed {
        Ok(inner)
    } else {
        Err(ShellError::new(
            ErrorKind::Parse,
            "Unterminated backtick command substitution",
        )
        .with_context("Missing closing backtick (`)")
        .into())
    }
}

pub fn parse_command_substitution_lenient<I>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<(String, bool), String>
where
    I: Iterator<Item = char>,
{
    parse_command_substitution_inner(chars, true)
}

fn parse_command_substitution_inner<I>(
    chars: &mut std::iter::Peekable<I>,
    lenient: bool,
) -> Result<(String, bool), String>
where
    I: Iterator<Item = char>,
{
    let mut inner = String::new();
    let mut depth = 1usize;
    let mut mode = ParseMode::Normal;

    while let Some(ch) = chars.next() {
        match mode {
            ParseMode::Normal => match ch {
                '\\' => {
                    if let Some(next) = chars.next() {
                        inner.push('\\');
                        inner.push(next);
                    } else {
                        inner.push('\\');
                    }
                }
                '\'' => {
                    mode = ParseMode::Single;
                    inner.push(ch);
                }
                '"' => {
                    mode = ParseMode::Double;
                    inner.push(ch);
                }
                '$' => {
                    if matches!(chars.peek(), Some('(')) {
                        chars.next();
                        depth += 1;
                        if depth > MAX_SUBST_DEPTH {
                            return Err(ShellError::new(
                                ErrorKind::Parse,
                                format!(
                                    "Command substitution nesting exceeds limit of {}",
                                    MAX_SUBST_DEPTH
                                ),
                            )
                            .with_context(
                                "Consider simplifying: $(cmd1 $(cmd2)) is nested, $(cmd1; cmd2) is not",
                            )
                            .into());
                        }
                        inner.push_str("$(");
                    } else {
                        inner.push(ch);
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok((inner, true));
                    }
                    inner.push(ch);
                }
                _ => inner.push(ch),
            },
            ParseMode::Single => {
                if ch == '\'' {
                    mode = ParseMode::Normal;
                }
                inner.push(ch);
            }
            ParseMode::Double => match ch {
                '"' => {
                    mode = ParseMode::Normal;
                    inner.push(ch);
                }
                '\\' => {
                    if let Some(next) = chars.next() {
                        inner.push('\\');
                        inner.push(next);
                    } else {
                        inner.push('\\');
                    }
                }
                '$' => {
                    if matches!(chars.peek(), Some('(')) {
                        chars.next();
                        depth += 1;
                        if depth > MAX_SUBST_DEPTH {
                            return Err(ShellError::new(
                                ErrorKind::Parse,
                                format!(
                                    "Command substitution nesting exceeds limit of {}",
                                    MAX_SUBST_DEPTH
                                ),
                            )
                            .with_context(
                                "Consider simplifying: $(cmd1 $(cmd2)) is nested, $(cmd1; cmd2) is not",
                            )
                            .into());
                        }
                        inner.push_str("$(");
                    } else {
                        inner.push(ch);
                    }
                }
                _ => inner.push(ch),
            },
        }
    }

    if lenient {
        Ok((inner, false))
    } else {
        Err(ShellError::new(
            ErrorKind::Parse,
            "Unterminated command substitution $(...)",
        )
        .with_context("Missing closing parenthesis for command substitution")
        .into())
    }
}

fn parse_backticks_lenient<I>(
    chars: &mut std::iter::Peekable<I>,
) -> Result<(String, bool), String>
where
    I: Iterator<Item = char>,
{
    parse_backticks_inner(chars, true)
}

fn parse_backticks_inner<I>(
    chars: &mut std::iter::Peekable<I>,
    lenient: bool,
) -> Result<(String, bool), String>
where
    I: Iterator<Item = char>,
{
    let mut inner = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    inner.push('\\');
                    inner.push(next);
                } else {
                    inner.push('\\');
                }
            }
            '`' => return Ok((inner, true)),
            _ => inner.push(ch),
        }
    }

    if lenient {
        Ok((inner, false))
    } else {
        Err(ShellError::new(
            ErrorKind::Parse,
            "Unterminated backtick command substitution",
        )
        .with_context("Missing closing backtick (`)")
        .into())
    }
}

fn push_escaped_normal(buf: &mut String, next: char) {
    let resolved = resolve_escape(next);
    buf.push(ESCAPE_MARKER);
    buf.push(resolved);
}

fn push_escaped_double(buf: &mut String, next: char) {
    let resolved = resolve_escape(next);
    buf.push(NOGLOB_MARKER);
    buf.push(ESCAPE_MARKER);
    buf.push(resolved);
}

fn resolve_escape(ch: char) -> char {
    match ch {
        'n' => '\n',
        't' => '\t',
        'r' => '\r',
        ' ' => ' ',
        '\\' => '\\',
        '"' => '"',
        '\'' => '\'',
        _ => ch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{strip_all_markers, strip_markers, ESCAPE_MARKER, NOGLOB_MARKER, OPERATOR_TOKEN_MARKER};

    #[test]
    fn tokenize_basic() {
        let tokens = parse_line("ls -la /tmp").unwrap();
        assert_eq!(tokens, vec!["ls", "-la", "/tmp"]);
    }

    #[test]
    fn quoting_and_escaping() {
        let tokens = parse_line("echo \"ab\\\"cd\"").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "ab\"cd");

        let tokens = parse_line("echo 'single # and $'").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "single # and $");

        let tokens = parse_line("printf '%s|%s' \"ab\"\"cd\" \"\"").unwrap();
        let stripped: Vec<String> = tokens.iter().map(|t| strip_markers(t)).collect();
        assert_eq!(stripped, vec!["printf", "%s|%s", "abcd", ""]);
    }

    #[test]
    fn backticks_and_command_substitution() {
        let tokens = parse_line("echo `echo hi`").unwrap();
        assert_eq!(tokens[1], "$(echo hi)");

        let tokens = parse_line("echo $(echo $(echo x))").unwrap();
        assert_eq!(tokens[1], "$(echo $(echo x))");
    }

    #[test]
    fn escapes_preserve_spaces() {
        let tokens = parse_line("echo foo\\ bar").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "foo bar");

        let tokens = parse_line("echo \"line\\n\"").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "line\n");
    }

    #[test]
    fn error_cases() {
        assert_eq!(
            parse_line("echo \"unterminated").unwrap_err(),
            "unterminated quote"
        );
        assert_eq!(
            parse_line("echo $(date").unwrap_err(),
            "unterminated $(...)"
        );
    }

    #[test]
    fn redirection_target_required_in_strict_mode() {
        let err = parse_line("echo >").unwrap_err();
        assert!(err.to_lowercase().contains("expected redirection target"));

        let err = parse_line("cat <<").unwrap_err();
        assert!(err.to_lowercase().contains("expected redirection target"));
    }

    #[test]
    fn redirection_target_lenient_mode_allows_missing() {
        let tokens = parse_line_lenient("echo >").unwrap();
        assert_eq!(tokens, vec!["echo", format!("{OPERATOR_TOKEN_MARKER}>")]);
    }

    #[test]
    fn mixed_operators_without_spaces() {
        let tokens = parse_line("echo a&&b||c;d").unwrap();
        let stripped: Vec<String> = tokens
            .into_iter()
            .map(|t| strip_all_markers(&t))
            .collect();
        assert_eq!(stripped, vec!["echo", "a", "&&", "b", "||", "c", ";", "d"]);
    }

    #[test]
    fn fd_redirection_without_space() {
        let tokens = parse_line("echo 2>err").unwrap();
        let stripped: Vec<String> = tokens
            .into_iter()
            .map(|t| strip_all_markers(&t))
            .collect();
        assert_eq!(stripped, vec!["echo", "2>", "err"]);
    }

    #[test]
    fn mixed_quotes_and_escaped_operator() {
        let tokens = parse_line("echo \"a'b'\\\"c\\\"\"").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "a'b'\"c\"");

        let tokens = parse_line("echo 'a\"b\"c'").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "a\"b\"c");

        let tokens = parse_line("echo foo\\|bar").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "foo|bar");
    }

    #[test]
    fn command_substitution_with_escaped_quotes() {
        let tokens = parse_line("echo $(printf \\\"hi\\\")").unwrap();
        assert_eq!(tokens[1], "$(printf \\\"hi\\\")");
    }

    #[test]
    fn command_substitution_nesting_limit() {
        let mut input = String::from("echo ");
        for _ in 0..MAX_SUBST_DEPTH {
            input.push_str("$(");
        }
        input.push_str("echo x");
        for _ in 0..MAX_SUBST_DEPTH {
            input.push(')');
        }
        assert!(parse_line(&input).is_ok());

        let mut too_deep = String::from("echo ");
        for _ in 0..=MAX_SUBST_DEPTH {
            too_deep.push_str("$(");
        }
        too_deep.push_str("echo x");
        for _ in 0..=MAX_SUBST_DEPTH {
            too_deep.push(')');
        }
        assert_eq!(
            parse_line(&too_deep).unwrap_err(),
            "command substitution nesting too deep"
        );
    }

    #[test]
    fn backticks_with_nested_substitution() {
        let tokens = parse_line("echo `echo $(echo hi)`").unwrap();
        assert_eq!(tokens[1], "$(echo $(echo hi))");
    }

    #[test]
    fn quoted_command_substitution_token() {
        let tokens = parse_line("echo \"$(echo a)\"").unwrap();
        assert_eq!(strip_markers(&tokens[1]), "$(echo a)");
    }

    #[test]
    fn marker_helpers() {
        let input = format!("{ESCAPE_MARKER}a{NOGLOB_MARKER}b");
        assert_eq!(strip_markers(&input), "ab");

        let input = format!("{OPERATOR_TOKEN_MARKER}&&");
        assert_eq!(strip_all_markers(&input), "&&");
    }
}

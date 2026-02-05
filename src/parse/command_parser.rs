use crate::parse::{CommandSpec, OPERATOR_TOKEN_MARKER};
use crate::parse::redirection_parser::apply_redirection;
use crate::parse::redirection_parser::try_parse_sandbox_directive;

#[derive(Copy, Clone, Debug)]
pub enum SeqOp {
    Always,
    And,
    Or,
}

#[derive(Debug)]
pub struct SeqSegment {
    pub op: SeqOp,
    pub tokens: Vec<String>,
    pub display: String,
}

pub fn split_sequence(tokens: Vec<String>) -> Result<Vec<SeqSegment>, String> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    let mut next_op = SeqOp::Always;

    for token in tokens {
        if let Some(stripped) = token.strip_prefix(OPERATOR_TOKEN_MARKER) {
            match stripped {
                ";" | "&&" | "||" => {
                    if current.is_empty() {
                        return Err("empty command".to_string());
                    }
                    let display = tokens_to_display(&current);
                    segments.push(SeqSegment {
                        op: next_op,
                        tokens: current,
                        display,
                    });
                    current = Vec::new();
                    next_op = match stripped {
                        "&&" => SeqOp::And,
                        "||" => SeqOp::Or,
                        _ => SeqOp::Always,
                    };
                    continue;
                }
                _ => {}
            }
        }
        current.push(token);
    }

    if current.is_empty() {
        return Err("trailing operator".to_string());
    }

    let display = tokens_to_display(&current);
    segments.push(SeqSegment {
        op: next_op,
        tokens: current,
        display,
    });

    Ok(segments)
}

pub fn split_sequence_lenient(tokens: Vec<String>) -> Vec<SeqSegment> {
    let mut segments = Vec::new();
    let mut current = Vec::new();
    let mut next_op = SeqOp::Always;

    for token in tokens {
        if let Some(stripped) = token.strip_prefix(OPERATOR_TOKEN_MARKER) {
            match stripped {
                ";" | "&&" | "||" => {
                    if !current.is_empty() {
                        let display = tokens_to_display(&current);
                        segments.push(SeqSegment {
                            op: next_op,
                            tokens: current,
                            display,
                        });
                        current = Vec::new();
                    }
                    next_op = match stripped {
                        "&&" => SeqOp::And,
                        "||" => SeqOp::Or,
                        _ => SeqOp::Always,
                    };
                    continue;
                }
                _ => {}
            }
        }
        current.push(token);
    }

    if !current.is_empty() {
        let display = tokens_to_display(&current);
        segments.push(SeqSegment {
            op: next_op,
            tokens: current,
            display,
        });
    }

    segments
}

fn tokens_to_display(tokens: &[String]) -> String {
    let mut parts = Vec::with_capacity(tokens.len());
    for token in tokens {
        if let Some(stripped) = token.strip_prefix(OPERATOR_TOKEN_MARKER) {
            parts.push(stripped.to_string());
        } else {
            parts.push(token.clone());
        }
    }
    parts.join(" ")
}

pub fn split_pipeline(tokens: Vec<String>) -> Result<(Vec<CommandSpec>, bool), String> {
    let mut pipeline = Vec::new();
    let mut current = CommandSpec::new();
    let mut iter = tokens.into_iter().peekable();
    let mut background = false;

    while let Some(token) = iter.next() {
        if let Some(stripped) = token.strip_prefix(OPERATOR_TOKEN_MARKER) {
            match stripped {
                "|" => {
                    if current.args.is_empty() {
                        return Err("empty command in pipeline".to_string());
                    }
                    pipeline.push(current);
                    current = CommandSpec::new();
                }
                "<" | "<<" | "<<<" | ">" | ">>" | "&>" | "&>>"
                | "0<" | "0<<" | "0<<<"
                | "1>" | "1>>"
                | "2>" | "2>>" => {
                    apply_redirection(&mut current, stripped, &mut iter)?;
                }
                "&" => {
                    if iter.peek().is_some() {
                        return Err("background operator must be at end of line".to_string());
                    }
                    background = true;
                }
                "&&" | "||" | ";" => {
                    return Err("unexpected control operator".to_string());
                }
                _ => current.args.push(stripped.to_string()),
            }
            continue;
        }

        if current.args.is_empty() {
            if let Some(directive) = try_parse_sandbox_directive(&token)? {
                if current.sandbox.is_some() {
                    return Err("duplicate sandbox directive".to_string());
                }
                current.sandbox = Some(directive);
                continue;
            }
        }

        current.args.push(token);
    }

    if current.args.is_empty() {
        return Err("trailing pipe".to_string());
    }

    pipeline.push(current);
    Ok((pipeline, background))
}

pub fn split_pipeline_lenient(tokens: Vec<String>) -> (Vec<CommandSpec>, bool) {
    let mut pipeline = Vec::new();
    let mut current = CommandSpec::new();
    let mut iter = tokens.into_iter().peekable();
    let mut background = false;

    while let Some(token) = iter.next() {
        if let Some(stripped) = token.strip_prefix(OPERATOR_TOKEN_MARKER) {
            match stripped {
                "|" => {
                    if !current.args.is_empty() {
                        pipeline.push(current);
                        current = CommandSpec::new();
                    }
                }
                "<" | "<<" | "<<<" | ">" | ">>" | "&>" | "&>>"
                | "0<" | "0<<" | "0<<<"
                | "1>" | "1>>"
                | "2>" | "2>>" => {
                    let target = iter.next();
                    if let Some(target) = target {
                        let mut tmp_iter = vec![target.clone()].into_iter().peekable();
                        if apply_redirection(&mut current, stripped, &mut tmp_iter).is_err() {
                            current.args.push(stripped.to_string());
                            current.args.push(target);
                        }
                    } else {
                        current.args.push(stripped.to_string());
                    }
                }
                "&" => {
                    if iter.peek().is_some() {
                        current.args.push(stripped.to_string());
                    } else {
                        background = true;
                    }
                }
                "&&" | "||" | ";" => {
                    current.args.push(stripped.to_string());
                }
                _ => current.args.push(stripped.to_string()),
            }
            continue;
        }

        if current.args.is_empty() {
            match try_parse_sandbox_directive(&token) {
                Ok(Some(directive)) => {
                    if current.sandbox.is_none() {
                        current.sandbox = Some(directive);
                        continue;
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        current.args.push(token);
    }

    if !current.args.is_empty() || !pipeline.is_empty() {
        pipeline.push(current);
    }

    (pipeline, background)
}

#[allow(dead_code)]
pub fn token_str(token: &str) -> &str {
    if let Some(stripped) = token.strip_prefix(OPERATOR_TOKEN_MARKER) {
        stripped
    } else {
        token
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::{parse_line, strip_markers};

    #[test]
    fn tokenize_operators_and_pipeline() {
        let tokens = parse_line("echo hi | cat").unwrap();
        assert!(tokens.contains(&format!("{OPERATOR_TOKEN_MARKER}|")));
        let (pipeline, background) = split_pipeline(tokens).unwrap();
        assert!(!background);
        assert_eq!(pipeline.len(), 2);
        assert_eq!(pipeline[0].args, vec!["echo", "hi"]);
        assert_eq!(pipeline[1].args, vec!["cat"]);
    }

    #[test]
    fn split_sequence_ops() {
        let tokens = parse_line("a && b || c ; d").unwrap();
        let segments = split_sequence(tokens).unwrap();
        assert_eq!(segments.len(), 4);
        assert!(matches!(segments[0].op, SeqOp::Always));
        assert!(matches!(segments[1].op, SeqOp::And));
        assert!(matches!(segments[2].op, SeqOp::Or));
        assert!(matches!(segments[3].op, SeqOp::Always));
        assert_eq!(segments[0].tokens, vec!["a"]);
        assert_eq!(segments[1].tokens, vec!["b"]);
        assert_eq!(segments[2].tokens, vec!["c"]);
        assert_eq!(segments[3].tokens, vec!["d"]);
    }

    #[test]
    fn split_sequence_trailing_operator_errors() {
        let tokens = parse_line("a &&").unwrap();
        assert_eq!(split_sequence(tokens).unwrap_err(), "trailing operator");
    }

    #[test]
    fn split_pipeline_redirects_and_background() {
        let tokens = parse_line("cmd < in > out").unwrap();
        let (pipeline, background) = split_pipeline(tokens).unwrap();
        assert!(!background);
        assert_eq!(pipeline.len(), 1);
        assert_eq!(pipeline[0].stdin.as_deref(), Some("in"));
        assert_eq!(pipeline[0].stdout.as_ref().unwrap().path, "out");
        assert!(!pipeline[0].stdout.as_ref().unwrap().append);

        let tokens = parse_line("cmd >> out").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        assert!(pipeline[0].stdout.as_ref().unwrap().append);

        let tokens = parse_line("cmd 2> err").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        assert_eq!(pipeline[0].stderr.as_ref().unwrap().path, "err");

        let tokens = parse_line("cmd 2>&1").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        assert!(pipeline[0].stderr_to_stdout);

        let tokens = parse_line("cmd 2>&-").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        assert!(pipeline[0].stderr_close);

        let tokens = parse_line("cmd &> both").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        assert_eq!(pipeline[0].stdout.as_ref().unwrap().path, "both");
        assert_eq!(pipeline[0].stderr.as_ref().unwrap().path, "both");

        let tokens = parse_line("cmd <<< value").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        assert_eq!(pipeline[0].herestring.as_deref(), Some("value"));

        let tokens = parse_line("cmd & other").unwrap();
        assert_eq!(
            split_pipeline(tokens).unwrap_err(),
            "background operator must be at end of line"
        );

        let tokens = parse_line("cmd << EOF").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        let heredoc = pipeline[0].heredoc.as_ref().unwrap();
        assert_eq!(heredoc.delimiter, "EOF");
        assert!(!heredoc.quoted);
    }

    #[test]
    fn split_pipeline_rejects_duplicate_redirections() {
        let tokens = parse_line("cmd > out1 > out2").unwrap();
        assert_eq!(
            split_pipeline(tokens).unwrap_err(),
            "multiple output redirections"
        );

        let tokens = parse_line("cmd 2> err1 2> err2").unwrap();
        assert_eq!(
            split_pipeline(tokens).unwrap_err(),
            "multiple stderr redirections"
        );
    }

    #[test]
    fn split_pipeline_rejects_unsupported_fd_dup() {
        let tokens = parse_line("cmd 2>&3").unwrap();
        assert_eq!(
            split_pipeline(tokens).unwrap_err(),
            "unsupported fd redirection"
        );
    }


    #[test]
    fn heredoc_quoted_and_unquoted_delimiters() {
        let tokens = parse_line("cat <<EOF").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        let heredoc = pipeline[0].heredoc.as_ref().unwrap();
        assert_eq!(heredoc.delimiter, "EOF");
        assert!(!heredoc.quoted);

        let tokens = parse_line("cat <<'EOF'").unwrap();
        let (pipeline, _) = split_pipeline(tokens).unwrap();
        let heredoc = pipeline[0].heredoc.as_ref().unwrap();
        assert_eq!(heredoc.delimiter, "EOF");
        assert!(heredoc.quoted);
    }

    #[test]
    fn token_str_operator() {
        let token = format!("{OPERATOR_TOKEN_MARKER}||");
        assert_eq!(token_str(&token), "||");
        assert_eq!(token_str("echo"), "echo");
    }
}

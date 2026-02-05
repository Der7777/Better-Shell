use crate::parse::{
    strip_markers, CommandSpec, HeredocSpec, OutputRedirection, SandboxDirective, ESCAPE_MARKER,
    NOGLOB_MARKER,
};

pub(crate) fn apply_redirection(
    current: &mut CommandSpec,
    op: &str,
    iter: &mut std::iter::Peekable<std::vec::IntoIter<String>>,
) -> Result<(), String> {
    if let Some(fd) = parse_fd_output_op(op) {
        if fd == 1 || fd == 2 {
            // Let the explicit cases below handle standard fds.
        } else {
            let target = iter
                .next()
                .ok_or_else(|| "missing output file".to_string())?;
            if let Some((_dup, close)) = parse_dup_target(&target)? {
                if close {
                    current.close_fds.push(fd);
                    return Ok(());
                }
                return Err("unsupported fd redirection".to_string());
            }
            return Err("unsupported fd redirection".to_string());
        }
    }
    match op {
        "<" | "0<" => {
            let path = iter
                .next()
                .ok_or_else(|| "missing input file".to_string())?;
            set_input_redirection(current, InputRedirection::File(path))
        }
        "<<" | "0<<" => {
            let raw = iter
                .next()
                .ok_or_else(|| "missing heredoc delimiter".to_string())?;
            let quoted = raw.contains(ESCAPE_MARKER) || raw.contains(NOGLOB_MARKER);
            let delimiter = strip_markers(&raw);
            set_input_redirection(
                current,
                InputRedirection::Heredoc(HeredocSpec {
                    delimiter,
                    quoted,
                    content: None,
                }),
            )
        }
        "<<<" | "0<<<" => {
            let raw = iter
                .next()
                .ok_or_else(|| "missing here-string value".to_string())?;
            let content = strip_markers(&raw);
            set_input_redirection(current, InputRedirection::HereString(content))
        }
        ">" | "1>" | ">>" | "1>>" => {
            let path = iter
                .next()
                .ok_or_else(|| "missing output file".to_string())?;
            if current.stdout.is_some() {
                return Err("multiple output redirections".to_string());
            }
            current.stdout = Some(OutputRedirection {
                path,
                append: op.ends_with(">>"),
            });
            Ok(())
        }
        "2>" | "2>>" => {
            let target = iter
                .next()
                .ok_or_else(|| "missing output file".to_string())?;
            if let Some((dup, close)) = parse_dup_target(&target)? {
                if dup == 1 {
                    current.stderr_to_stdout = true;
                    current.stderr_close = false;
                    current.stderr = None;
                    Ok(())
                } else if close {
                    current.stderr_close = true;
                    current.stderr_to_stdout = false;
                    current.stderr = None;
                    Ok(())
                } else {
                    Err("unsupported fd redirection".to_string())
                }
            } else {
                if current.stderr.is_some() {
                    return Err("multiple stderr redirections".to_string());
                }
                current.stderr = Some(OutputRedirection {
                    path: target,
                    append: op.ends_with(">>"),
                });
                current.stderr_to_stdout = false;
                current.stderr_close = false;
                Ok(())
            }
        }
        "&>" | "&>>" => {
            let path = iter
                .next()
                .ok_or_else(|| "missing output file".to_string())?;
            if current.stdout.is_some() || current.stderr.is_some() {
                return Err("multiple output redirections".to_string());
            }
            current.stdout = Some(OutputRedirection {
                path: path.clone(),
                append: op.ends_with(">>"),
            });
            current.stderr = Some(OutputRedirection {
                path,
                append: op.ends_with(">>"),
            });
            current.stderr_to_stdout = false;
            current.stderr_close = false;
            Ok(())
        }
        _ => Err("unsupported redirection".to_string()),
    }
}

enum InputRedirection {
    File(String),
    Heredoc(HeredocSpec),
    HereString(String),
}

fn set_input_redirection(current: &mut CommandSpec, input: InputRedirection) -> Result<(), String> {
    if current.stdin.is_some() || current.heredoc.is_some() || current.herestring.is_some() {
        return Err("multiple input redirections".to_string());
    }
    match input {
        InputRedirection::File(path) => current.stdin = Some(path),
        InputRedirection::Heredoc(spec) => current.heredoc = Some(spec),
        InputRedirection::HereString(content) => current.herestring = Some(content),
    }
    Ok(())
}

fn parse_dup_target(target: &str) -> Result<Option<(i32, bool)>, String> {
    let Some(rest) = target.strip_prefix('&') else {
        return Ok(None);
    };
    if rest == "-" {
        return Ok(Some((0, true)));
    }
    if rest.chars().all(|c| c.is_ascii_digit()) {
        let fd = rest
            .parse::<i32>()
            .map_err(|_| "invalid fd redirection".to_string())?;
        return Ok(Some((fd, false)));
    }
    Err("invalid fd redirection".to_string())
}

fn parse_fd_output_op(op: &str) -> Option<i32> {
    let (digits, op_tail) = op.split_at(op.chars().take_while(|c| c.is_ascii_digit()).count());
    if digits.is_empty() {
        return None;
    }
    if op_tail == ">" || op_tail == ">>" {
        return digits.parse::<i32>().ok();
    }
    None
}

pub(crate) fn try_parse_sandbox_directive(
    token: &str,
) -> Result<Option<SandboxDirective>, String> {
    let Some((key, value)) = token.split_once('=') else {
        return Ok(None);
    };
    if !key.eq_ignore_ascii_case("sandbox") {
        return Ok(None);
    }
    let value = strip_markers(value);
    let directive = crate::parse::parse_sandbox_value(&value)?;
    Ok(Some(directive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dup_target_accepts_close_and_dup() {
        assert_eq!(parse_dup_target("&-").unwrap(), Some((0, true)));
        assert_eq!(parse_dup_target("&1").unwrap(), Some((1, false)));
        assert_eq!(parse_dup_target("&2").unwrap(), Some((2, false)));
    }

    #[test]
    fn parse_dup_target_rejects_invalid() {
        assert!(parse_dup_target("&x").is_err());
        assert!(parse_dup_target("&1x").is_err());
    }
}

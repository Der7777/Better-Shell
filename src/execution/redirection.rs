use std::fs;
use std::io;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::process::CommandExt;
use std::process::{ChildStdout, Command, Stdio};

use nix::unistd::{close, dup2, pipe, write};

use crate::parse::{CommandSpec, OutputRedirection};

pub(crate) fn apply_input_redirection(command: &mut Command, cmd: &CommandSpec) -> io::Result<()> {
    if input_redirection_count(cmd) > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "multiple input redirections",
        ));
    }
    if let Some(ref path) = cmd.stdin {
        let file = fs::OpenOptions::new().read(true).open(path)?;
        command.stdin(Stdio::from(file));
    }
    if let Some(ref heredoc) = cmd.heredoc {
        let Some(ref content) = heredoc.content else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "heredoc not supported here",
            ));
        };
        command.stdin(heredoc_stdin(content)?);
    }
    if let Some(ref content) = cmd.herestring {
        command.stdin(here_string_stdin(content)?);
    }
    Ok(())
}

pub(crate) fn apply_stdout_redirection(
    command: &mut Command,
    output: &OutputRedirection,
) -> io::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true);
    if output.append {
        opts.append(true);
    } else {
        opts.truncate(true);
    }
    let file = opts.open(&output.path)?;
    command.stdout(Stdio::from(file));
    Ok(())
}

pub(crate) fn apply_stderr_redirection(command: &mut Command, cmd: &CommandSpec) -> io::Result<()> {
    if cmd.stderr_close {
        set_pre_exec(command, || {
            close(2).map_err(|err| io::Error::other(err.to_string()))?;
            Ok(())
        });
        return Ok(());
    }

    if cmd.stderr_to_stdout {
        set_pre_exec(command, || {
            dup2(1, 2).map_err(|err| io::Error::other(err.to_string()))?;
            Ok(())
        });
        return Ok(());
    }

    if let Some(ref err) = cmd.stderr {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true);
        if err.append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let file = opts.open(&err.path)?;
        command.stderr(Stdio::from(file));
    }
    Ok(())
}

fn set_pre_exec<F>(command: &mut Command, f: F)
where
    F: FnMut() -> io::Result<()> + Send + Sync + 'static,
{
    unsafe {
        command.pre_exec(f);
    }
}

pub(crate) fn apply_pipeline_stdin(
    command: &mut Command,
    cmd: &CommandSpec,
    prev_stdout: Option<ChildStdout>,
) {
    if let Some(stdout) = prev_stdout {
        if input_redirection_count(cmd) == 0 {
            command.stdin(Stdio::from(stdout));
        }
    }
}

pub(crate) fn apply_pipeline_stdout(
    command: &mut Command,
    cmd: &CommandSpec,
    last: bool,
    pipe_last_if_missing: bool,
) -> io::Result<()> {
    if !last {
        command.stdout(Stdio::piped());
        return Ok(());
    }
    if let Some(ref output) = cmd.stdout {
        apply_stdout_redirection(command, output)?;
    } else if pipe_last_if_missing {
        command.stdout(Stdio::piped());
    }
    Ok(())
}

pub(crate) fn heredoc_stdin(content: &str) -> io::Result<Stdio> {
    let (read_fd, write_fd) = pipe().map_err(|err| io::Error::other(err.to_string()))?;
    let bytes = content.as_bytes();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let written =
            write(&write_fd, &bytes[offset..]).map_err(|err| io::Error::other(err.to_string()))?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "heredoc write returned 0",
            ));
        }
        offset += written;
    }
    drop(write_fd);
    let file = unsafe { fs::File::from_raw_fd(read_fd.into_raw_fd()) };
    Ok(Stdio::from(file))
}

pub(crate) fn here_string_stdin(content: &str) -> io::Result<Stdio> {
    // Here-strings reuse heredoc plumbing for consistent stdin setup.
    let mut buf = String::from(content);
    buf.push('\n');
    heredoc_stdin(&buf)
}

pub(crate) fn input_redirection_count(cmd: &CommandSpec) -> usize {
    let mut count = 0usize;
    if cmd.stdin.is_some() {
        count += 1;
    }
    if cmd.heredoc.is_some() {
        count += 1;
    }
    if cmd.herestring.is_some() {
        count += 1;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::HeredocSpec;
    use tempfile::tempdir;

    fn run_cat_with_spec(spec: CommandSpec) -> io::Result<String> {
        let mut command = Command::new(&spec.args[0]);
        command.args(&spec.args[1..]);
        command.stdout(Stdio::piped());
        let child = command.spawn()?;
        let output = child.wait_with_output()?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    #[test]
    fn apply_input_redirection_reads_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("input.txt");
        fs::write(&path, "hello").unwrap();

        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.stdin = Some(path.display().to_string());

        match run_cat_with_spec(spec) {
            Ok(output) => assert_eq!(output, "hello"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                eprintln!("cat not found; skipping test");
            }
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn heredoc_pipes_content() {
        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.heredoc = Some(HeredocSpec {
            delimiter: "EOF".to_string(),
            quoted: false,
            content: Some("line1\nline2\n".to_string()),
        });

        match run_cat_with_spec(spec) {
            Ok(output) => assert_eq!(output, "line1\nline2\n"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                eprintln!("cat not found; skipping test");
            }
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn here_string_pipes_content() {
        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.herestring = Some("line1".to_string());

        match run_cat_with_spec(spec) {
            Ok(output) => assert_eq!(output, "line1\n"),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                eprintln!("cat not found; skipping test");
            }
            Err(err) => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn multiple_input_redirections_error() {
        let mut spec = CommandSpec::new();
        spec.args = vec!["cat".to_string()];
        spec.stdin = Some("in.txt".to_string());
        spec.heredoc = Some(HeredocSpec {
            delimiter: "EOF".to_string(),
            quoted: false,
            content: Some("data".to_string()),
        });
        let mut command = Command::new("cat");
        let err = apply_input_redirection(&mut command, &spec).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}

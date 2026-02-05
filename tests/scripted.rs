#![cfg(target_os = "linux")]

use std::io::Write;
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn run_script(script: &str) -> (String, String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_better_shell"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shell");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(script.as_bytes()).expect("write");
    }
    let output = child.wait_with_output().expect("wait");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(1);
    (stdout, stderr, code)
}

#[test]
fn scripted_basic_sequencing() {
    let script = "echo one; echo two\nexit 0\n";
    let (out, err, code) = run_script(script);
    assert!(err.is_empty(), "stderr: {err}");
    assert!(out.contains("one"));
    assert!(out.contains("two"));
    assert_eq!(code, 0);
}

#[test]
fn scripted_quoting_and_empty_args() {
    let script = "printf '%s|%s|%s\\n' \"ab\"\"cd\" \"\" \"e\"\nexit 0\n";
    let (out, err, code) = run_script(script);
    assert!(err.is_empty(), "stderr: {err}");
    assert!(out.contains("abcd||e"));
    assert_eq!(code, 0);
}

#[test]
fn scripted_glob_and_redirects() {
    let dir = TempDir::new().expect("tempdir");
    let a = dir.path().join("a.rs");
    let b = dir.path().join("b.rs");
    std::fs::write(&a, "a").unwrap();
    std::fs::write(&b, "b").unwrap();
    let script = format!(
        "cd {}\nls *.rs | wc -l > count.txt\ncat count.txt\nexit 0\n",
        dir.path().display()
    );
    let (out, err, code) = run_script(&script);
    assert!(err.is_empty(), "stderr: {err}");
    assert!(out.contains('2'));
    assert_eq!(code, 0);
}

#[test]
fn scripted_pipefail_option() {
    let script = "set -o pipefail\nfalse | true && echo ok\nexit 0\n";
    let (out, err, code) = run_script(script);
    assert!(err.is_empty(), "stderr: {err}");
    assert!(!out.contains("ok"));
    assert_eq!(code, 0);
}

#[test]
fn scripted_heredoc() {
    let script = "cat <<EOF\nhello\nEOF\nexit 0\n";
    let (out, err, code) = run_script(script);
    assert!(err.is_empty(), "stderr: {err}");
    assert!(out.contains("hello"));
    assert_eq!(code, 0);
}

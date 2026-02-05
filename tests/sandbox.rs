#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
use tempfile::tempdir;

#[cfg(target_os = "linux")]
const BWRAP_ARGS: &str = "--ro-bind / / --tmpfs /tmp --tmpfs /home --dev /dev --proc /proc \
--unshare-net --die-with-parent --setenv PATH /usr/bin --chdir /";

#[cfg(target_os = "linux")]
fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn run_shell(script: &str) -> std::process::Output {
    let exe = env!("CARGO_BIN_EXE_better_shell");
    let home = tempdir().expect("temp home");
    let mut cmd = Command::new(exe);
    cmd.arg("--sandbox=bwrap")
        .env("HOME", home.path())
        .env("MINISHELL_BWRAP_ARGS", BWRAP_ARGS)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn shell");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin.write_all(script.as_bytes()).expect("write script");
        stdin.write_all(b"\nexit\n").expect("write exit");
    }
    child.wait_with_output().expect("wait output")
}

#[test]
#[cfg_attr(not(feature = "sandbox"), ignore = "Sandbox feature not enabled")]
#[cfg(target_os = "linux")]
fn sandbox_fs_isolation() {
    if !bwrap_available() {
        eprintln!("bwrap not found");
        return;
    }
    let secret_path = format!("/tmp/host_secret_{}", std::process::id());
    let created_path = format!("/tmp/host_created_{}", std::process::id());
    fs::write(&secret_path, "topsecret").expect("write secret");

    let script = format!(
        "cat {secret_path} || echo denied\n\
touch {created_path}\n"
    );
    let output = run_shell(&script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("denied"),
        "expected denial marker in stdout, got: {stdout}"
    );
    assert!(
        !stdout.contains("topsecret"),
        "secret leaked to stdout: {stdout}"
    );
    assert!(
        stderr.contains("No such file or directory") || stderr.contains("Permission denied"),
        "expected missing/permission error, got: {stderr}"
    );
    assert!(
        !Path::new(&created_path).exists(),
        "sandbox created file on host: {created_path}"
    );
    let _ = fs::remove_file(&secret_path);
    let _ = fs::remove_file(&created_path);
}

#[test]
#[cfg_attr(not(feature = "sandbox"), ignore = "Sandbox feature not enabled")]
#[cfg(target_os = "linux")]
fn sandbox_network_isolation() {
    if !bwrap_available() {
        eprintln!("bwrap not found");
        return;
    }
    if !Path::new("/usr/bin/curl").exists() {
        eprintln!("curl not found in /usr/bin");
        return;
    }
    let script = "curl --connect-timeout 2 --max-time 3 -I https://example.com || echo netfail";
    let output = run_shell(script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lc = stderr.to_lowercase();

    assert!(
        stdout.contains("netfail"),
        "expected netfail marker in stdout, got: {stdout}"
    );
    assert!(
        stderr_lc.contains("network is unreachable")
            || stderr_lc.contains("could not resolve host")
            || stderr_lc.contains("failed to connect")
            || stderr_lc.contains("connection refused"),
        "unexpected curl error: {stderr}"
    );
}

#[test]
#[cfg_attr(not(feature = "sandbox"), ignore = "Sandbox feature not enabled")]
#[cfg(target_os = "linux")]
#[ignore = "seccomp filters not implemented yet"]
fn sandbox_seccomp_blocks_forbidden_syscall() {
    if !bwrap_available() {
        eprintln!("bwrap not found");
        return;
    }
    let script = "sh -c 'unshare -n true' || echo blocked";
    let output = run_shell(script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_lc = stderr.to_lowercase();

    assert!(
        stdout.contains("blocked"),
        "expected blocked marker in stdout, got: {stdout}"
    );
    assert!(
        stderr_lc.contains("operation not permitted")
            || stderr_lc.contains("permission denied")
            || stderr_lc.contains("not permitted"),
        "unexpected error for forbidden syscall: {stderr}"
    );
}

#[test]
#[cfg_attr(not(feature = "sandbox"), ignore = "Sandbox feature not enabled")]
#[cfg(target_os = "linux")]
#[ignore = "rlimits not implemented yet"]
fn sandbox_resource_caps_enforced() {
    if !bwrap_available() {
        eprintln!("bwrap not found");
        return;
    }
    let script = "sh -c 'ulimit -t 1; yes >/dev/null' || echo capped";
    let output = run_shell(script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stdout.contains("capped"),
        "expected capped marker in stdout, got: {stdout}"
    );
    assert!(
        stderr.contains("CPU") || stderr.contains("killed") || stderr.contains("resource"),
        "unexpected resource cap error: {stderr}"
    );
}

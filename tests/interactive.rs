#![cfg(all(target_os = "linux", feature = "pty-tests"))]

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use serial_test::serial;
use std::fs;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

struct PtySession {
    writer: Box<dyn Write + Send>,
    rx: Receiver<String>,
    buffer: String,
    pid: u32,
}

impl PtySession {
    fn spawn() -> anyhow::Result<Self> {
        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut cmd = CommandBuilder::new(bin_path());
        let child = pair.slave.spawn_command(cmd)?;
        let pid = child.process_id().unwrap_or(0);
        if pid == 0 {
            return Err(anyhow::anyhow!("failed to get child pid"));
        }

        let mut reader = pair.master.try_clone_reader()?;
        let writer = pair.master.take_writer()?;
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            writer,
            rx,
            buffer: String::new(),
            pid,
        })
    }

    fn send_line(&mut self, line: &str) -> anyhow::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }

    fn send_ctrl(&mut self, ch: u8) -> anyhow::Result<()> {
        self.writer.write_all(&[ch])?;
        self.writer.flush()?;
        Ok(())
    }

    fn read_until_prompt(&mut self, timeout: Duration) -> anyhow::Result<String> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            if let Ok(chunk) = self.rx.recv_timeout(Duration::from_millis(50)) {
                self.buffer.push_str(&chunk);
                if looks_like_prompt(&self.buffer) {
                    let out = self.buffer.clone();
                    self.buffer.clear();
                    return Ok(out);
                }
            }
        }
        Err(anyhow::anyhow!("timeout waiting for prompt"))
    }
}

fn looks_like_prompt(buf: &str) -> bool {
    buf.contains(" $ ")
}

fn bin_path() -> String {
    env!("CARGO_BIN_EXE_better_shell").to_string()
}

fn list_children(pid: u32) -> Vec<u32> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let Ok(content) = fs::read_to_string(path) else {
        return Vec::new();
    };
    content
        .split_whitespace()
        .filter_map(|part| part.parse::<u32>().ok())
        .collect()
}

fn is_zombie(pid: u32) -> bool {
    let path = format!("/proc/{pid}/stat");
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    let close = match content.rfind(')') {
        Some(pos) => pos,
        None => return false,
    };
    let state = content.get(close + 2..close + 3).unwrap_or("");
    state == "Z"
}

fn zombies_with_ppid(ppid: u32) -> Vec<u32> {
    let mut zombies = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return zombies;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(pid) = name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let close = match stat.rfind(')') {
            Some(pos) => pos,
            None => continue,
        };
        let fields = &stat[close + 2..];
        let mut parts = fields.split_whitespace();
        let state = parts.next().unwrap_or("");
        let ppid_field = parts.next().unwrap_or("");
        if state == "Z" && ppid_field == ppid.to_string() {
            zombies.push(pid);
        }
    }
    zombies
}

#[test]
#[serial]
fn pty_prompt_and_ctrl_c() -> anyhow::Result<()> {
    let mut session = PtySession::spawn()?;
    session.read_until_prompt(Duration::from_secs(5))?;
    session.send_line("echo hi")?;
    let output = session.read_until_prompt(Duration::from_secs(5))?;
    assert!(output.contains("hi"));
    session.send_line("sleep 5")?;
    thread::sleep(Duration::from_millis(100));
    session.send_ctrl(0x03)?;
    session.read_until_prompt(Duration::from_secs(5))?;
    session.send_line("exit")?;
    Ok(())
}

#[test]
#[serial]
fn background_pipeline_reaped() -> anyhow::Result<()> {
    let mut session = PtySession::spawn()?;
    session.read_until_prompt(Duration::from_secs(5))?;
    session.send_line("sleep 0.1 | cat &")?;
    session.read_until_prompt(Duration::from_secs(5))?;
    thread::sleep(Duration::from_millis(300));
    session.send_line("true")?;
    session.read_until_prompt(Duration::from_secs(5))?;
    let children = list_children(session.pid);
    let zombies: Vec<u32> = children.into_iter().filter(|pid| is_zombie(*pid)).collect();
    assert!(zombies.is_empty(), "zombie children found: {zombies:?}");
    session.send_line("exit")?;
    Ok(())
}

#[test]
#[serial]
fn stopped_job_then_exit_no_zombie() -> anyhow::Result<()> {
    let mut session = PtySession::spawn()?;
    let shell_pid = session.pid;
    session.read_until_prompt(Duration::from_secs(5))?;
    session.send_line("sleep 5")?;
    thread::sleep(Duration::from_millis(100));
    session.send_ctrl(0x1a)?;
    session.read_until_prompt(Duration::from_secs(2))?;
    session.send_line("exit")?;
    thread::sleep(Duration::from_millis(200));
    let zombies = zombies_with_ppid(shell_pid);
    assert!(
        zombies.is_empty(),
        "zombies with ppid {shell_pid}: {zombies:?}"
    );
    Ok(())
}

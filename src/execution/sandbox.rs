use std::io;
use std::process::Command;

use crate::parse::{CommandSpec, SandboxDirective};

#[cfg(feature = "sandbox")]
use std::ffi::CString;
#[cfg(feature = "sandbox")]
use std::os::unix::ffi::OsStrExt;

// Two backends: bubblewrap for stronger isolation, native for broad compatibility.
#[derive(Debug, Clone, Copy)]
pub enum SandboxBackend {
    Bubblewrap,
    Native,
}

// Persistent config loaded from env/config files.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub enabled: bool,
    pub backend: SandboxBackend,
    pub bubblewrap_path: Option<String>,
    pub bubblewrap_args: Vec<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: SandboxBackend::Native,
            bubblewrap_path: None,
            bubblewrap_args: Vec::new(),
        }
    }
}

// Per-command options computed from config and inline directives.
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "sandbox"), allow(dead_code))]
pub struct SandboxOptions {
    pub trace: bool,
    pub backend: SandboxBackend,
    pub bubblewrap_path: Option<String>,
    pub bubblewrap_args: Vec<String>,
}

impl Default for SandboxOptions {
    fn default() -> Self {
        Self {
            trace: false,
            backend: SandboxBackend::Native,
            bubblewrap_path: None,
            bubblewrap_args: Vec::new(),
        }
    }
}

pub fn apply_sandbox_directive(sandbox: &mut SandboxConfig, directive: SandboxDirective) {
    match directive {
        SandboxDirective::Enable => sandbox.enabled = true,
        SandboxDirective::Disable => sandbox.enabled = false,
        SandboxDirective::Bubblewrap => {
            sandbox.enabled = true;
            sandbox.backend = SandboxBackend::Bubblewrap;
        }
        SandboxDirective::Native => {
            sandbox.enabled = true;
            sandbox.backend = SandboxBackend::Native;
        }
    }
}

pub fn sandbox_options_for_command(
    cmd: &CommandSpec,
    sandbox: &SandboxConfig,
    trace: bool,
) -> Option<SandboxOptions> {
    // Allow per-command sandbox overrides without mutating global config.
    let mut enabled = sandbox.enabled;
    let mut backend = sandbox.backend;
    if let Some(directive) = cmd.sandbox {
        match directive {
            SandboxDirective::Enable => enabled = true,
            SandboxDirective::Disable => enabled = false,
            SandboxDirective::Bubblewrap => {
                enabled = true;
                backend = SandboxBackend::Bubblewrap;
            }
            SandboxDirective::Native => {
                enabled = true;
                backend = SandboxBackend::Native;
            }
        }
    }
    if !enabled {
        return None;
    }
    Some(SandboxOptions {
        trace,
        backend,
        bubblewrap_path: sandbox.bubblewrap_path.clone(),
        bubblewrap_args: sandbox.bubblewrap_args.clone(),
    })
}

pub(crate) fn apply_sandbox(command: &mut Command, options: &SandboxOptions) -> io::Result<()> {
    #[cfg(feature = "sandbox")]
    {
        match options.backend {
            SandboxBackend::Bubblewrap => {
                let program = command.get_program().to_os_string();
                let args: Vec<_> = command.get_args().map(|arg| arg.to_os_string()).collect();
                let bwrap_path = options
                    .bubblewrap_path
                    .unwrap_or_else(|| "bwrap".to_string());
                let bwrap_path_os = std::ffi::OsString::from(bwrap_path);
                let mut bwrap_args = options
                    .bubblewrap_args
                    .iter()
                    .map(|arg| arg.into())
                    .collect::<Vec<_>>();
                bwrap_args.push("--".into());
                bwrap_args.push(program);
                bwrap_args.extend(args);
                set_pre_exec(command, move || {
                    execvp_os(&bwrap_path_os, &bwrap_args).map_err(|err| {
                        io::Error::new(err.kind(), format!("bwrap exec failed: {err}"))
                    })
                });
                Ok(())
            }
            SandboxBackend::Native => {
                let _ = command;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "native sandbox backend not implemented; use bubblewrap or disable sandbox",
                ))
            }
        }
    }
    #[cfg(not(feature = "sandbox"))]
    {
        let _ = (command, options);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sandbox feature disabled",
        ))
    }
}

#[cfg(feature = "sandbox")]
fn set_pre_exec<F>(command: &mut Command, f: F)
where
    F: FnMut() -> io::Result<()> + Send + Sync + 'static,
{
    unsafe {
        command.pre_exec(f);
    }
}

#[cfg(feature = "sandbox")]
fn execvp_os(program: &std::ffi::OsStr, args: &[std::ffi::OsString]) -> io::Result<()> {
    let prog_c = CString::new(program.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "program contains null"))?;
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(prog_c.clone());
    for arg in args {
        let cstr = CString::new(arg.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "argument contains null"))?;
        argv.push(cstr);
    }
    nix::unistd::execvp(&prog_c, &argv).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(())
}

#[cfg(feature = "sandbox")]
#[allow(dead_code)]
fn native_sandbox_exec(
    program: &std::ffi::OsString,
    args: &[std::ffi::OsString],
) -> io::Result<()> {
    // Placeholder for advanced native sandbox setup.
    execvp_os(program, args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_backend_is_explicitly_unsupported() {
        let options = SandboxOptions {
            trace: false,
            backend: SandboxBackend::Native,
            bubblewrap_path: None,
            bubblewrap_args: Vec::new(),
        };
        let mut command = Command::new("true");
        let err = apply_sandbox(&mut command, &options).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}

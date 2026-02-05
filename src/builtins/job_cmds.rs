use std::fmt::Write;
use std::io;

use crate::job_control::{
    bring_job_foreground, continue_job, find_job, parse_job_id, take_job, JobStatus,
};
use crate::ShellState;

pub(crate) fn handle_fg(
    state: &mut ShellState,
    args: &[String],
    _output: &mut String,
) -> io::Result<()> {
    let job_id = parse_job_id(args.get(1))?;
    let job = match take_job(&mut state.jobs, job_id) {
        Some(job) => job,
        None => {
            eprintln!("fg: no such job");
            state.last_status = 1;
            return Ok(());
        }
    };
    match bring_job_foreground(job, &state.fg_pgid, state.shell_pgid) {
        Ok(result) => {
            if let Some(stopped) = result.stopped_job {
                state.jobs.push(stopped);
            }
            state.last_status = result.status_code.unwrap_or(0);
        }
        Err(err) => {
            eprintln!("fg: {err}");
            state.last_status = 1;
        }
    }
    Ok(())
}

pub(crate) fn handle_bg(
    state: &mut ShellState,
    args: &[String],
    output: &mut String,
) -> io::Result<()> {
    let job_id = parse_job_id(args.get(1))?;
    let job = match find_job(&mut state.jobs, job_id) {
        Some(job) => job,
        None => {
            eprintln!("bg: no such job");
            state.last_status = 1;
            return Ok(());
        }
    };
    if let Err(err) = continue_job(job.pgid) {
        eprintln!("bg: {err}");
        state.last_status = 1;
    } else {
        job.status = JobStatus::Running;
        let _ = writeln!(output, "[{}] Running {}", job.id, job.command);
        state.last_status = 0;
    }
    Ok(())
}

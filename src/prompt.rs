use std::path::Path;
use std::process::Command;

use crate::colors::{resolve_color, ColorConfig};

#[derive(Clone, Copy, Debug)]
pub enum PromptTheme {
    Fish,
    Classic,
    Minimal,
}

pub fn parse_prompt_theme(value: &str) -> Option<PromptTheme> {
    match value.trim().to_lowercase().as_str() {
        "fish" | "default" => Some(PromptTheme::Fish),
        "classic" => Some(PromptTheme::Classic),
        "minimal" => Some(PromptTheme::Minimal),
        _ => None,
    }
}

pub fn render_prompt_template(template: &str, last_status: i32, cwd: &Path) -> String {
    let status_str = last_status.to_string();
    let status_opt = if last_status == 0 { "" } else { &status_str };
    let mut out = template.replace("{status?}", status_opt);
    out = out.replace("{status}", &status_str);
    out = out.replace("{cwd}", &cwd.display().to_string());
    out
}

pub fn render_prompt_theme(
    theme: PromptTheme,
    colors: &ColorConfig,
    last_status: i32,
    cwd: &Path,
) -> String {
    match theme {
        PromptTheme::Classic => {
            if last_status == 0 {
                format!("{} $ ", cwd.display())
            } else {
                format!("[{}] {} $ ", last_status, cwd.display())
            }
        }
        PromptTheme::Minimal => "> ".to_string(),
        PromptTheme::Fish => render_fish_prompt(colors, last_status, cwd),
    }
}

fn render_fish_prompt(colors: &ColorConfig, last_status: i32, cwd: &Path) -> String {
    let reset = "\x1b[0m";
    let status_color = resolve_color(&colors.prompt_status);
    let cwd_color = resolve_color(&colors.prompt_cwd);
    let git_color = resolve_color(&colors.prompt_git);
    let symbol_color = resolve_color(&colors.prompt_symbol);
    let status = if last_status == 0 {
        String::new()
    } else if status_color.is_empty() {
        format!("[{last_status}] ")
    } else {
        format!("{status_color}[{last_status}]{reset} ")
    };
    let git = git_prompt_info(cwd)
        .map(|info| {
            if git_color.is_empty() {
                format!("{info} ")
            } else {
                format!("{git_color}{info}{reset} ")
            }
        })
        .unwrap_or_default();
    let cwd_text = if cwd_color.is_empty() {
        cwd.display().to_string()
    } else {
        format!("{cwd_color}{}{reset}", cwd.display())
    };
    let symbol = if symbol_color.is_empty() {
        ">".to_string()
    } else {
        format!("{symbol_color}>{reset}")
    };
    format!("{status}{cwd_text} {git}{symbol} ")
}

fn git_prompt_info(cwd: &Path) -> Option<String> {
    let inside = Command::new("git")
        .arg("rev-parse")
        .arg("--is-inside-work-tree")
        .current_dir(cwd)
        .output()
        .ok()?;
    if !inside.status.success() {
        return None;
    }
    let branch_out = Command::new("git")
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .current_dir(cwd)
        .output()
        .ok()?;
    if !branch_out.status.success() {
        return None;
    }
    let mut branch = String::from_utf8_lossy(&branch_out.stdout)
        .trim()
        .to_string();
    if branch == "HEAD" {
        let hash_out = Command::new("git")
            .arg("rev-parse")
            .arg("--short")
            .arg("HEAD")
            .current_dir(cwd)
            .output()
            .ok()?;
        if hash_out.status.success() {
            branch = String::from_utf8_lossy(&hash_out.stdout).trim().to_string();
        }
    }
    let status_out = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .current_dir(cwd)
        .output()
        .ok()?;
    let dirty = status_out.status.success()
        && !String::from_utf8_lossy(&status_out.stdout)
            .trim()
            .is_empty();
    if dirty {
        Some(format!("({branch}*)"))
    } else {
        Some(format!("({branch})"))
    }
}

use std::env;
use std::fs;
use std::io;

#[derive(Clone, Debug)]
pub struct ColorConfig {
    pub prompt_status: String,
    pub prompt_cwd: String,
    pub prompt_git: String,
    pub prompt_symbol: String,
    pub hint: String,
}

impl Default for ColorConfig {
    fn default() -> Self {
        Self {
            prompt_status: "red".to_string(),
            prompt_cwd: "cyan".to_string(),
            prompt_git: "yellow".to_string(),
            prompt_symbol: "green".to_string(),
            hint: "bright_black".to_string(),
        }
    }
}

pub fn resolve_color(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return String::new();
    }
    if let Some(rest) = trimmed.strip_prefix("ansi:") {
        return rest.to_string();
    }
    if trimmed.contains("\x1b") {
        return trimmed.to_string();
    }
    match trimmed.to_lowercase().as_str() {
        "black" => "\x1b[30m",
        "red" => "\x1b[31m",
        "green" => "\x1b[32m",
        "yellow" => "\x1b[33m",
        "blue" => "\x1b[34m",
        "magenta" => "\x1b[35m",
        "cyan" => "\x1b[36m",
        "white" => "\x1b[37m",
        "bright_black" | "gray" | "grey" => "\x1b[90m",
        "bright_red" => "\x1b[91m",
        "bright_green" => "\x1b[92m",
        "bright_yellow" => "\x1b[93m",
        "bright_blue" => "\x1b[94m",
        "bright_magenta" => "\x1b[95m",
        "bright_cyan" => "\x1b[96m",
        "bright_white" => "\x1b[97m",
        "bold" => "\x1b[1m",
        "dim" => "\x1b[2m",
        _ => "",
    }
    .to_string()
}

pub fn apply_color_setting(config: &mut ColorConfig, key: &str, value: &str) -> Result<(), String> {
    match key {
        "prompt_status" => config.prompt_status = value.to_string(),
        "prompt_cwd" => config.prompt_cwd = value.to_string(),
        "prompt_git" => config.prompt_git = value.to_string(),
        "prompt_symbol" => config.prompt_symbol = value.to_string(),
        "hint" => config.hint = value.to_string(),
        _ => return Err(format!("unknown color key '{key}'")),
    }
    Ok(())
}

pub fn format_color_lines(config: &ColorConfig) -> Vec<String> {
    vec![
        format!("color.prompt_status={}", config.prompt_status),
        format!("color.prompt_cwd={}", config.prompt_cwd),
        format!("color.prompt_git={}", config.prompt_git),
        format!("color.prompt_symbol={}", config.prompt_symbol),
        format!("color.hint={}", config.hint),
    ]
}

pub fn save_colors(config: &ColorConfig) -> io::Result<()> {
    let Some(home) = env::var("HOME").ok() else {
        return Ok(());
    };
    let path = format!("{home}/.minishell_colors");
    let content = format_color_lines(config).join("\n");
    fs::write(
        path,
        if content.is_empty() {
            content
        } else {
            format!("{content}\n")
        },
    )
}

pub fn load_color_lines(config: &mut ColorConfig, content: &str) {
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            eprintln!("colors:{}: invalid line", idx + 1);
            continue;
        };
        let key = key.trim().strip_prefix("color.").unwrap_or(key.trim());
        let value = value.trim();
        if let Err(err) = apply_color_setting(config, key, value) {
            eprintln!("colors:{}: {err}", idx + 1);
        }
    }
}

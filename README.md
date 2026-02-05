# Better Shell

A minimal Rust shell with job control, pipelines, redirection, and a small scripting layer.

## Build

```
cargo build --bins
```

## Library API (parse + expansion)

The crate exports a minimal parser/expansion API for fuzzing and unit tests:

- `parse_tokens`
- `parse_sequence`
- `parse_pipeline`

When built with the `expansion` feature, it also exports:

- `expand_tokens`
- `expand_token`
- `expand_globs`
- `glob_pattern`

## Module overview

- `src/repl.rs`: interactive loop, editor integration, and top-level shell state.
- `src/parse/`: tokenization, command parsing, and redirection parsing.
- `src/expansion/`: parameter/command substitution and glob expansion.
- `src/execution/`: spawning, redirection plumbing, pipelines, and sandbox adapters.
- `src/builtins/`: core builtins, control flow, scripting helpers, and config commands.
- `src/job_control.rs`: job tracking, process groups, and SIGCHLD handling.

## Implementation notes

- `src/repl.rs` owns the interactive loop, state, and job tracking. Each input line is parsed
  into a sequence, then expanded and executed segment-by-segment to preserve `&&/||` semantics.
- `src/parse/` splits tokenization, command parsing, and redirection parsing. Operator tokens
  are marked with a sentinel byte to preserve exact operator boundaries through expansion.
- `src/expansion/` handles parameter/command substitution and glob expansion. Globs are
  expanded after parameter substitution to avoid accidental globbing in quoted segments.
- `src/execution/` contains pipeline orchestration, spawning, and sandbox adapters. Foreground
  jobs use a process group so job control (fg/bg, stops) behaves predictably.

## Marker system

The parser uses three marker bytes to preserve intent across phases:

- `OPERATOR_TOKEN_MARKER` prefixes operator tokens so operators survive expansion unchanged.
- `NOGLOB_MARKER` tags characters that must not be globbed (for example, from double quotes).
- `ESCAPE_MARKER` records escaped literals so they stay literal through expansion.

## Test

```
cargo test
```

## Config (`~/.minishellrc`)

Supported directives:

- `alias ll='ls -la'`
- `export VAR=value`
- `prompt = {cwd} $ `

Notes:
- `prompt` supports `{cwd}`, `{status}`, and `{status?}`.
- Set `MINISHELL_EDITMODE=vi` in your environment to enable vi mode for line editing.
- Set `MINISHELL_LOG=debug` (or `RUST_LOG`) to control log verbosity.

## Fuzz (optional)

```
cargo fuzz run parser
```

## Security notes

By default, this shell does not sandbox execution. Do not run untrusted scripts or binaries.
The optional `sandbox` feature lets you run commands with `sandbox=yes` or `--sandbox`, but it is not a security boundary unless configured correctly.
For isolation, run inside a container/VM or wrap with OS-level sandboxes (e.g., seccomp, namespaces, chroot), and consider dropping privileges before executing commands.
Command substitution runs with the full environment and privileges of the shell unless sandboxing is enabled.

## CI

GitHub Actions runs `cargo fmt --check`, `cargo clippy`, and `cargo test` on push/PR.

If you're reading this, you're probably a nerd. Feel free to explore the code!

## Troubleshooting

- `parse error: missing redirection target`: a redirection operator has no following path.
- `pipes only work with external commands`: builtins do not run in pipelines here.
- `background jobs only work with external commands`: builtins cannot be backgrounded.
- `config: unknown theme`: check `prompt_theme` value in `~/.minishellrc`.

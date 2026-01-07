use rustyline::history::DefaultHistory;
use rustyline::Editor;

use crate::completion::LineHelper;
use crate::io_helpers::read_heredoc;
use crate::parse::CommandSpec;

pub fn fill_heredocs(
    pipeline: &mut [CommandSpec],
    interactive: bool,
    editor: &mut Editor<LineHelper, DefaultHistory>,
) -> Result<(), String> {
    let mut editor = if interactive { Some(editor) } else { None };
    for cmd in pipeline.iter_mut() {
        let Some(ref mut heredoc) = cmd.heredoc else {
            continue;
        };
        if heredoc.content.is_some() {
            continue;
        }
        let content = read_heredoc(editor.as_deref_mut(), interactive, &heredoc.delimiter)?;
        heredoc.content = Some(content);
    }
    Ok(())
}

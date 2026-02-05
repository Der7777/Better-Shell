use glob::glob;

use crate::parse::{strip_markers, ESCAPE_MARKER, NOGLOB_MARKER, OPERATOR_TOKEN_MARKER};

pub fn expand_globs(tokens: Vec<String>) -> Result<Vec<String>, String> {
    let mut expanded = Vec::new();
    for token in tokens {
        if token.starts_with(OPERATOR_TOKEN_MARKER) {
            expanded.push(token);
            continue;
        }
        let (pattern, has_glob) = glob_pattern(&token);
        if has_glob {
            let mut matches = Vec::new();
            for entry in glob(&pattern).map_err(|err| format!("glob error: {err}"))? {
                match entry {
                    Ok(path) => matches.push(path.display().to_string()),
                    Err(err) => return Err(format!("glob error: {err}")),
                }
            }
            if matches.is_empty() {
                expanded.push(strip_markers(&token));
            } else {
                matches.sort();
                expanded.extend(matches);
            }
        } else {
            expanded.push(strip_markers(&token));
        }
    }
    Ok(expanded)
}

pub fn glob_pattern(token: &str) -> (String, bool) {
    let mut pattern = String::new();
    let mut has_glob = false;
    let mut chars = token.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == ESCAPE_MARKER || ch == NOGLOB_MARKER {
            if let Some(next) = chars.next() {
                pattern.push(next);
            }
            continue;
        }
        if ch == '*' || ch == '?' {
            has_glob = true;
        }
        pattern.push(ch);
    }

    (pattern, has_glob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    #[test]
    fn expand_globs_matches_and_sorts() {
        let dir = tempdir().unwrap();
        let p1 = dir.path().join("a.rs");
        let p2 = dir.path().join("b.rs");
        let p3 = dir.path().join("c.txt");
        std::fs::write(&p1, "a").unwrap();
        std::fs::write(&p2, "b").unwrap();
        std::fs::write(&p3, "c").unwrap();

        let pattern = format!("{}/{}.rs", dir.path().display(), "*");
        let expanded = expand_globs(vec![pattern]).unwrap();
        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0], p1.display().to_string());
        assert_eq!(expanded[1], p2.display().to_string());
    }

    #[test]
    fn expand_globs_globstar_recursive() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let nested = root.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();
        let f1 = root.join("root.rs");
        let f2 = nested.join("deep.rs");
        std::fs::write(&f1, "root").unwrap();
        std::fs::write(&f2, "deep").unwrap();

        let pattern = format!("{}/**/*.rs", root.display());
        let expanded = expand_globs(vec![pattern]).unwrap();
        assert!(expanded.contains(&f1.display().to_string()));
        assert!(expanded.contains(&f2.display().to_string()));
    }

    proptest! {
        #[test]
        fn glob_pattern_no_wildcards_no_glob(s in "[^\u{1d}\u{1e}\u{1f}*?]{0,32}") {
            let (pattern, has_glob) = glob_pattern(&s);
            prop_assert_eq!(pattern, s);
            prop_assert!(!has_glob);
        }

        #[test]
        fn glob_pattern_detects_wildcards(prefix in "[^\u{1d}\u{1e}\u{1f}]{0,16}", suffix in "[^\u{1d}\u{1e}\u{1f}]{0,16}", wildcard in prop_oneof![Just('*'), Just('?')]) {
            let mut input = prefix;
            input.push(wildcard);
            input.push_str(&suffix);
            let (_, has_glob) = glob_pattern(&input);
            prop_assert!(has_glob);
        }
    }
}

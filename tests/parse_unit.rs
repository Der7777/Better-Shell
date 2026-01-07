use custom_shell::{parse_pipeline, parse_sequence, parse_tokens, SeqOp};

#[test]
fn pipeline_black_box() {
    let tokens = parse_tokens("echo hi | cat").unwrap();
    let (pipeline, background) = parse_pipeline(tokens).unwrap();
    assert!(!background);
    assert_eq!(pipeline.len(), 2);
    assert_eq!(pipeline[0].args, vec!["echo", "hi"]);
    assert_eq!(pipeline[1].args, vec!["cat"]);
}

#[test]
fn sequence_black_box() {
    let tokens = parse_tokens("a && b || c ; d").unwrap();
    let segments = parse_sequence(tokens).unwrap();
    assert_eq!(segments.len(), 4);
    assert!(matches!(segments[0].op, SeqOp::Always));
    assert!(matches!(segments[1].op, SeqOp::And));
    assert!(matches!(segments[2].op, SeqOp::Or));
    assert!(matches!(segments[3].op, SeqOp::Always));
}

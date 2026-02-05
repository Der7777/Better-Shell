use std::env;

use crate::parse::strip_markers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Lt,
    Le,
    Gt,
    Ge,
    Eq,
    Ne,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    UnaryPlus,
    UnaryMinus,
    Not,
    BitNot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Num(i64),
    Op(Op),
    LParen,
    RParen,
}

pub fn eval_arithmetic(expr: &str) -> Result<i64, String> {
    let stripped = strip_markers(expr);
    let tokens = tokenize(&stripped)?;
    let rpn = to_rpn(&tokens)?;
    eval_rpn(&rpn)
}

fn tokenize(expr: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = expr.chars().peekable();
    let mut prev_is_op = true;

    while let Some(ch) = chars.peek().copied() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch.is_ascii_digit() {
            let mut buf = String::new();
            while let Some(c) = chars.peek().copied() {
                if c.is_ascii_hexdigit() || c == 'x' || c == 'X' {
                    buf.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            let value = if buf.starts_with("0x") || buf.starts_with("0X") {
                i64::from_str_radix(buf.trim_start_matches("0x").trim_start_matches("0X"), 16)
                    .map_err(|_| "invalid hex literal".to_string())?
            } else {
                buf.parse::<i64>()
                    .map_err(|_| "invalid number".to_string())?
            };
            tokens.push(Token::Num(value));
            prev_is_op = false;
            continue;
        }
        if is_ident_start(ch) {
            let mut name = String::new();
            while let Some(c) = chars.peek().copied() {
                if is_ident_char(c) {
                    name.push(c);
                    chars.next();
                } else {
                    break;
                }
            }
            let value = env::var(&name)
                .ok()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            tokens.push(Token::Num(value));
            prev_is_op = false;
            continue;
        }

        let op_token = match ch {
            '(' => {
                chars.next();
                tokens.push(Token::LParen);
                prev_is_op = true;
                continue;
            }
            ')' => {
                chars.next();
                tokens.push(Token::RParen);
                prev_is_op = false;
                continue;
            }
            '+' => {
                chars.next();
                if prev_is_op {
                    Token::Op(Op::UnaryPlus)
                } else {
                    Token::Op(Op::Add)
                }
            }
            '-' => {
                chars.next();
                if prev_is_op {
                    Token::Op(Op::UnaryMinus)
                } else {
                    Token::Op(Op::Sub)
                }
            }
            '!' => {
                chars.next();
                if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::Ne)
                } else {
                    Token::Op(Op::Not)
                }
            }
            '~' => {
                chars.next();
                Token::Op(Op::BitNot)
            }
            '*' => {
                chars.next();
                Token::Op(Op::Mul)
            }
            '/' => {
                chars.next();
                Token::Op(Op::Div)
            }
            '%' => {
                chars.next();
                Token::Op(Op::Mod)
            }
            '<' => {
                chars.next();
                if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::Le)
                } else if matches!(chars.peek(), Some('<')) {
                    chars.next();
                    Token::Op(Op::Shl)
                } else {
                    Token::Op(Op::Lt)
                }
            }
            '>' => {
                chars.next();
                if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::Ge)
                } else if matches!(chars.peek(), Some('>')) {
                    chars.next();
                    Token::Op(Op::Shr)
                } else {
                    Token::Op(Op::Gt)
                }
            }
            '=' => {
                chars.next();
                if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::Eq)
                } else {
                    return Err("unexpected '='".to_string());
                }
            }
            '&' => {
                chars.next();
                if matches!(chars.peek(), Some('&')) {
                    chars.next();
                    Token::Op(Op::And)
                } else {
                    Token::Op(Op::BitAnd)
                }
            }
            '|' => {
                chars.next();
                if matches!(chars.peek(), Some('|')) {
                    chars.next();
                    Token::Op(Op::Or)
                } else {
                    Token::Op(Op::BitOr)
                }
            }
            '^' => {
                chars.next();
                Token::Op(Op::BitXor)
            }
            _ => return Err(format!("unexpected character '{ch}'")),
        };

        tokens.push(op_token);
        prev_is_op = true;
    }

    Ok(tokens)
}

fn to_rpn(tokens: &[Token]) -> Result<Vec<Token>, String> {
    let mut output = Vec::new();
    let mut ops: Vec<Token> = Vec::new();

    for token in tokens {
        match token {
            Token::Num(_) => output.push(token.clone()),
            Token::LParen => ops.push(Token::LParen),
            Token::RParen => {
                while let Some(top) = ops.pop() {
                    if matches!(top, Token::LParen) {
                        break;
                    }
                    output.push(top);
                }
            }
            Token::Op(op) => {
                while let Some(top) = ops.last() {
                    if let Token::Op(top_op) = top {
                        let (prec1, right_assoc1) = precedence(*op);
                        let (prec2, _) = precedence(*top_op);
                        if prec2 > prec1 || (prec2 == prec1 && !right_assoc1) {
                            output.push(ops.pop().unwrap());
                            continue;
                        }
                    }
                    break;
                }
                ops.push(Token::Op(*op));
            }
        }
    }

    while let Some(top) = ops.pop() {
        if matches!(top, Token::LParen | Token::RParen) {
            return Err("mismatched parentheses".to_string());
        }
        output.push(top);
    }

    Ok(output)
}

fn eval_rpn(tokens: &[Token]) -> Result<i64, String> {
    let mut stack: Vec<i64> = Vec::new();
    for token in tokens {
        match token {
            Token::Num(n) => stack.push(*n),
            Token::Op(op) => {
                if is_unary(*op) {
                    let val = stack.pop().ok_or_else(|| "missing operand".to_string())?;
                    let out = match op {
                        Op::UnaryPlus => val,
                        Op::UnaryMinus => -val,
                        Op::Not => (val == 0) as i64,
                        Op::BitNot => !val,
                        _ => return Err("invalid unary operator".to_string()),
                    };
                    stack.push(out);
                } else {
                    let rhs = stack.pop().ok_or_else(|| "missing operand".to_string())?;
                    let lhs = stack.pop().ok_or_else(|| "missing operand".to_string())?;
                    let out = match op {
                        Op::Add => lhs + rhs,
                        Op::Sub => lhs - rhs,
                        Op::Mul => lhs * rhs,
                        Op::Div => {
                            if rhs == 0 {
                                return Err("division by zero".to_string());
                            }
                            lhs / rhs
                        }
                        Op::Mod => {
                            if rhs == 0 {
                                return Err("division by zero".to_string());
                            }
                            lhs % rhs
                        }
                        Op::Lt => (lhs < rhs) as i64,
                        Op::Le => (lhs <= rhs) as i64,
                        Op::Gt => (lhs > rhs) as i64,
                        Op::Ge => (lhs >= rhs) as i64,
                        Op::Eq => (lhs == rhs) as i64,
                        Op::Ne => (lhs != rhs) as i64,
                        Op::And => ((lhs != 0) && (rhs != 0)) as i64,
                        Op::Or => ((lhs != 0) || (rhs != 0)) as i64,
                        Op::BitAnd => lhs & rhs,
                        Op::BitOr => lhs | rhs,
                        Op::BitXor => lhs ^ rhs,
                        Op::Shl => lhs << rhs,
                        Op::Shr => lhs >> rhs,
                        _ => return Err("invalid operator".to_string()),
                    };
                    stack.push(out);
                }
            }
            _ => return Err("invalid token in expression".to_string()),
        }
    }

    if stack.len() != 1 {
        return Err("invalid expression".to_string());
    }
    Ok(stack[0])
}

fn precedence(op: Op) -> (u8, bool) {
    match op {
        Op::UnaryPlus | Op::UnaryMinus | Op::Not | Op::BitNot => (7, true),
        Op::Mul | Op::Div | Op::Mod => (6, false),
        Op::Add | Op::Sub => (5, false),
        Op::Shl | Op::Shr => (4, false),
        Op::Lt | Op::Le | Op::Gt | Op::Ge => (3, false),
        Op::Eq | Op::Ne => (2, false),
        Op::BitAnd => (1, false),
        Op::BitXor => (1, false),
        Op::BitOr => (1, false),
        Op::And => (0, false),
        Op::Or => (0, false),
    }
}

fn is_unary(op: Op) -> bool {
    matches!(op, Op::UnaryPlus | Op::UnaryMinus | Op::Not | Op::BitNot)
}

fn is_ident_start(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphabetic()
}

fn is_ident_char(ch: char) -> bool {
    ch == '_' || ch.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_basic_ops() {
        assert_eq!(eval_arithmetic("1+2*3").unwrap(), 7);
        assert_eq!(eval_arithmetic("(1+2)*3").unwrap(), 9);
        assert_eq!(eval_arithmetic("10/2+3").unwrap(), 8);
        assert_eq!(eval_arithmetic("10%3").unwrap(), 1);
    }

    #[test]
    fn arithmetic_comparisons_and_logic() {
        assert_eq!(eval_arithmetic("1<2").unwrap(), 1);
        assert_eq!(eval_arithmetic("1==2").unwrap(), 0);
        assert_eq!(eval_arithmetic("1&&0").unwrap(), 0);
        assert_eq!(eval_arithmetic("1||0").unwrap(), 1);
        assert_eq!(eval_arithmetic("!0").unwrap(), 1);
    }
}

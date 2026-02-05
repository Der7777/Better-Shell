use std::env;

use crate::parse::strip_markers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Pow,
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
    Assign,
    AddAssign,
    SubAssign,
    MulAssign,
    DivAssign,
    ModAssign,
    Inc,
    Dec,
    UnaryPlus,
    UnaryMinus,
    Not,
    BitNot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Num(i64),
    Ident(String),
    Op(Op),
    LParen,
    RParen,
}

pub fn eval_arithmetic(expr: &str) -> Result<i64, String> {
    let stripped = strip_markers(expr);
    let tokens = tokenize(&stripped)?;
    let mut parser = Parser::new(tokens);
    let value = parser.parse_expr(0)?.value;
    if parser.peek().is_some() {
        return Err("unexpected tokens at end of expression".to_string());
    }
    Ok(value)
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
            tokens.push(Token::Ident(name));
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
                if matches!(chars.peek(), Some('+')) {
                    chars.next();
                    Token::Op(Op::Inc)
                } else if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::AddAssign)
                } else if prev_is_op {
                    Token::Op(Op::UnaryPlus)
                } else {
                    Token::Op(Op::Add)
                }
            }
            '-' => {
                chars.next();
                if matches!(chars.peek(), Some('-')) {
                    chars.next();
                    Token::Op(Op::Dec)
                } else if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::SubAssign)
                } else if prev_is_op {
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
                if matches!(chars.peek(), Some('*')) {
                    chars.next();
                    Token::Op(Op::Pow)
                } else if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::MulAssign)
                } else {
                    Token::Op(Op::Mul)
                }
            }
            '/' => {
                chars.next();
                if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::DivAssign)
                } else {
                    Token::Op(Op::Div)
                }
            }
            '%' => {
                chars.next();
                if matches!(chars.peek(), Some('=')) {
                    chars.next();
                    Token::Op(Op::ModAssign)
                } else {
                    Token::Op(Op::Mod)
                }
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
                    Token::Op(Op::Assign)
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

#[derive(Clone)]
struct ExprValue {
    value: i64,
    lvalue: Option<String>,
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        if self.pos >= self.tokens.len() {
            return None;
        }
        let tok = self.tokens[self.pos].clone();
        self.pos += 1;
        Some(tok)
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<ExprValue, String> {
        let mut lhs = self.parse_prefix()?;

        loop {
            let op = match self.peek() {
                Some(Token::Op(op)) => *op,
                _ => break,
            };

            // Postfix ++ / --
            if matches!(op, Op::Inc | Op::Dec) {
                self.next();
                let name = lhs
                    .lvalue
                    .take()
                    .ok_or_else(|| "invalid increment target".to_string())?;
                let current = get_var(&name);
                let new_val = if op == Op::Inc { current + 1 } else { current - 1 };
                set_var(&name, new_val);
                lhs.value = current; // postfix returns old value
                lhs.lvalue = None;
                continue;
            }

            let (lbp, rbp) = binding_power(op);
            if lbp < min_bp {
                break;
            }
            self.next();
            let rhs = self.parse_expr(rbp)?;

            lhs = match op {
                Op::Assign
                | Op::AddAssign
                | Op::SubAssign
                | Op::MulAssign
                | Op::DivAssign
                | Op::ModAssign => {
                    let name = lhs
                        .lvalue
                        .take()
                        .ok_or_else(|| "invalid assignment target".to_string())?;
                    let base = get_var(&name);
                    let new_val = match op {
                        Op::Assign => rhs.value,
                        Op::AddAssign => base + rhs.value,
                        Op::SubAssign => base - rhs.value,
                        Op::MulAssign => base * rhs.value,
                        Op::DivAssign => {
                            if rhs.value == 0 {
                                return Err("division by zero".to_string());
                            }
                            base / rhs.value
                        }
                        Op::ModAssign => {
                            if rhs.value == 0 {
                                return Err("division by zero".to_string());
                            }
                            base % rhs.value
                        }
                        _ => unreachable!(),
                    };
                    set_var(&name, new_val);
                    ExprValue {
                        value: new_val,
                        lvalue: None,
                    }
                }
                _ => {
                    let out = eval_binary(op, lhs.value, rhs.value)?;
                    ExprValue {
                        value: out,
                        lvalue: None,
                    }
                }
            };
        }

        Ok(lhs)
    }

    fn parse_prefix(&mut self) -> Result<ExprValue, String> {
        let token = self.next().ok_or_else(|| "unexpected end of expression".to_string())?;
        match token {
            Token::Num(n) => Ok(ExprValue {
                value: n,
                lvalue: None,
            }),
            Token::Ident(name) => Ok(ExprValue {
                value: get_var(&name),
                lvalue: Some(name),
            }),
            Token::LParen => {
                let expr = self.parse_expr(0)?;
                match self.next() {
                    Some(Token::RParen) => {}
                    _ => return Err("mismatched parentheses".to_string()),
                }
                Ok(ExprValue {
                    value: expr.value,
                    lvalue: None,
                })
            }
            Token::Op(op) if matches!(op, Op::UnaryPlus | Op::UnaryMinus | Op::Not | Op::BitNot) => {
                let rbp = unary_binding_power(op);
                let rhs = self.parse_expr(rbp)?;
                let out = match op {
                    Op::UnaryPlus => rhs.value,
                    Op::UnaryMinus => -rhs.value,
                    Op::Not => (rhs.value == 0) as i64,
                    Op::BitNot => !rhs.value,
                    _ => unreachable!(),
                };
                Ok(ExprValue {
                    value: out,
                    lvalue: None,
                })
            }
            Token::Op(op) if matches!(op, Op::Inc | Op::Dec) => {
                let name = match self.next() {
                    Some(Token::Ident(name)) => name,
                    _ => return Err("invalid increment target".to_string()),
                };
                let current = get_var(&name);
                let new_val = if op == Op::Inc { current + 1 } else { current - 1 };
                set_var(&name, new_val);
                Ok(ExprValue {
                    value: new_val,
                    lvalue: None,
                })
            }
            Token::Op(op) => Err(format!("unexpected operator '{op:?}'")),
            Token::RParen => Err("unexpected ')'".to_string()),
        }
    }
}

fn get_var(name: &str) -> i64 {
    env::var(name)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
}

fn set_var(name: &str, value: i64) {
    env::set_var(name, value.to_string());
}

fn eval_binary(op: Op, lhs: i64, rhs: i64) -> Result<i64, String> {
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
        Op::Pow => lhs.pow(rhs as u32),
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
    Ok(out)
}

fn precedence(op: Op) -> (u8, bool) {
    match op {
        Op::Pow => (8, true),
        Op::Mul | Op::Div | Op::Mod => (7, false),
        Op::Add | Op::Sub => (6, false),
        Op::Shl | Op::Shr => (5, false),
        Op::Lt | Op::Le | Op::Gt | Op::Ge => (4, false),
        Op::Eq | Op::Ne => (3, false),
        Op::BitAnd => (2, false),
        Op::BitXor => (2, false),
        Op::BitOr => (2, false),
        Op::And => (1, false),
        Op::Or => (1, false),
        Op::Assign
        | Op::AddAssign
        | Op::SubAssign
        | Op::MulAssign
        | Op::DivAssign
        | Op::ModAssign => (0, true),
        _ => (0, false),
    }
}

fn binding_power(op: Op) -> (u8, u8) {
    let (prec, right_assoc) = precedence(op);
    if right_assoc {
        (prec, prec)
    } else {
        (prec, prec + 1)
    }
}

fn unary_binding_power(op: Op) -> u8 {
    match op {
        Op::UnaryPlus | Op::UnaryMinus | Op::Not | Op::BitNot => 7,
        _ => 0,
    }
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
        assert_eq!(eval_arithmetic("2 ** 10").unwrap(), 1024);
    }

    #[test]
    fn arithmetic_comparisons_and_logic() {
        assert_eq!(eval_arithmetic("1<2").unwrap(), 1);
        assert_eq!(eval_arithmetic("1==2").unwrap(), 0);
        assert_eq!(eval_arithmetic("1&&0").unwrap(), 0);
        assert_eq!(eval_arithmetic("1||0").unwrap(), 1);
        assert_eq!(eval_arithmetic("!0").unwrap(), 1);
    }

    #[test]
    fn arithmetic_increments_and_assignments() {
        env::set_var("x", "1");
        assert_eq!(eval_arithmetic("x++").unwrap(), 1);
        assert_eq!(env::var("x").unwrap(), "2");
        assert_eq!(eval_arithmetic("++x").unwrap(), 3);
        assert_eq!(env::var("x").unwrap(), "3");
        assert_eq!(eval_arithmetic("x += 5").unwrap(), 8);
        assert_eq!(env::var("x").unwrap(), "8");
        assert_eq!(eval_arithmetic("x--").unwrap(), 8);
        assert_eq!(env::var("x").unwrap(), "7");
        assert_eq!(eval_arithmetic("--x").unwrap(), 6);
        assert_eq!(env::var("x").unwrap(), "6");
    }
}

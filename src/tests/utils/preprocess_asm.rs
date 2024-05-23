use crate::ethereum_types::U256;
use regex::Regex;

// Contains functions to preprocess asm templates and generate valid assembly code compatible with TestingTracer

/// Default config template for simple tests
const DEFAULT_CONFIG: &str = r#"
    .text
    .file	"Test_zkevm"
    .rodata.cst32
    .p2align	5
    .text
    .globl	__entry
"#;

pub fn asm_with_default_config(asm: &str) -> String {
    DEFAULT_CONFIG.to_owned() + asm
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Directive {
    Print(PrintType),
    Revert,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PrintType {
    Text,
    Register,
    Pointer,
}

pub const EXCEPTION_PREFIX: &str = "E:";
pub const PRINT_PREFIX: &str = "L:";
pub const PRINT_REG_PREFIX: &str = "R:";
pub const PRINT_PTR_PREFIX: &str = "P:";

/// Replaces special directives in asm with TestingTracer compatible "commands"
pub fn preprocess_asm(asm: &str) -> String {
    let mut result = asm.to_owned();
    for directive in [
        Directive::Print(PrintType::Text),
        Directive::Print(PrintType::Register),
        Directive::Print(PrintType::Pointer),
        Directive::Revert,
    ] {
        result = preprocess_directive(&result, directive);
    }
    result
}

fn preprocess_directive(asm: &str, directive: Directive) -> String {
    let (asm_replaced, messages) = replace_directives(asm, directive);
    add_data_section_for_directive(&asm_replaced, directive, messages)
}

/// replace all occurrences of the directive with the corresponding assembly code
fn replace_directives(asm: &str, directive: Directive) -> (String, Vec<String>) {
    let mut result = asm.to_owned();
    let mut args: Vec<String> = Vec::new();

    let (command_prefix, regex, cell_name, prefix, suffix) = match directive {
        Directive::Revert => {
            // regex: revert("<message>")
            let revert_regex = Regex::new(r#"revert\("[^"]*"\)"#).expect("Invalid regex");
            (
                EXCEPTION_PREFIX,
                revert_regex,
                "REVERT",
                r#"revert(""#,
                r#"")"#,
            )
        }
        Directive::Print(PrintType::Text) => {
            // regex: print("<message>")
            let print_regex = Regex::new(r#"print\("[^"]*"\)"#).expect("Invalid regex");
            (PRINT_PREFIX, print_regex, "PRINT", r#"print(""#, r#"")"#)
        }
        Directive::Print(PrintType::Register) => {
            // regex: print(<src>)
            let print_reg_regex = Regex::new(r#"print\([^"\))]+\)"#).expect("Invalid regex");
            (
                PRINT_REG_PREFIX,
                print_reg_regex,
                "PRINT_REG",
                r#"print("#,
                r#")"#,
            )
        }
        Directive::Print(PrintType::Pointer) => {
            // regex: printPtr(<src>)
            let print_ptr_regex = Regex::new(r#"printPtr\([^"\)]+\)"#).expect("Invalid regex");
            (
                PRINT_PTR_PREFIX,
                print_ptr_regex,
                "PRINT_PTR",
                r#"printPtr("#,
                r#")"#,
            )
        }
    };

    for (index, matched) in asm.match_indices(&regex) {
        // skip if directive commented out
        if asm[..index]
            .chars()
            .rev()
            .take_while(|&symbol| symbol != '\n')
            .any(|symbol| symbol == ';')
        {
            continue;
        }

        let arg = matched
            .trim()
            .strip_prefix(prefix)
            .expect("Invalid text in directive")
            .strip_suffix(suffix)
            .expect("Invalid text in directive");

        match directive {
            Directive::Print(PrintType::Register | PrintType::Pointer) => {
                // ignore any args
                if args.is_empty() {
                    args.push("".to_owned());
                }
            }
            _ => {
                if arg.len() > 32 - command_prefix.len() {
                    panic!("Message inside directive is too long: {}", arg);
                }
                args.push(arg.to_owned());
            }
        };

        let reference_var = format!("@{}_{}_STRING", cell_name, args.len() - 1);
        let line = format!("add {reference_var}, r0, r0");

        // additional lines
        let line = match directive {
            Directive::Revert => {
                format!("{line}\n ret.panic r0")
            }
            Directive::Print(print_type) => {
                if print_type == PrintType::Text {
                    line
                } else {
                    let opcode = match print_type {
                        PrintType::Register => "add",
                        PrintType::Pointer => "ptr.add",
                        _ => {
                            panic!("Unknown print type")
                        }
                    };
                    format!("{line}\n {opcode} {arg}, r0, r0")
                }
            }
        };
        result = result.replace(matched, &line);
    }

    (result, args)
}

/// add .rodata section with messages from directives
fn add_data_section_for_directive(asm: &str, directive: Directive, args: Vec<String>) -> String {
    let mut result = asm.to_owned();
    if args.is_empty() {
        return result;
    }

    let (command_prefix, arg_label_prefix) = match directive {
        Directive::Revert => (EXCEPTION_PREFIX, "REVERT"),
        Directive::Print(PrintType::Text) => (PRINT_PREFIX, "PRINT"),
        Directive::Print(PrintType::Register) => (PRINT_REG_PREFIX, "PRINT_REG"),
        Directive::Print(PrintType::Pointer) => (PRINT_PTR_PREFIX, "PRINT_PTR"),
    };

    let data_section: String = args
        .iter()
        .enumerate()
        .map(|(index, arg)| {
            let data_line = format!(
                "{arg_label_prefix}_{index}_STRING:\n .cell {}\n",
                U256::from(format!("{command_prefix}{arg}").as_bytes())
            );
            data_line
        })
        .chain(Some(".text\n".to_owned()))
        .fold(".rodata\n".to_owned(), |mut acc, line| {
            acc.push_str(&line);
            acc
        });

    let position = result.find("__entry:").expect("Invalid asm");
    result.insert_str(position, &data_section);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocess_asm() {
        let asm = r#"
__entry:
.main:
print("TEST")
print(r5)
revert("TEST2")"#;

        let result = preprocess_asm(&asm);

        let print_text = U256::from(format!("{}{}", PRINT_PREFIX, "TEST").as_bytes());
        let print_reg_text = U256::from(PRINT_REG_PREFIX.as_bytes());
        let revert_text = U256::from(format!("{}{}", EXCEPTION_PREFIX, "TEST2").as_bytes());

        let expected_result = format!(
            r#"
.rodata
PRINT_0_STRING:
 .cell {print_text}
.text
.rodata
PRINT_REG_0_STRING:
 .cell {print_reg_text}
.text
.rodata
REVERT_0_STRING:
 .cell {revert_text}
.text
__entry:
.main:
add @PRINT_0_STRING, r0, r0
add @PRINT_REG_0_STRING, r0, r0
 add r5, r0, r0
add @REVERT_0_STRING, r0, r0
 ret.panic r0"#
        );

        assert_eq!(result, expected_result);
    }

    #[test]
    #[should_panic(
        expected = "Message inside directive is too long: ttttttttttttttttttttttttttttttt"
    )]
    fn test_panic_too_long_print() {
        let long_message = "ttttttttttttttttttttttttttttttt";

        let asm = format! {r#"
            .text
            .globl	__entry
            __entry:
                .main:
                    print("{long_message}")
                    ret.ok r0
        "#, };

        preprocess_asm(&asm);
    }

    #[test]
    #[should_panic(expected = "Invalid asm")]
    fn test_panic_with_unexpected_entry() {
        let args = Vec::from(["Test".to_owned()]);
        let asm = r#"
            .text
            .globl	__unexpected_entry
            __unexpected_entry:
                .main:
                    ret.ok r0
        "#;
        add_data_section_for_directive(asm, Directive::Print(PrintType::Text), args);
    }
}

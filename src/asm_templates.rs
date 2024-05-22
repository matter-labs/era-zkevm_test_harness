use crate::ethereum_types::U256;
use regex::Regex;

// Contains functions to preprocess asm templates and generate valid assembly code

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
    Print,
    PrintRegister,
    PrintPointer,
    Revert,
}

pub const EXCEPTION_PREFIX: &str = "E:";
pub const PRINT_PREFIX: &str = "L:";
pub const PRINT_REG_PREFIX: &str = "R:";
pub const PRINT_PTR_PREFIX: &str = "P:";

/// Replaces special directives in asm with TestingTracer compatible "commands"
pub fn preprocess_asm(asm: &str) -> String {
    let mut result = asm.to_owned();
    for directive in [
        Directive::Print,
        Directive::Revert,
        Directive::PrintRegister,
        Directive::PrintPointer,
    ] {
        result = preprocess_directive(&result, directive.clone());
    }
    result
}

fn preprocess_directive(asm: &str, directive: Directive) -> String {
    let (asm_replaced, messages) = replace_directives(asm, directive);
    let result = add_data_section_for_directive(&asm_replaced, directive, messages);
    result
}

/// replace all occurrences of the directive with the corresponding assembly code
fn replace_directives(asm: &str, directive: Directive) -> (String, Vec<String>) {
    let mut result = asm.to_owned();
    let mut prints: Vec<String> = Vec::new();

    let (command_prefix, regex, cell_name, prefix, suffix) = match directive.clone() {
        Directive::Print => {
            // regex: print("<message>")
            let print_regex = Regex::new(r#"print\("[^"]*"\)"#).expect("Invalid regex");
            (PRINT_PREFIX, print_regex, "PRINT", r#"print(""#, r#"")"#)
        }
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
        Directive::PrintRegister => {
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
        Directive::PrintPointer => {
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

    for (_, matched) in asm.match_indices(&regex) {
        let arg = matched
            .strip_prefix(&prefix)
            .expect("Invalid text in directive")
            .strip_suffix(&suffix)
            .expect("Invalid text in directive");

        if directive == Directive::PrintRegister || directive == Directive::PrintPointer {
            // ignore any args
            if prints.is_empty() {
                prints.push("".to_owned());
            }
        } else {
            if arg.len() > 32 - command_prefix.len() {
                panic!("Message inside directive is too long: {}", arg);
            }
            prints.push(arg.to_owned());
        }

        let reference_var = format!("@{}_{}_STRING", cell_name, prints.len() - 1);
        let line = format!("add {reference_var}, r0, r0");

        // additional lines
        let line = match directive {
            Directive::Revert => {
                format!("{line}\n ret.panic r0")
            }
            Directive::Print => line,
            Directive::PrintRegister => {
                format!("{line}\n add {arg}, r0, r0")
            }
            Directive::PrintPointer => {
                format!("{line}\n ptr.add {arg}, r0, r0")
            }
        };
        result = result.replace(matched, &line);
    }

    return (result, prints);
}

/// add .rodata section with messages from directives
fn add_data_section_for_directive(asm: &str, directive: Directive, args: Vec<String>) -> String {
    let mut result = asm.to_owned();
    if args.len() == 0 {
        return result;
    }

    let (command_prefix, arg_label_prefix) = match directive {
        Directive::Print => (PRINT_PREFIX, "PRINT"),
        Directive::Revert => (EXCEPTION_PREFIX, "REVERT"),
        Directive::PrintRegister => (PRINT_REG_PREFIX, "PRINT_REG"),
        Directive::PrintPointer => (PRINT_PTR_PREFIX, "PRINT_PTR"),
    };

    let mut data_section = ".rodata\n".to_owned();
    for (index, arg) in args.iter().enumerate() {
        let mut data_line = format!("{arg_label_prefix}_{index}_STRING:\n");

        let command = format! {"{command_prefix}{arg}"};
        let value = U256::from(command.as_bytes());

        data_line = format!("{data_line} .cell {value}\n");
        data_section = data_section + &data_line;
    }
    data_section = data_section + ".text\n";

    let position = result.find("__entry:").expect("Invalid asm");
    result.insert_str(position, &data_section);

    result
}

use crate::ethereum_types::U256;
use regex::Regex;

// Default config template for simple tests
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
enum Directives {
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
    let mut result = asm.to_owned().clone();
    for directive in [
        Directives::Print,
        Directives::Revert,
        Directives::PrintRegister,
        Directives::PrintPointer,
    ]
    .iter()
    {
        result = preprocess_directive(&result, directive.clone());
    }
    result
}

fn preprocess_directive(asm: &str, directive: Directives) -> String {
    let (asm_replaced, messages) = replace_directives(asm, directive);
    let result = add_data_section_for_directive(&asm_replaced, directive, messages);
    result
}

/// replace all occurrences of the directive with the corresponding assembly code
fn replace_directives(asm: &str, directive: Directives) -> (String, Vec<String>) {
    let mut result = asm.to_owned().clone();
    let mut prints: Vec<String> = Vec::new();

    let (command_prefix, regex, cell_name, prefix, suffix) = match directive.clone() {
        Directives::Print => {
            // regex: print("<message>")
            let print_regex = Regex::new(r#"print\("[^"]*"\)"#).expect("Invalid regex");
            (PRINT_PREFIX, print_regex, "PRINT", r#"print(""#, r#"")"#)
        }
        Directives::Revert => {
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
        Directives::PrintRegister => {
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
        Directives::PrintPointer => {
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

        if directive == Directives::PrintRegister || directive == Directives::PrintPointer {
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

        let reference_var =
            "@".to_owned() + cell_name + "_" + &(prints.len() - 1).to_string() + "_STRING";
        let mut line = "add ".to_owned() + &reference_var + ", r0, r0";

        // additional lines
        match directive {
            Directives::Revert => {
                line = line + "\n" + "ret.panic r0";
            }
            Directives::PrintRegister => {
                line = line + "\n" + "add " + arg + ", r0, r0";
            }
            Directives::PrintPointer => {
                line = line + "\n" + "ptr.add " + arg + ", r0, r0";
            }
            _ => {}
        }
        result = result.replace(matched, &line);
    }

    return (result, prints);
}

/// add .rodata section with messages from directives
fn add_data_section_for_directive(
    asm: &str,
    directive: Directives,
    messages: Vec<String>,
) -> String {
    let mut result = asm.to_owned().clone();
    if messages.len() == 0 {
        return result;
    }

    let (prefix, directive_line) = match directive {
        Directives::Print => (PRINT_PREFIX, "PRINT"),
        Directives::Revert => (EXCEPTION_PREFIX, "REVERT"),
        Directives::PrintRegister => (PRINT_REG_PREFIX, "PRINT_REG"),
        Directives::PrintPointer => (PRINT_PTR_PREFIX, "PRINT_PTR"),
    };

    let mut data_section = ".rodata\n".to_owned();
    for (index, message) in messages.iter().enumerate() {
        let mut data_line = directive_line.to_owned() + "_" + &(index).to_string() + "_STRING:\n";

        let text = prefix.to_owned() + message;
        let value = U256::from(text.as_bytes());
        data_line = data_line + ".cell " + &value.to_string() + "\n";
        data_section = data_section + &data_line;
    }
    data_section = data_section + ".text\n";

    let position = result.find("__entry:").expect("Invalid asm");
    result.insert_str(position, &data_section);

    result
}

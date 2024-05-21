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
pub const PRINT_PREFIX: &str = "P:";
pub const PRINT_REG_PREFIX: &str = "R:PRINT";

pub fn preprocess_asm(asm: &str) -> String {
    let mut result = preprocess_directive(asm, Directives::Print);
    result = preprocess_directive(&result, Directives::Revert);
    result = preprocess_directive(&result, Directives::PrintRegister);
    result = preprocess_directive(&result, Directives::PrintPointer);
    result
}

fn preprocess_directive(asm: &str, directive: Directives) -> String {
    let (asm_replaced, messages) = replace_directives(asm, directive);
    let result = add_data_section_for_directive(&asm_replaced, directive, messages);
    result
}

fn replace_directives(asm: &str, directive: Directives) -> (String, Vec<String>) {
    let mut result = asm.to_owned().clone();
    let mut prints: Vec<String> = Vec::new();

    let (regex, directive_line, prefix, suffix) = match directive.clone() {
        Directives::Print => {
            let print_regex = Regex::new(r#"print\("[^"]*"\)"#).expect("Invalid regex");
            (print_regex, "PRINT", r#"print(""#, r#"")"#)
        }
        Directives::Revert => {
            let revert_regex = Regex::new(r#"revert\("[^"]*"\)"#).expect("Invalid regex");
            (revert_regex, "REVERT", r#"revert(""#, r#"")"#)
        }
        Directives::PrintRegister => {
            let print_reg_regex = Regex::new(r#"print\([^"\))]+\)"#).expect("Invalid regex");
            (print_reg_regex, "PRINT_REG", r#"print("#, r#")"#)
        }
        Directives::PrintPointer => {
            let print_ptr_regex = Regex::new(r#"printPtr\([^"\)]+\)"#).expect("Invalid regex");
            (print_ptr_regex, "PRINT_PTR", r#"printPtr("#, r#")"#)
        }
    };

    for (_, matched) in asm.match_indices(&regex) {
        let text = matched
            .strip_prefix(&prefix)
            .expect("Invalid text in directive")
            .strip_suffix(&suffix)
            .expect("Invalid text in directive");

        if directive == Directives::PrintRegister || directive == Directives::PrintPointer {
            prints.push("".to_owned());
        } else {
            if text.len() > 30 {
                panic!("Message insinde directive is too long: {}", text);
            }
            prints.push(text.to_owned());
        }

        let reference_var =
            "@".to_owned() + directive_line + "_" + &(prints.len() - 1).to_string() + "_STRING";
        let mut line = "add ".to_owned() + &reference_var + ", r0, r0";

        if directive == Directives::Revert {
            line = line + "\n" + "ret.panic r0";
        }

        if directive == Directives::PrintRegister {
            line = line + "\n" + "add " + text + ", r0, r0";
        }

        if directive == Directives::PrintPointer {
            line = line + "\n" + "ptr.add " + text + ", r0, r0";
        }

        result = result.replace(matched, &line);
    }

    return (result, prints);
}

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
        Directives::PrintPointer => (PRINT_REG_PREFIX, "PRINT_PTR"),
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

use self::run_manually::{
    run_and_try_create_witness_for_extended_state, run_and_try_create_witness_inner, Options,
};
use super::*;
use crate::tests::utils::preprocess_asm::preprocess_asm;
use std::{fs, path::Path};
use zkevm_assembly::Assembly;

/// Runs the tests based on the ASM files from a given directory.
/// The main assembly should be in `entry.asm` file, while additional
/// contracts should be in `ADDRESS.asm` files, where `ADDRESS` is the numerical
/// address at which they should be deployed.
pub fn run_asm_based_test(test_dir: &str, additional_contracts: &[i32], options: Options) {
    let data_path = Path::new(test_dir);
    let entry_asm = fs::read_to_string(data_path.join("entry.asm"))
        .expect("Should have been able to read the file");
    let entry_asm_preprocessed = preprocess_asm(&entry_asm);
    let entry_bytecode = Assembly::try_from(entry_asm_preprocessed.to_owned())
        .unwrap()
        .compile_to_bytecode()
        .unwrap();

    let contracts = additional_contracts
        .iter()
        .map(|address| {
            let file_path = data_path.join(format!("{}.asm", address));
            let asm = fs::read_to_string(file_path.clone()).expect(&format!(
                "Should have been able to read the file {:?}",
                file_path
            ));
            let asm_preprocessed = preprocess_asm(&asm);
            let bytecode = Assembly::try_from(asm_preprocessed.to_owned())
                .unwrap()
                .compile_to_bytecode()
                .expect(&format!("Failed to compile {:?}", file_path));
            (Address::from_low_u64_be(*address as u64), bytecode)
        })
        .collect();

    let mut options = options.clone();
    options.other_contracts = contracts;
    run_with_options(entry_bytecode, options);
}

#[test_log::test]
fn test_meta_opcode_asm() {
    run_asm_based_test(
        "src/tests/simple_tests/testdata/meta_opcode",
        &[],
        Default::default(),
    )
}

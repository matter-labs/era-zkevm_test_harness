#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    #[test_log::test]
    fn test_pubdata_and_storage_writes() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/storage_writes",
            &[],
            Options {
                cycles_per_vm_snapshot: Some(1),
                ..Default::default()
            },
        );
    }
}

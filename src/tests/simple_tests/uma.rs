#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    #[test_log::test]
    fn test_uma_reads_and_writes() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma",
            &[60000, 800000],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        );
    }
}

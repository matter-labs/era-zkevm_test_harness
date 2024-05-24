#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    #[test_log::test]
    fn test_uma_reads_and_writes() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/reads_and_writes",
            &[800000],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test_log::test]
    fn test_uma_static_reads() {
        let error = run_asm_based_test(
            "src/tests/simple_tests/testdata/uma/static_reads",
            &[800000],
            Options {
                cycle_limit: 100,
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
        .err()
        .expect("Expected this test to fail");
        // We try to access static data from user space - it results in
        assert!(
            error.contains("PRIVILAGED_ACCESS_NOT_FROM_KERNEL"),
            "Error was: {:?}",
            error
        );
    }
}

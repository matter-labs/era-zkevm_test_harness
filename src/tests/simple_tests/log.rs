#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    fn test_common(dir: &str) {
        run_asm_based_test(
            &format!("src/tests/simple_tests/testdata/{}", dir),
            &[800000],
            Options {
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_log_l1_message_out_of_gas() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/l1_message_out_of_gas",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    /// Tests the case where we run out of gas during the precompile execution.
    fn test_precompile_out_of_gas() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/precompile_out_of_gas",
            &[],
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_log_decommit_invalid() {
        test_common("decommit_invalid")
    }

    #[test_log::test]
    fn test_log_decommit_ok() {
        test_common("decommit_ok");
    }

    #[test_log::test]
    fn test_log_decommit_ok_with_panic() {
        test_common("decommit_ok_with_panic");
    }

    #[test_log::test]
    fn test_log_write_same_value() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/write_same_value",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    fn test_log_rollback_to_same_value_no_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/rollback_to_same_value_no_reads",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    fn test_log_rollback_to_same_value_with_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/rollback_to_same_value_with_reads",
            &[],
            Default::default(),
        )
    }
}

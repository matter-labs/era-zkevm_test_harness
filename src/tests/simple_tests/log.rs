#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    fn test_snapshot_every_cycle(dir: &str, additional_contracts: &[i32]) {
        run_asm_based_test(
            &format!("src/tests/simple_tests/testdata/log/{}", dir),
            additional_contracts,
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    /// Tests the case where we do not have enough gas to send a message to l1
    fn test_log_l1_message_out_of_gas() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/l1_message_out_of_gas",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    fn test_log_l1_message_has_zero_pubdata_cost() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/l1_message_has_zero_pubdata_cost",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    /// Tests the case where we run out of gas during the precompile execution.
    fn test_log_precompile_out_of_gas() {
        test_snapshot_every_cycle("precompile_out_of_gas", &[]);
    }

    #[test_log::test]
    fn test_log_precompile_invalid_address() {
        test_snapshot_every_cycle("precompile_invalid_address", &[65399]);
    }

    #[test_log::test]
    fn test_log_decommit_invalid() {
        test_snapshot_every_cycle("decommit_invalid", &[800000])
    }

    #[test_log::test]
    fn test_log_decommit_ok() {
        test_snapshot_every_cycle("decommit_ok", &[800000]);
    }

    #[test_log::test]
    fn test_log_decommit_ok_twice() {
        test_snapshot_every_cycle("decommit_ok_twice", &[800000]);
    }

    #[test_log::test]
    fn test_log_decommit_ok_with_panic() {
        test_snapshot_every_cycle("decommit_ok_with_panic", &[800000]);
    }

    #[test_log::test]
    fn test_log_storage_clear_slot() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_clear_slot",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    fn test_log_storage_write_rollback_no_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_write_rollback_no_reads",
            &[],
            Default::default(),
        )
    }

    #[test_log::test]
    fn test_log_storage_write_rollback_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_write_rollback_reads",
            &[],
            Default::default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    fn test_snapshot_every_cycle(dir: &str, additional_contracts: &[i32]) {
        run_asm_based_test(
            &format!("src/tests/simple_tests/testdata/{}", dir),
            additional_contracts,
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_pubdata_and_storage_writes() {
        test_snapshot_every_cycle("log/storage/storage_writes", &[]);
    }

    #[test_log::test]
    fn test_storage_reads() {
        test_snapshot_every_cycle("log/storage/storage_reads", &[]);
    }

    #[test_log::test]
    fn test_storage_write_after_panic() {
        test_snapshot_every_cycle("log/storage/storage_write_after_panic", &[]);
    }

    #[test_log::test]
    fn test_storage_pubdata_refunds() {
        test_snapshot_every_cycle("log/storage/storage_pubdata_refunds", &[]);
    }
}

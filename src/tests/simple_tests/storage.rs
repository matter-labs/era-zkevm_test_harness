#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::{asm_tests::run_asm_based_test, Options};

    #[test_log::test]
    fn test_pubdata_and_storage_writes() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_writes",
            &[],
            Options {
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        );
    }

    #[test_log::test]
    fn test_storage_reads() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_reads",
            &[],
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_storage_write_after_panic() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_write_after_panic",
            &[],
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }

    #[test_log::test]
    fn test_storage_pubdata_refunds() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log/storage/storage_pubdata_refunds",
            &[],
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        );
    }
}

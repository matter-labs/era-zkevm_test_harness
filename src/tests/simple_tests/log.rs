use super::*;

#[test_log::test]
fn test_out_of_ergs_l1_message() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        event r1, r10
        to_l1 r1, r10
        context.set_ergs_per_pubdata r10
        near_call r1, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        to_l1 r0, r1
        ret.ok r0
    handler:
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[cfg(test)]
mod tests {
    use crate::tests::simple_tests::asm_tests::run_asm_based_test;
    use crate::tests::simple_tests::run_manually::Options;

    #[test_log::test]
    /// Tests the case where we run out of gas during the precompile execution.
    fn test_precompile_out_of_gas() {
        run_asm_based_test(
            "src/tests/simple_tests/testdata/log_precompile",
            &[],
            Options {
                // Do only 1 cycle per VM snapshot to really test all the boundary conditions.
                cycles_per_vm_snapshot: 1,
                ..Default::default()
            },
        )
    }
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
    fn test_decommit_invalid() {
        test_common("decommit_invalid")
    }

    #[test_log::test]
    fn test_decommit_ok() {
        test_common("decommit_ok");
        test_common("decommit_ok_with_panic");
    }
}

#[test_log::test]
fn test_write_same_value() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r0, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        sstore r1, r0
        ret.ok r0
    handler:
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_rollback_to_same_value_no_reads() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r0, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        ret.panic r0
    handler:
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

#[test_log::test]
fn test_rollback_to_same_value_with_reads() {
    let asm = r#"
        .text
        .file	"Test_26"
        .rodata.cst32
        .p2align	5
        .text
        .globl	__entry
    __entry:
    .main:
        near_call r1, @inner, @handler
        context.ergs_left r15
        ret.ok r0
    inner:
        add 10000, r0, r1
        add 1000, r0, r10
        sstore r1, r10
        ret.panic r0
    handler:
    add 10000, r0, r1
        sload r1, r2
        ret.ok r0
    "#;

    run_and_try_create_witness_inner(asm, 50);
}

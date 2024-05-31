use super::*;
use crate::tests::simple_tests::asm_tests::{run_asm_based_test, run_asm_based_test_template};
use crate::tests::utils::preprocess_asm::TemplateDictionary;

#[test_log::test]
fn test_memory_growth_heap_write_kernel() {
    test_memory_growth_heap_write(65534);
}

#[test_log::test]
fn test_memory_growth_heap_write_not_kernel() {
    test_memory_growth_heap_write(800000);
}

fn test_memory_growth_heap_write(heaps_growth_test_address: i32) {
    let additional_contracts =
        Vec::<(String, i32)>::from([("heaps_grows_test".to_owned(), heaps_growth_test_address)]);

    let mut dictionary = TemplateDictionary::new();
    dictionary.insert(
        "heaps_grows_test_contract_address",
        heaps_growth_test_address.to_string(),
    );

    run_asm_based_test_template(
        "src/tests/simple_tests/testdata/memory_growth/heap_write",
        &additional_contracts,
        Options {
            cycle_limit: 100,
            ..Default::default()
        },
        Some(&dictionary),
    )
}

#[test_log::test]
fn test_memory_growth_ret_kernel() {
    test_memory_growth_ret(65534, 65533);
}

#[test_log::test]
fn test_memory_growth_ret_not_kernel() {
    test_memory_growth_ret(800000, 800001);
}

fn test_memory_growth_ret(heap_test_address: i32, aux_heap_test_address: i32) {
    let additional_contracts = Vec::<(String, i32)>::from([
        ("heap_test".to_owned(), heap_test_address),
        ("aux_heap_test".to_owned(), aux_heap_test_address),
    ]);

    let mut dictionary = TemplateDictionary::new();

    dictionary.insert("heap_test_contract_address", heap_test_address.to_string());
    dictionary.insert(
        "aux_heap_test_contract_address",
        aux_heap_test_address.to_string(),
    );

    run_asm_based_test_template(
        "src/tests/simple_tests/testdata/memory_growth/ret",
        &additional_contracts,
        Options {
            cycle_limit: 100,
            ..Default::default()
        },
        Some(&dictionary),
    )
}

#[test_log::test]
fn test_memory_growth_far_call_kernel() {
    test_memory_growth_far_call(65534);
}

#[test_log::test]
fn test_memory_growth_far_call_not_kernel() {
    test_memory_growth_far_call(800000);
}

fn test_memory_growth_far_call(far_call_test_address: i32) {
    let dummy_address = 900000;
    let additional_contracts = Vec::<(String, i32)>::from([
        ("far_call_test".to_owned(), far_call_test_address),
        ("dummy".to_owned(), dummy_address),
    ]);

    let mut dictionary = TemplateDictionary::new();
    dictionary.insert("far_call_test_address", far_call_test_address.to_string());
    dictionary.insert("dummy_address", dummy_address.to_string());

    run_asm_based_test_template(
        "src/tests/simple_tests/testdata/memory_growth/far_call",
        &additional_contracts,
        Options {
            cycle_limit: 100,
            ..Default::default()
        },
        Some(&dictionary),
    )
}

#[test_log::test]
fn test_memory_growth_ret_out_of_ergs_kernel() {
    test_memory_growth_ret_out_of_ergs(65534, 65533);
}

#[test_log::test]
fn test_memory_growth_ret_out_of_ergs_not_kernel() {
    test_memory_growth_ret_out_of_ergs(800000, 800001);
}

fn test_memory_growth_ret_out_of_ergs(heap_test_address: i32, aux_heap_test_address: i32) {
    let additional_contracts = Vec::<(String, i32)>::from([
        ("heap_test".to_owned(), heap_test_address),
        ("aux_heap_test".to_owned(), aux_heap_test_address),
    ]);

    let mut dictionary = TemplateDictionary::new();

    dictionary.insert("heap_test_contract_address", heap_test_address.to_string());
    dictionary.insert(
        "aux_heap_test_contract_address",
        aux_heap_test_address.to_string(),
    );

    run_asm_based_test_template(
        "src/tests/simple_tests/testdata/memory_growth/ret_out_of_ergs",
        &additional_contracts,
        Options {
            cycle_limit: 100,
            ..Default::default()
        },
        Some(&dictionary),
    )
}

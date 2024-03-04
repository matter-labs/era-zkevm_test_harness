use std::alloc::Global;
use std::panic;

use crate::boojum::cs::CSGeometry;
use crate::boojum::field::goldilocks::GoldilocksField;

use crate::boojum::cs::traits::circuit::CircuitBuilder;
use circuit_definitions::aux_definitions::witness_oracle::VmWitnessOracle;
use circuit_definitions::circuit_definitions::base_layer::*;
use circuit_definitions::circuit_definitions::ZkSyncUniformSynthesisFunction;
use circuit_definitions::ZkSyncDefaultRoundFunction;

pub(crate) fn compute_size_inner<
    SF: ZkSyncUniformSynthesisFunction<GoldilocksField, RoundFunction = ZkSyncDefaultRoundFunction>,
    F: Fn(usize) -> SF::Config,
>(
    geometry: CSGeometry,
    max_trace_len_log_2: usize,
    start_hint: Option<usize>,
    config_fn: F,
) -> usize
where
    SF: Send + 'static,
    SF::Config: Send + 'static,
{
    println!(
        "Will try to estimate capacity for {}",
        std::any::type_name::<SF>()
    );
    let start_size = start_hint.unwrap_or(1024);

    // kind-of binary search

    let mut size: usize = 1;
    let mut next_size = start_size;

    loop {
        // we just try to make one
        println!(
            "Trying size {} for circuit {}",
            next_size,
            std::any::type_name::<SF>()
        );

        if size == next_size {
            break;
        }

        let config = (config_fn)(next_size);

        let join_result = std::thread::spawn(move || {
            use crate::boojum::config::SetupCSConfig;
            use crate::boojum::cs::cs_builder::new_builder;
            use crate::boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;

            type P = GoldilocksField;

            let builder_impl =
                CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
                    geometry,
                    1 << max_trace_len_log_2,
                );
            let builder = new_builder::<_, GoldilocksField>(builder_impl);

            let witness = SF::Witness::default();
            let round_function = ZkSyncDefaultRoundFunction::default();
            let config = config;

            let builder = SF::configure_builder(builder);
            let mut cs = builder.build(1); // Resolver is inactive in this mode
            SF::add_tables(&mut cs);
            let _ = SF::synthesize_into_cs_inner(&mut cs, witness, &round_function, config);
            let (max_trace_len, _) = cs.pad_and_shrink();
            let cs = cs.into_assembly::<Global>();

            cs.print_gate_stats();

            max_trace_len
        })
        .join();

        match join_result {
            Ok(max_trace_len) => {
                println!("Size {} requires {} rows", next_size, max_trace_len);
                if max_trace_len <= (1 << (max_trace_len_log_2 - 1)) {
                    size = next_size;
                    next_size *= 2;
                } else {
                    if (next_size - size) < 1 {
                        break;
                    }

                    if size + 1 == next_size {
                        // small step
                        size = next_size;
                        next_size += 1;
                        continue;
                    }

                    if ((next_size - size) as f64) / (size as f64) < 0.03 {
                        size = next_size;
                        break;
                    }

                    let mut next_size_binsearch = (next_size - size) / 2 + next_size;
                    if next_size_binsearch == next_size {
                        next_size_binsearch += 1;
                    }
                    size = next_size;
                    next_size = next_size_binsearch;
                }
            }
            Err(_e) => {
                if next_size == start_size {
                    panic!("Initial search point is too large");
                }
                if next_size == size + 1 {
                    break;
                }
                // println!("Error in synthesis occured");
                let next_size_binsearch = (next_size - size) / 2 + size;
                if next_size_binsearch == size {
                    break;
                }
                next_size = next_size_binsearch;
            }
        }
    }

    println!(
        "{} has capacity of {} cycles",
        std::any::type_name::<SF>(),
        size
    );

    size
}

pub fn main_vm_capacity() -> usize {
    type SF = VmMainInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(5500), |x: usize| x)
}

pub fn code_decommittments_sorter_capacity() -> usize {
    type SF = CodeDecommittmentsSorterSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(40000), |x: usize| x)
}

pub fn code_decommitter_capacity() -> usize {
    type SF = CodeDecommitterInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(2048), |x: usize| x)
}

pub fn log_demuxer_capacity() -> usize {
    type SF = LogDemuxInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(20000), |x: usize| x)
}

pub fn keccak256_rf_capacity() -> usize {
    type SF = Keccak256RoundFunctionInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(100), |x: usize| x)
}

pub fn sha256_rf_capacity() -> usize {
    type SF = Sha256RoundFunctionInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(2048), |x: usize| x)
}

pub fn ecrecover_capacity() -> usize {
    type SF = ECRecoverFunctionInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(2), |x: usize| x)
}

pub fn ram_permutation_capacity() -> usize {
    type SF = RAMPermutationInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(70000), |x: usize| x)
}

pub fn event_sorter_capacity() -> usize {
    type SF = EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(20000), |x: usize| x)
}

pub fn storage_sorter_capacity() -> usize {
    type SF = StorageSortAndDedupInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(22000), |x: usize| x)
}

pub fn storage_application_capacity() -> usize {
    type SF = StorageApplicationInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(32), |x: usize| x)
}

pub fn l1_messages_hasher_capacity() -> usize {
    type SF = LinearHasherInstanceSynthesisFunction;

    compute_size_inner::<SF, _>(SF::geometry(), 20, Some(512), |x: usize| x)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_size_estimation() {
        println!("Size of main_vm_capacity: {}", main_vm_capacity());
        println!(
            "Size of code_decommittments_sorter_capacity: {}",
            code_decommittments_sorter_capacity()
        );
        println!(
            "Size of code_decommitter_capacity: {}",
            code_decommitter_capacity()
        );
        println!("Size of log_demuxer_capacity: {}", log_demuxer_capacity());
        println!("Size of keccak256_rf_capacity: {}", keccak256_rf_capacity());
        println!("Size of sha256_rf_capacity: {}", sha256_rf_capacity());
        println!("Size of ecrecover_capacity: {}", ecrecover_capacity());
        println!(
            "Size of ram_permutation_capacity: {}",
            ram_permutation_capacity()
        );
        println!("Size of event_sorter_capacity: {}", event_sorter_capacity());
        println!(
            "Size of storage_sorter_capacity: {}",
            storage_sorter_capacity()
        );
        println!(
            "Size of storage_application_capacity: {}",
            storage_application_capacity()
        );
        println!(
            "Size of l1_messages_hasher_capacity: {}",
            l1_messages_hasher_capacity()
        );
    }
}

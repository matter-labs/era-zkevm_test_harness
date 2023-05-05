use std::panic;

use boojum::cs::CSGeometry;
use boojum::field::goldilocks::GoldilocksField;

use crate::ZkSyncDefaultRoundFunction;
use crate::abstract_zksync_circuit::{ZkSyncUniformCircuitCircuitInstance, ZkSyncUniformSynthesisFunction};
use crate::abstract_zksync_circuit::concrete_circuits::*;
use crate::witness::oracle::VmWitnessOracle;

pub(crate) fn compute_size_inner<
    SF: ZkSyncUniformSynthesisFunction<GoldilocksField, RoundFunction = ZkSyncDefaultRoundFunction>,
    F: Fn(usize) -> SF::Config
>(
    geometry: CSGeometry,
    max_trace_len_log_2: usize,
    max_variables_hint_log_2: Option<usize>,
    start_hint: Option<usize>,
    config_fn: F,
    optional_circuit_limit_generation_mode_fn: Option<fn(usize) -> usize>,
) -> usize 
    where SF: Send + 'static,
        SF::Config: Send + 'static,
{
    let max_variables_hint_log_2 = max_variables_hint_log_2.unwrap_or(30);
    let start_size = start_hint.unwrap_or(1024);

    // kind-of binary search

    let mut size: usize = 1;
    let mut next_size = start_size;

    loop {
        // we just try to make one
        println!("Trying for size {}", next_size);

        let config = (config_fn)(next_size);

        let join_result = std::thread::spawn(move || {
            use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
            use boojum::config::SetupCSConfig;
            use boojum::cs::cs_builder::new_cs_builder;
        
            type P = GoldilocksField;
        
            let builder_impl = CsReferenceImplementationBuilder::<GoldilocksField, P, SetupCSConfig>::new(
                geometry, 
                1 << max_variables_hint_log_2, 
                1 << max_trace_len_log_2,
            );
            let builder = new_cs_builder::<_, GoldilocksField>(builder_impl);
    
            let witness = SF::Witness::default();
            let round_function = ZkSyncDefaultRoundFunction::default();
            let config = config;

            let builder = SF::configure_builder(builder);
            let mut cs = builder.build(());
            SF::add_tables(&mut cs);
            let _ = SF::synthesize_into_cs_inner(&mut cs, witness, &round_function, config);

            cs.print_gate_stats();

            let (max_trace_len, _) = cs.pad_and_shrink();

            max_trace_len
        
        }).join();

        match join_result {
            Ok(max_trace_len) => {
                println!("Size {} requires {} rows", next_size, max_trace_len);
                if max_trace_len <= (1 << (max_trace_len_log_2-1)) {
                    size = next_size;
                    next_size *= 2;
                } else {
                    if (next_size - size) < 1 {
                        break;
                    }

                    if size + 1 == next_size {
                        continue;
                    }

                    if ((next_size - size) as f64) / (size as f64) < 0.03 {
                        size = next_size;
                        break
                    }
                    let mut next_size_binsearch = (next_size - size) / 2 + next_size;
                    if next_size_binsearch == next_size {
                        next_size_binsearch += 1;
                    }
                    size = next_size;
                    next_size = next_size_binsearch;
                }
            },
            Err(_e) => {
                if next_size == start_size {
                    panic!("Initial search point is too large");
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

    size
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_vm_size_estimation() {
        type SF = VmMainInstanceSynthesisFunction<GoldilocksField, VmWitnessOracle<GoldilocksField>, ZkSyncDefaultRoundFunction>;

        let size = compute_size_inner::<
            SF,
            _,
        > (
            SF::geometry(),
            20,
            Some(28),
            Some(2048),
            |x: usize| {
                x
            },
            None,
        );

        println!("Size for VM = {}", size)
    }

}

// pub fn get_circuit_capacity(circuit_type: u8) -> usize {
//     match circuit_type {
//         3 => compute_inner::<VmMainInstanceSynthesisFunction<_, VmWitnessOracle<_>>, _>(
//             |x: usize| {
//                 x
//             }, None,
//         ),
//         4 => compute_inner::<CodeDecommittmentsSorterSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         5 => compute_inner::<CodeDecommitterInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         6 => compute_inner::<LogDemuxInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         7 => compute_inner::<Keccak256RoundFunctionInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         8 => compute_inner::<Sha256RoundFunctionInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         9 => compute_inner::<ECRecoverFunctionInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         10 => compute_inner::<RAMPermutationInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         11 => compute_inner::<StorageSortAndDedupInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         12 => compute_inner::<StorageApplicationInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 (x, USE_BLAKE2S_EXTRA_TABLES)
//             },
//             None,
//         ),
//         13 => compute_inner::<StorageInitialWritesRehasherInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         14 => compute_inner::<StorageRepeatedWritesRehasherInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         15 | 16 => compute_inner::<EventsAndL1MessagesSortAndDedupInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 x
//             },
//             None,
//         ),
//         // L1MessagesRehasherInstanceSynthesisFunction
//         17 | 18 => compute_inner::<MessagesMerklizerInstanceSynthesisFunction, _>(
//             |x: usize| {
//                 (x, L1_MESSAGES_MERKLIZER_OUTPUT_LINEAR_HASH)
//             },
//             // Round down cycles to power of 2 as L1 message merklizer circuit expects it to be power of 2
//             // https://github.com/matter-labs/sync_vm/blob/b538a6105bbc0586ad437484f7f76b2c3e329c46/src/glue/merkleize_l1_messages/merkleize.rs#L298-L301
//             Some(|cycles: usize| { 2usize.pow((cycles as f64).log2().floor() as u32) }),
//         ),
//         _ => panic!("Unknown circuit type for which the limit can be computed {}", circuit_type)
//     }
// }

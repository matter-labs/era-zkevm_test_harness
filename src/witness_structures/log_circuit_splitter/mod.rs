pub mod simulator {
    use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
    use sync_vm::franklin_crypto::bellman::ScalarEngine;
    use crate::encodings::OutOfCircuitFixedLengthEncodable;
    use crate::witness::full_block_artifact::FullBlockArtifacts;
    use crate::bellman::SynthesisError;
    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    use sync_vm::vm::vm_cycle::add_all_tables;
    use sync_vm::glue::demux_log_queue::demultiplex_storage_logs_enty_point;
    use sync_vm::scheduler::storage_log_demux::LogDemultiplexorStructuredInputWitness;
    use sync_vm::scheduler::DemultiplexorStructuredLogicalOutput;
    use sync_vm::traits::CSWitnessable;
    use crate::ff::Field;
    use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;
    use sync_vm::scheduler::data_access_functions::StorageLogRecord;
    use crate::franklin_crypto::plonk::circuit::allocated_num::Num;
    type E = sync_vm::testing::Bn256;

    pub fn create_demux_witness_and_fill_next_stage<
        R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>
    >(
        artifacts: &mut FullBlockArtifacts<E>,
        round_function: &R,
        num_rounds_per_circuit: usize,
    ) -> Result<(), SynthesisError> {
        assert!(artifacts.is_processed);
        // we will use the circuit to simulate everything

        let (mut cs, _, _) = create_test_artifacts_with_optimized_gate();
        add_all_tables(&mut cs)?;

        // put initial witness
        let input_witness = LogDemultiplexorStructuredInputWitness::<E> {
            input_queue_length: artifacts.original_log_queue.len() as u32,
            input_queue_tail: artifacts.original_log_queue_states.last().map(|el| el.1.tail).unwrap_or(<E as ScalarEngine>::Fr::zero()),
            output_data: DemultiplexorStructuredLogicalOutput::placeholder_witness(), // we do not care

            _marker: std::marker::PhantomData
        };

        use crate::encodings::log_query::log_query_into_storage_record_witness;

        let mut wit = vec![];
        for ((_c0, query), (_c1, info)) in artifacts.original_log_queue.iter().zip(artifacts.original_log_queue_states.iter()) {
            assert_eq!(_c0, _c1);

            let witness_element = log_query_into_storage_record_witness(query);
            let previous_tail = info.previous_tail;
            let encoding: [<E as ScalarEngine>::Fr; 5] = OutOfCircuitFixedLengthEncodable::<E, 5>::encoding_witness(query);

            wit.push((encoding, witness_element, previous_tail));
        }

        let queue_elements_witness: FixedWidthEncodingGenericQueueWitness<E, StorageLogRecord<E>, {sync_vm::scheduler::queues::storage_log::STORAGE_LOG_RECORD_ENCODING_LEN}> = FixedWidthEncodingGenericQueueWitness{
            wit,
        };

        let report = std::sync::Arc::new(std::sync::Mutex::new(None)); 

        let c = std::sync::Arc::clone(&report);
        let reporting_function = move |el| {
            let mut guard = c.lock().unwrap();
            *guard = Some(el);
        };

        demultiplex_storage_logs_enty_point(
            &mut cs,
            Some(input_witness),
            Some(queue_elements_witness),
            round_function,
            num_rounds_per_circuit,
            Some(Box::new(reporting_function)),
        )?;

        let result = (*(report.lock().unwrap())).take();
        let result = result.unwrap();

        Ok(())
    }
}

use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::precompiles::keccak256::KECCAK256_PRECOMPILE_ADDRESS;
use crate::encodings::log_query::LogQueueSimulator;
use crate::ff::Field;
use crate::pairing::Engine;
use crate::witness::full_block_artifact::FullBlockArtifacts;
use derivative::Derivative;
use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;
use sync_vm::scheduler::storage_log_demux::{LogDemultiplexorStructuredInputWitness, DemultiplexorStructuredLogicalOutput};
use sync_vm::scheduler::data_access_functions::StorageLogRecord;

/// We should keep the full original queue data, and quickly compute demuxed circuits information 
/// for other circuit types
#[derive(Derivative)]
#[derivative(Clone, Debug)]
pub struct DemuxCircuitWitness<E: Engine> {
    // For now it's a mix, just everything necessary
    pub circuit_input: LogDemultiplexorStructuredInputWitness<E>,
    pub circuit_witness: FixedWidthEncodingGenericQueueWitness<E, StorageLogRecord<E>, {sync_vm::scheduler::queues::storage_log::STORAGE_LOG_RECORD_ENCODING_LEN}>,
}

pub fn demux_storage_logs<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(
    artifacts: &mut FullBlockArtifacts<E>,
    round_function: &R,
    num_rounds_per_circuit: usize,
) -> DemuxCircuitWitness<E> {
    assert!(artifacts.is_processed);

    assert!(artifacts.original_log_queue.len() <= num_rounds_per_circuit);

    // logically we should just filter everything
    use sync_vm::traits::CSWitnessable;

    // put initial witness
    let mut input_witness = LogDemultiplexorStructuredInputWitness::<E> {
        input_queue_length: artifacts.original_log_queue.len() as u32,
        input_queue_tail: artifacts.original_log_queue_states.last().map(|el| el.1.tail).unwrap_or(E::Fr::zero()),
        output_data: DemultiplexorStructuredLogicalOutput::placeholder_witness(), // we do not care yet

        _marker: std::marker::PhantomData
    };

    use crate::encodings::log_query::log_query_into_storage_record_witness;

    use crate::encodings::OutOfCircuitFixedLengthEncodable;

    let total_it = artifacts.original_log_queue.iter().zip(artifacts.original_log_queue_states.iter())
    .map(|((c0, q), (c1, info))| {
        assert_eq!(c0, c1);

        (q, info)
    });

    let mut wit = vec![];
    for (query,info) in total_it.clone() {

        let witness_element = log_query_into_storage_record_witness(query);
        let previous_tail = info.previous_tail;
        let encoding: [E::Fr; 5] = OutOfCircuitFixedLengthEncodable::<E, 5>::encoding_witness(query);

        wit.push((encoding, witness_element, previous_tail));
    }

    let queue_elements_witness: FixedWidthEncodingGenericQueueWitness<E, StorageLogRecord<E>, {sync_vm::scheduler::queues::storage_log::STORAGE_LOG_RECORD_ENCODING_LEN}> = FixedWidthEncodingGenericQueueWitness{
        wit,
    };

    use zk_evm::aux_structures::*;

    let mut rollup_storage_queue_simulator = LogQueueSimulator::<E>::empty();
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == STORAGE_AUX_BYTE && q.shard_id == 0);
    
    for (q, _) in filtered_it {
        let (_, info) = rollup_storage_queue_simulator.push_and_output_intermediate_data(*q, round_function);
        artifacts.demuxed_rollup_storage_queries.push(*q);
        artifacts.demuxed_rollup_storage_queue_states.push(info);
    }

    // no porter queries
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == STORAGE_AUX_BYTE && q.shard_id != 0);
    assert!(filtered_it.collect::<Vec<_>>().len() == 0);
    
    // events
    let mut events_queue_simulator = LogQueueSimulator::<E>::empty();
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == EVENT_AUX_BYTE);
    
    for (q, _) in filtered_it {
        let (_, info) = events_queue_simulator.push_and_output_intermediate_data(*q, round_function);
        artifacts.demuxed_event_queries.push(*q);
        artifacts.demuxed_event_queue_states.push(info);
    }

    // l1 messages
    let mut l1_messages_queue_simulator = LogQueueSimulator::<E>::empty();
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == L1_MESSAGE_AUX_BYTE);
    
    for (q, _) in filtered_it {
        let (_, info) = l1_messages_queue_simulator.push_and_output_intermediate_data(*q, round_function);
        artifacts.demuxed_to_l1_queries.push(*q);
        artifacts.demuxed_to_l1_queue_states.push(info);
    }

    use zk_evm::precompiles::*;

    // keccak
    let mut keccak_queue_simulator = LogQueueSimulator::<E>::empty();
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == PRECOMPILE_AUX_BYTE && q.address == *KECCAK256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS);
    
    for (q, _) in filtered_it {
        let (_, info) = keccak_queue_simulator.push_and_output_intermediate_data(*q, round_function);
        artifacts.demuxed_keccak_precompile_queries.push(*q);
        artifacts.demuxed_keccak_precompile_queue_states.push(info);
    }

    // sha256
    let mut sha256_queue_simulator = LogQueueSimulator::<E>::empty();
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == PRECOMPILE_AUX_BYTE && q.address == *SHA256_ROUND_FUNCTION_PRECOMPILE_FORMAL_ADDRESS);
    
    for (q, _) in filtered_it {
        let (_, info) = sha256_queue_simulator.push_and_output_intermediate_data(*q, round_function);
        artifacts.demuxed_sha256_precompile_queries.push(*q);
        artifacts.demuxed_sha256_precompile_queue_states.push(info);
    }

    // ecrecover
    let mut ecdsa_queue_simulator = LogQueueSimulator::<E>::empty();
    let filtered_it = total_it.clone().filter(|(q, _info)| q.aux_byte == PRECOMPILE_AUX_BYTE && q.address == *ECRECOVER_INNER_FUNCTION_PRECOMPILE_FORMAL_ADDRESS);
    
    for (q, _) in filtered_it {
        let (_, info) = ecdsa_queue_simulator.push_and_output_intermediate_data(*q, round_function);
        artifacts.demuxed_ecrecover_queries.push(*q);
        artifacts.demuxed_ecrecover_queue_states.push(info);
    }

    // finish with logical output data
    use sync_vm::scheduler::DemultiplexorStructuredLogicalOutputWitness;

    input_witness.output_data = DemultiplexorStructuredLogicalOutputWitness::<E> {
        rollup_storage_queue_tail: rollup_storage_queue_simulator.tail,
        rollup_storage_queue_num_items: rollup_storage_queue_simulator.num_items,
        porter_storage_queue_tail: E::Fr::zero(),
        porter_storage_queue_num_items: 0,
        events_queue_tail: events_queue_simulator.tail,
        events_queue_num_items: events_queue_simulator.num_items,
        l1_messages_queue_tail: l1_messages_queue_simulator.tail,
        l1_messages_queue_num_items: l1_messages_queue_simulator.num_items,
        keccak_calls_queue_tail: keccak_queue_simulator.tail,
        keccak_calls_queue_num_items: keccak_queue_simulator.num_items,
        sha256_calls_queue_tail: sha256_queue_simulator.tail,
        sha256_calls_queue_num_items: sha256_queue_simulator.num_items,
        ecdsa_calls_queue_tail: ecdsa_queue_simulator.tail,
        ecdsa_calls_queue_num_items: ecdsa_queue_simulator.num_items,
        _marker: std::marker::PhantomData
    };

    let circuit_witness = DemuxCircuitWitness {
        circuit_input: input_witness,
        circuit_witness: queue_elements_witness,
    };


   circuit_witness
}
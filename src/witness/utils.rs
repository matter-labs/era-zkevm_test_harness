use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::glue::optimizable_queue::commit_variable_length_encodable_item;
use sync_vm::scheduler::queues::StorageLogQueue;
use sync_vm::vm::ports::ArithmeticFlagsPortWitness;
use sync_vm::vm::vm_state::GlobalContext;
use sync_vm::vm::vm_state::VmGlobalStateWitness;
use sync_vm::vm::vm_state::VmLocalState;
use zk_evm::aux_structures::LogQuery;

use crate::encodings::log_query::LogQueueState;

use crate::bellman::Engine;
use crate::encodings::log_query::LogQueueSimulator;

pub fn log_queries_into_states<
    E: Engine,
    R: CircuitArithmeticRoundFunction<E, 2, 3>
>(queries: impl Iterator<Item = LogQuery>, round_function: &R) -> Vec<LogQueueState<E>> {
    let mut result = vec![];
    let mut simulator = LogQueueSimulator::<E>::empty();
    for q in queries {
        let (_, intermediate_info) = simulator.push_and_output_intermediate_data(q, round_function);
        result.push(intermediate_info);
    }

    result
}

use crate::ff::ScalarEngine;
use crate::bellman::bn256::Bn256;
use sync_vm::glue::traits::CSAllocatable;
use sync_vm::glue::traits::CircuitVariableLengthEncodableExt;
use sync_vm::inputs::ClosedFormInputWitness;
use sync_vm::traits::CSWitnessable;
use sync_vm::inputs::ClosedFormInputCompactFormWitness;

pub fn simulate_public_input_value_from_witness<
    T: std::fmt::Debug + CSAllocatable<Bn256> + CircuitVariableLengthEncodableExt<Bn256>, 
    IN: std::fmt::Debug + CSAllocatable<Bn256> + CircuitVariableLengthEncodableExt<Bn256>,
    OUT: std::fmt::Debug + CSAllocatable<Bn256> + CircuitVariableLengthEncodableExt<Bn256>
>(
    input_witness: ClosedFormInputWitness<Bn256, T, IN, OUT>, 
) -> (<Bn256 as ScalarEngine>::Fr, ClosedFormInputCompactFormWitness<Bn256>)
    where <T as CSWitnessable<Bn256>>::Witness: serde::Serialize + serde::de::DeserializeOwned,
        <IN as CSWitnessable<Bn256>>::Witness: serde::Serialize + serde::de::DeserializeOwned,
        <OUT as CSWitnessable<Bn256>>::Witness: serde::Serialize + serde::de::DeserializeOwned
{
    use sync_vm::testing::create_test_artifacts_with_optimized_gate;
    use sync_vm::inputs::ClosedFormInput;
    use crate::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;

    // allocate in full
    let (mut cs, round_function, _) = create_test_artifacts_with_optimized_gate();
    use sync_vm::vm::VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
    use sync_vm::vm::tables::BitwiseLogicTable;
    use crate::bellman::plonk::better_better_cs::cs::LookupTableApplication;
    use crate::bellman::plonk::better_better_cs::data_structures::PolyIdentifier;

    let columns3 = vec![
        PolyIdentifier::VariablesPolynomial(0), 
        PolyIdentifier::VariablesPolynomial(1), 
        PolyIdentifier::VariablesPolynomial(2)
    ];

    use crate::bellman::plonk::better_better_cs::cs::ConstraintSystem;
    
    if cs.get_table(VM_BITWISE_LOGICAL_OPS_TABLE_NAME).is_err() {
        let name = VM_BITWISE_LOGICAL_OPS_TABLE_NAME;
        let bitwise_logic_table = LookupTableApplication::new(
            name, BitwiseLogicTable::new(&name, 8), columns3.clone(), None, true
        );
        cs.add_table(bitwise_logic_table).unwrap();
    };
    inscribe_default_range_table_for_bit_width_over_first_three_columns(&mut cs, 16).unwrap();

    let full_input = ClosedFormInput::alloc_from_witness(&mut cs, Some(input_witness)).unwrap();
    // compute the compact form
    use sync_vm::inputs::ClosedFormInputCompactForm;
    let compact_form = ClosedFormInputCompactForm::from_full_form(&mut cs, &full_input, &round_function).unwrap();
    // compute the encoding and committment of compact form
    let compact_form_witness = compact_form.create_witness().unwrap();
    // dbg!(&compact_form_witness);

    use sync_vm::glue::optimizable_queue::commit_encodable_item;
    let public_input = commit_encodable_item(&mut cs, &compact_form, &round_function).unwrap();

    (public_input.get_value().unwrap(), compact_form_witness)
}

use crate::witness::oracle::VmInstanceWitness;
use sync_vm::vm::vm_cycle::witness_oracle::WitnessOracle;
use sync_vm::vm::vm_cycle::input::VmCircuitWitness;

use crate::witness::oracle::VmInCircuitAuxilaryParameters;

pub fn vm_instance_witness_to_vm_formal_state<E: Engine>(
    vm_state: &zk_evm::vm_state::VmLocalState,
    aux_params: &VmInCircuitAuxilaryParameters<E>,
) -> VmGlobalStateWitness<E, 3> {
    use sync_vm::vm::vm_state::VmGlobalState;

    let mut hidden_fsm = VmGlobalState::<E, 3>::placeholder_witness();
    // depth and state encoding
    hidden_fsm.callstack.stack_sponge_state = aux_params.callstack_state.0;
    hidden_fsm.callstack.context_stack_depth = vm_state.callstack.depth() as u16;

    // non-saved part
    hidden_fsm.callstack.current_context.log_queue_forward_part_length = aux_params.storage_log_queue_state.num_items;
    hidden_fsm.callstack.current_context.log_queue_forward_tail = aux_params.storage_log_queue_state.tail_state;
    hidden_fsm.callstack.current_context.returndata_page = vm_state.callstack.returndata_page.0;
    // saved part

    let mut ctx = &mut hidden_fsm.callstack.current_context;
    let out_of_circuit_context = &vm_state.callstack.current;

    // memory pages
    ctx.saved_context.common_part.base_page = out_of_circuit_context.base_memory_page.0;
    ctx.saved_context.common_part.calldata_page = out_of_circuit_context.calldata_page.0;
    ctx.saved_context.common_part.code_page = out_of_circuit_context.code_page.0;

    // various counters
    ctx.saved_context.common_part.pc = out_of_circuit_context.pc;
    ctx.saved_context.common_part.sp = out_of_circuit_context.sp;
    ctx.saved_context.common_part.exception_handler_loc = out_of_circuit_context.exception_handler_location;
    ctx.saved_context.common_part.ergs_remaining = out_of_circuit_context.ergs_remaining;

    // addresses
    use crate::u160_from_address;
    ctx.saved_context.common_part.code_address = u160_from_address(out_of_circuit_context.code_address);
    ctx.saved_context.common_part.this = u160_from_address(out_of_circuit_context.this_address);
    ctx.saved_context.common_part.caller = u160_from_address(out_of_circuit_context.msg_sender);
    
    // flags
    ctx.saved_context.common_part.is_static_execution = out_of_circuit_context.is_static;
    ctx.saved_context.extension.is_local_call = out_of_circuit_context.is_local_frame;
    ctx.saved_context.common_part.is_kernel_mode = out_of_circuit_context.is_kernel_mode();

    drop(ctx);

    // storage log specific part
    hidden_fsm.callstack.current_context.saved_context.common_part.reverted_queue_head = aux_params.current_frame_rollback_queue_head;
    hidden_fsm.callstack.current_context.saved_context.common_part.reverted_queue_tail = aux_params.current_frame_rollback_queue_tail;
    hidden_fsm.callstack.current_context.saved_context.common_part.reverted_queue_segment_len = aux_params.current_frame_rollback_queue_segment_length;

    // arithmetic flags
    hidden_fsm.flags = ArithmeticFlagsPortWitness {
        overflow_or_less_than: vm_state.flags.overflow_or_less_than_flag,
        equal: vm_state.flags.equality_flag,
        greater_than: vm_state.flags.greater_than_flag,
    };

    // registers
    assert_eq!(hidden_fsm.registers.len(), vm_state.registers.len());
    for (dst, src) in hidden_fsm.registers.iter_mut().zip(vm_state.registers.iter()) {
        let low = (src.0[0] as u128) + ((src.0[1] as u128) << 64);
        let high = (src.0[2] as u128) + ((src.0[3] as u128) << 64);
        dst.inner[0] = low;
        dst.inner[1] = high;
    }

    for (i, dst) in hidden_fsm.previous_code_word.iter_mut().enumerate() {
        let value = vm_state.previous_code_word.0[i];
        *dst = value;
    }

    // auxilary counters and information

    hidden_fsm.timestamp = vm_state.timestamp;
    hidden_fsm.memory_page_counter = vm_state.memory_page_counter;
    hidden_fsm.tx_number_in_block = vm_state.tx_number_in_block;
    hidden_fsm.previous_super_pc = vm_state.previous_super_pc;
    hidden_fsm.did_call_or_ret_recently = vm_state.did_call_or_ret_recently;
    hidden_fsm.tx_origin = u160_from_address(vm_state.tx_origin);
    hidden_fsm.ergs_per_pubdata_byte = vm_state.current_ergs_per_pubdata_byte;

    hidden_fsm.memory_queue_state = aux_params.memory_queue_state.tail;
    hidden_fsm.memory_queue_length = aux_params.memory_queue_state.length;

    hidden_fsm.code_decommittment_queue_state = aux_params.decommittment_queue_state.tail;
    hidden_fsm.code_decommittment_queue_length = aux_params.decommittment_queue_state.length;

    hidden_fsm
}

pub fn vm_instance_witness_to_circuit_formal_input<E: Engine, O: WitnessOracle<E>>(
    witness: VmInstanceWitness<E, O>,
    is_first: bool,
    is_last: bool,
    global_context: GlobalContext<E>,
) -> VmCircuitWitness<E, O> {
    let VmInstanceWitness {
        initial_state,
        witness_oracle,
        auxilary_initial_parameters,
        cycles_range: _,
    
        // final state for test purposes
        final_state,
        auxilary_final_parameters,
    } = witness;

    use sync_vm::traits::CSWitnessable;
    use sync_vm::vm::vm_cycle::input::*;
    use crate::witness::oracle::VmInCircuitAuxilaryParameters;

    use sync_vm::vm::vm_state::*;

    let hidden_fsm_input = vm_instance_witness_to_vm_formal_state(
        &initial_state,
        &auxilary_initial_parameters
    );

    let hidden_fsm_output = vm_instance_witness_to_vm_formal_state(
        &final_state,
        &auxilary_final_parameters
    );

    let mut observable_input = VmInputData::placeholder_witness();
    if is_first {
        let VmInCircuitAuxilaryParameters {
            decommittment_queue_state,
            memory_queue_state,
            current_frame_rollback_queue_tail,
            ..
        } = auxilary_initial_parameters;

        observable_input.rollback_queue_tail_for_block = current_frame_rollback_queue_tail;
        observable_input.memory_queue_initial_state = memory_queue_state;
        observable_input.decommitment_queue_initial_state = decommittment_queue_state;
        observable_input.per_block_context = global_context.create_witness().unwrap();
    }


    let mut observable_output = VmOutputData::placeholder_witness();
    if is_last {
        let VmInCircuitAuxilaryParameters {
            decommittment_queue_state,
            memory_queue_state,
            storage_log_queue_state,
            ..
        } = auxilary_final_parameters;

        observable_output.memory_queue_final_state = memory_queue_state;
        observable_output.decommitment_queue_final_state = decommittment_queue_state;
        observable_output.log_queue_final_state = storage_log_queue_state;
    }

    VmCircuitWitness {
        closed_form_input: VmCircuitInputOutputWitness::<E> {
            start_flag: is_first,
            completion_flag: is_last,
            observable_input,
            observable_output,
            hidden_fsm_input,
            hidden_fsm_output,
            _marker_e: (),
            _marker: std::marker::PhantomData,
        },
        witness_oracle,
    }
}
use boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use boojum::config::DevCSConfig;
use boojum::cs::CSGeometry;
use boojum::cs::GateConfigurationHolder;
use boojum::cs::StaticToolboxHolder;
use boojum::cs::gates::BooleanConstraintGate;
use boojum::cs::gates::ConstantsAllocatorGate;
use boojum::cs::gates::FmaGateInBaseFieldWithoutConstant;
use boojum::cs::gates::ReductionGate;
use boojum::cs::gates::SelectionGate;
use boojum::cs::implementations::reference_cs::CSReferenceImplementation;
use boojum::cs::traits::cs::ConstraintSystem;
use boojum::gadgets::queue::QueueStateWitness;
use boojum::gadgets::queue::QueueTailState;
use boojum::gadgets::queue::QueueTailStateWitness;
use boojum::gadgets::traits::encodable::CircuitEncodable;
use zkevm_circuits::base_structures::vm_state::GlobalContextWitness;
use zkevm_circuits::base_structures::vm_state::VmLocalStateWitness;
use zk_evm::aux_structures::LogQuery;
use zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use crate::encodings::log_query::LogQueueState;
use crate::encodings::log_query::LogQueueSimulator;
use boojum::field::SmallField;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::gadgets::poseidon::CircuitRoundFunction;
use boojum::gadgets::queue::QueueState;
use zkevm_circuits::base_structures::vm_state::{QUEUE_STATE_WIDTH, FULL_SPONGE_QUEUE_STATE_WIDTH};

pub fn log_queries_into_states<
    F: SmallField,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
>(queries: impl Iterator<Item = LogQuery>, round_function: &R) -> Vec<LogQueueState<F>> {
    let mut result = vec![];
    let mut simulator = LogQueueSimulator::<F>::empty();
    for q in queries {
        let (_, intermediate_info) = simulator.push_and_output_intermediate_data(q, round_function);
        result.push(intermediate_info);
    }

    result
}

use super::*;

use crate::encodings::{QueueIntermediateStates};

pub fn transform_queue_state<F: SmallField, const N: usize, const M: usize>(
    witness_state: QueueIntermediateStates<F, QUEUE_STATE_WIDTH, N, M>,
) -> QueueStateWitness<F, QUEUE_STATE_WIDTH> {
    let result = QueueStateWitness {
        head: witness_state.head,
        tail: QueueTailStateWitness {
            tail: witness_state.tail,
            length: witness_state.num_items
        },
    };

    result
}

pub fn transform_sponge_like_queue_state<F: SmallField, const M: usize>(
    witness_state: FullWidthQueueIntermediateStates<F, FULL_SPONGE_QUEUE_STATE_WIDTH, M>,
) -> QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH> {
    let result = QueueStateWitness {
        head: witness_state.head,
        tail: QueueTailStateWitness {
            tail: witness_state.tail,
            length: witness_state.num_items
        },
    };

    result
}

use crate::encodings::*;

pub fn take_queue_state_from_simulator<
    F: SmallField, 
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const N: usize,
    const ROUNDS: usize
>(
    simulator: &QueueSimulator<F, I, QUEUE_STATE_WIDTH, N, ROUNDS>
) -> QueueStateWitness<F, QUEUE_STATE_WIDTH> {
    let result = QueueStateWitness {
        head: simulator.head,
        tail: QueueTailStateWitness {
            tail: simulator.tail,
            length: simulator.num_items
        },
    };

    result
}

pub fn take_sponge_like_queue_state_from_simulator<
    F: SmallField, 
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const N: usize,
    const ROUNDS: usize
>(
    simulator: &FullWidthQueueSimulator<F, I, N, 12, ROUNDS>
) -> QueueStateWitness<F, FULL_SPONGE_QUEUE_STATE_WIDTH> {
    let result = QueueStateWitness {
        head: simulator.head,
        tail: QueueTailStateWitness {
            tail: simulator.tail,
            length: simulator.num_items
        },
    };
    
    result
}

use std::collections::VecDeque;
use boojum::gadgets::queue::CircuitQueueWitness;
use std::sync::RwLock;

pub fn transform_queue_witness<
    'a, 
    F: SmallField, 
    I: OutOfCircuitFixedLengthEncodable<F, N> + 'a + CircuitEquivalentReflection<F, Destination = D>,
    const N: usize,
    D: CircuitEncodable<F, N>,
>(
    witness_iter: impl Iterator<Item = &'a ([F; N], [F; QUEUE_STATE_WIDTH], I)>,
) -> CircuitQueueWitness<F, D, QUEUE_STATE_WIDTH, N> {
    let wit: VecDeque<_> = witness_iter.map(|(enc, old_tail, el)| {
        (el.reflect(), *old_tail)
    }).collect();

    CircuitQueueWitness {
        elements: RwLock::new(wit)
    }
}

use zk_evm::aux_structures::MemoryQuery;
use boojum::gadgets::traits::allocatable::*;
use boojum::gadgets::poseidon::BuildableCircuitRoundFunction;
use boojum::gadgets::traits::encodable::CircuitVarLengthEncodable;
use boojum::gadgets::traits::witnessable::WitnessHookable;
use zkevm_circuits::fsm_input_output::*;

pub fn create_cs_for_witness_generation<
F: SmallField,
R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
>() -> CSReferenceImplementation<F, F, DevCSConfig, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
    // create temporary cs, and allocate in full

    let geometry = CSGeometry {
        num_columns_under_copy_permutation: 140,
        num_witness_columns: 0,
        num_constant_columns: 8,
        max_allowed_constraint_degree: 8
    };
    let max_trace_len = 1 << 20;
    let num_vars = 1 << 24;

    let max_trace_len = 1 << 23;
    let num_vars = 1 << 27;

    use boojum::cs::cs_builder_reference::CsReferenceImplementationBuilder;
    use boojum::config::DevCSConfig;

    let builder_impl = CsReferenceImplementationBuilder::<F, F, DevCSConfig>::new(
        geometry, 
        num_vars, 
        max_trace_len,
    );
    let builder = boojum::cs::cs_builder::new_cs_builder::<_, F>(builder_impl);
    let builder = builder.allow_lookup(
        boojum::cs::LookupParameters::UseSpecializedColumnsWithTableIdAsConstant { 
            width: 3, 
            num_repetitions: 1, 
            share_table_id: true
        }
    );

    let builder = ConstantsAllocatorGate::configure_builder(builder, boojum::cs::GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = R::configure_builder(builder, boojum::cs::GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(builder, boojum::cs::GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = BooleanConstraintGate::configure_builder(builder, boojum::cs::GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = ReductionGate::<F, 4>::configure_builder(builder, boojum::cs::GatePlacementStrategy::UseGeneralPurposeColumns);
    let builder = SelectionGate::configure_builder(builder, boojum::cs::GatePlacementStrategy::UseGeneralPurposeColumns);

    let mut cs = builder.build(());

    use boojum::gadgets::tables::*;
    use boojum::cs::traits::cs::ConstraintSystem;

    let table = create_binop_table();
    cs.add_lookup_table::<BinopTable, 3>(table);

    cs
}

pub fn simulate_public_input_value_from_witness<
    F: SmallField,
    CS: ConstraintSystem<F>,
    R: BuildableCircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4> + serde::Serialize + serde::de::DeserializeOwned,
    T: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessHookable<F>,
    IN: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessHookable<F>,
    OUT: Clone + std::fmt::Debug + CSAllocatable<F> + CircuitVarLengthEncodable<F> + WitnessHookable<F>,
>(
    cs: &mut CS,
    input_witness: ClosedFormInputWitness<F, T, IN, OUT>, 
    round_function: &R,
) -> ([F; INPUT_OUTPUT_COMMITMENT_LENGTH], ClosedFormInputCompactFormWitness<F>)
where
    <T as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <IN as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
    <OUT as CSAllocatable<F>>::Witness: serde::Serialize + serde::de::DeserializeOwned + Eq,
{
    // allocate in full
    
    let full_input = ClosedFormInput::allocate(cs, input_witness);
    // compute the compact form
    let compact_form = ClosedFormInputCompactForm::from_full_form(cs, &full_input, round_function);
    // compute the encoding and committment of compact form
    let compact_form_witness = compact_form.witness_hook(&*cs)().unwrap();

    // dbg!(&compact_form_witness);

    let input_commitment = commit_variable_length_encodable_item(cs, &compact_form, round_function);
    let public_input = input_commitment.witness_hook(&*cs)().unwrap();

    (public_input, compact_form_witness)
}

// use crate::witness::oracle::VmInstanceWitness;
// use sync_vm::vm::vm_cycle::witness_oracle::WitnessOracle;
// use sync_vm::vm::vm_cycle::input::VmCircuitWitness;

use crate::witness::oracle::VmInCircuitAuxilaryParameters;

pub fn vm_instance_witness_to_vm_formal_state<F: SmallField>(
    vm_state: &zk_evm::vm_state::VmLocalState,
    aux_params: &VmInCircuitAuxilaryParameters<F>,
) -> VmLocalStateWitness<F> {
    use boojum::gadgets::traits::allocatable::CSAllocatable;
    use zkevm_circuits::base_structures::vm_state::VmLocalState;

    let mut hidden_fsm = VmLocalState::placeholder_witness();
    // depth and state encoding
    hidden_fsm.callstack.stack_sponge_state = aux_params.callstack_state.0;
    hidden_fsm.callstack.context_stack_depth = vm_state.callstack.depth() as u32;

    // non-saved part
    hidden_fsm.callstack.current_context.log_queue_forward_part_length = aux_params.storage_log_queue_state.tail.length;
    hidden_fsm.callstack.current_context.log_queue_forward_tail = aux_params.storage_log_queue_state.tail.tail;
    // saved part

    let mut ctx = &mut hidden_fsm.callstack.current_context;
    let out_of_circuit_context = &vm_state.callstack.current;

    // memory pages
    ctx.saved_context.base_page = out_of_circuit_context.base_memory_page.0;
    ctx.saved_context.code_page = out_of_circuit_context.code_page.0;

    // memory sizes
    ctx.saved_context.heap_upper_bound = out_of_circuit_context.heap_bound;
    ctx.saved_context.aux_heap_upper_bound = out_of_circuit_context.aux_heap_bound;

    // context composite
    ctx.saved_context.context_u128_value_composite[0] = out_of_circuit_context.context_u128_value as u32;
    ctx.saved_context.context_u128_value_composite[1] = (out_of_circuit_context.context_u128_value >> 32) as u32;
    ctx.saved_context.context_u128_value_composite[2] = (out_of_circuit_context.context_u128_value >> 64) as u32;
    ctx.saved_context.context_u128_value_composite[3] = (out_of_circuit_context.context_u128_value >> 96) as u32;

    // various counters
    ctx.saved_context.pc = out_of_circuit_context.pc;
    ctx.saved_context.sp = out_of_circuit_context.sp;
    ctx.saved_context.exception_handler_loc = out_of_circuit_context.exception_handler_location;
    ctx.saved_context.ergs_remaining = out_of_circuit_context.ergs_remaining;

    // addresses
    ctx.saved_context.code_address = out_of_circuit_context.code_address;
    ctx.saved_context.this = out_of_circuit_context.this_address;
    ctx.saved_context.caller = out_of_circuit_context.msg_sender;
    
    // flags
    ctx.saved_context.is_static_execution = out_of_circuit_context.is_static;
    ctx.saved_context.is_local_call = out_of_circuit_context.is_local_frame;
    ctx.saved_context.is_kernel_mode = out_of_circuit_context.is_kernel_mode();

    drop(ctx);

    // storage log specific part
    hidden_fsm.callstack.current_context.saved_context.reverted_queue_head = aux_params.current_frame_rollback_queue_head;
    hidden_fsm.callstack.current_context.saved_context.reverted_queue_tail = aux_params.current_frame_rollback_queue_tail;
    hidden_fsm.callstack.current_context.saved_context.reverted_queue_segment_len = aux_params.current_frame_rollback_queue_segment_length;

    use zkevm_circuits::base_structures::vm_state::ArithmeticFlagsPortWitness;

    // arithmetic flags
    hidden_fsm.flags = ArithmeticFlagsPortWitness {
        overflow_or_less_than: vm_state.flags.overflow_or_less_than_flag,
        equal: vm_state.flags.equality_flag,
        greater_than: vm_state.flags.greater_than_flag,
    };

    // registers
    assert_eq!(hidden_fsm.registers.len(), vm_state.registers.len());
    for (dst, src) in hidden_fsm.registers.iter_mut().zip(vm_state.registers.iter()) {
        dst.value = src.value;
        dst.is_pointer = src.is_pointer;
    }

    hidden_fsm.previous_code_word = vm_state.previous_code_word;

    // auxilary counters and information

    hidden_fsm.timestamp = vm_state.timestamp;
    hidden_fsm.memory_page_counter = vm_state.memory_page_counter;
    hidden_fsm.tx_number_in_block = vm_state.tx_number_in_block as u32;
    hidden_fsm.previous_code_page = vm_state.previous_code_memory_page.0;
    hidden_fsm.previous_super_pc = vm_state.previous_super_pc;
    hidden_fsm.ergs_per_pubdata_byte = vm_state.current_ergs_per_pubdata_byte;
    hidden_fsm.pending_exception = vm_state.pending_exception;

    hidden_fsm.context_composite_u128 = [
        vm_state.context_u128_register as u32,
        (out_of_circuit_context.context_u128_value >> 32) as u32,
        (out_of_circuit_context.context_u128_value >> 64) as u32,
        (out_of_circuit_context.context_u128_value >> 96) as u32,
    ];

    hidden_fsm.memory_queue_state = aux_params.memory_queue_state.tail.tail;
    hidden_fsm.memory_queue_length = aux_params.memory_queue_state.tail.length;

    hidden_fsm.code_decommittment_queue_state = aux_params.decommittment_queue_state.tail.tail;
    hidden_fsm.code_decommittment_queue_length = aux_params.decommittment_queue_state.tail.length;

    hidden_fsm
}

use crate::witness::oracle::VmInstanceWitness;
use zkevm_circuits::main_vm::witness_oracle::WitnessOracle;
use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::VmCircuitWitness;

pub fn vm_instance_witness_to_circuit_formal_input<F: SmallField, O: WitnessOracle<F>>(
    witness: VmInstanceWitness<F, O>,
    is_first: bool,
    is_last: bool,
    global_context: GlobalContextWitness<F>,
) -> VmCircuitWitness<F, O> {
    let VmInstanceWitness {
        initial_state,
        witness_oracle,
        auxilary_initial_parameters,
        cycles_range: _,
    
        // final state for test purposes
        final_state,
        auxilary_final_parameters,
    } = witness;

    use crate::witness::oracle::VmInCircuitAuxilaryParameters;

    let hidden_fsm_input = vm_instance_witness_to_vm_formal_state(
        &initial_state,
        &auxilary_initial_parameters
    );

    let hidden_fsm_output = vm_instance_witness_to_vm_formal_state(
        &final_state,
        &auxilary_final_parameters
    );

    use boojum::gadgets::traits::allocatable::CSAllocatable;
    use zkevm_circuits::fsm_input_output::circuit_inputs::main_vm::*;

    let mut observable_input = VmInputData::placeholder_witness();
    if is_first {
        let VmInCircuitAuxilaryParameters {
            decommittment_queue_state,
            memory_queue_state,
            current_frame_rollback_queue_tail,
            ..
        } = auxilary_initial_parameters;

        observable_input.rollback_queue_tail_for_block = current_frame_rollback_queue_tail;
        observable_input.memory_queue_initial_state = memory_queue_state.tail;
        observable_input.decommitment_queue_initial_state = decommittment_queue_state.tail;
        observable_input.per_block_context = global_context;
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
        closed_form_input: VmCircuitInputOutputWitness {
            start_flag: is_first,
            completion_flag: is_last,
            observable_input,
            observable_output,
            hidden_fsm_input,
            hidden_fsm_output,
        },
        witness_oracle,
    }
}

pub fn produce_fs_challenges<
    F: SmallField,
    R: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>,
    const N: usize,
    const NUM_CHALLENGES: usize,
    const NUM_REPETITIONS: usize,
>(
    unsorted_tail: QueueTailStateWitness<F, N>,
    sorted_tail: QueueTailStateWitness<F, N>,
    round_function: &R
) -> [[F; NUM_CHALLENGES]; NUM_REPETITIONS] {
    let mut fs_input = vec![];
    fs_input.extend_from_slice(&unsorted_tail.tail);
    fs_input.push(F::from_u64_with_reduction(unsorted_tail.length as u64));
    fs_input.extend_from_slice(&sorted_tail.tail);
    fs_input.push(F::from_u64_with_reduction(sorted_tail.length as u64));

    let mut state = R::initial_state();
    R::specialize_for_len(fs_input.len() as u32, &mut state);
    let mut it = fs_input.array_chunks::<8>();
    for chunk in &mut it {
        R::absorb_into_state::<AbsorbtionModeOverwrite>(&mut state, chunk);
        R::round_function(&mut state);
    }

    let remainder = it.remainder();
    if remainder.len() != 0 {
        let mut padded_chunk = [F::ZERO; 8];
        padded_chunk[..remainder.len()].copy_from_slice(remainder);
        R::absorb_into_state::<AbsorbtionModeOverwrite>(&mut state, &padded_chunk);
        R::round_function(&mut state);
    }

    // now get as many as necessary
    let max_to_take = 8;
    let mut can_take = max_to_take;

    let mut result = [[F::ONE; NUM_CHALLENGES]; NUM_REPETITIONS];

    for dst in result.iter_mut() {
        for dst in dst.iter_mut().skip(1) {
            if can_take == 0 {
                R::round_function(&mut state);
                can_take = max_to_take;
            }
            let el = state[max_to_take - can_take];
            can_take -= 1;
            *dst = el;
        }
    }

    result
}

const PARALLELIZATION_CHUNK_SIZE: usize = 1 << 16;

pub(crate) fn compute_grand_product_chains<F: SmallField, const N: usize, const M: usize>(
    lhs_contributions: &Vec<[F; N]>,
    rhs_contributions: &Vec<[F; N]>,
    challenges: &[F; M],
) -> (Vec<F>, Vec<F>) {
    assert_eq!(N+1, M);
    let mut lhs_grand_product_chain: Vec<F> = vec![F::ZERO; lhs_contributions.len()];
    let mut rhs_grand_product_chain: Vec<F> = vec![F::ZERO; rhs_contributions.len()];

    let challenges: [F; M] = *challenges;

    use rayon::prelude::*;

    lhs_grand_product_chain.par_chunks_mut(PARALLELIZATION_CHUNK_SIZE).zip(lhs_contributions.par_chunks(PARALLELIZATION_CHUNK_SIZE)).for_each(
        |(dst, src)| {
            let mut grand_product = F::ONE;
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = challenges[M-1];

                debug_assert_eq!(challenges[..(M-1)].len(), src.len());

                for (a, b) in src.iter().zip(challenges[..(M-1)].iter()) {
                    let mut tmp = *a;
                    tmp.mul_assign(b);
                    acc.add_assign(&tmp);
                }

                grand_product.mul_assign(&acc);
    
                *dst = grand_product;
            }
        }
    );

    rhs_grand_product_chain.par_chunks_mut(PARALLELIZATION_CHUNK_SIZE).zip(rhs_contributions.par_chunks(PARALLELIZATION_CHUNK_SIZE)).for_each(
        |(dst, src)| {
            let mut grand_product = F::ONE;
            for (dst, src) in dst.iter_mut().zip(src.iter()) {
                let mut acc = challenges[M-1];

                debug_assert_eq!(challenges[..(M-1)].len(), src.len());

                for (a, b) in src.iter().zip(challenges[..(M-1)].iter()) {
                    let mut tmp = *a;
                    tmp.mul_assign(b);
                    acc.add_assign(&tmp);
                }

                grand_product.mul_assign(&acc);
    
                *dst = grand_product;
            }
        }
    );

    // elementwise products are done, now must fold

    let mut lhs_intermediates: Vec<F> = lhs_grand_product_chain.par_chunks(PARALLELIZATION_CHUNK_SIZE).map(
        |slice: &[F]| {
            *slice.last().unwrap()
        }
    ).collect();

    let mut rhs_intermediates: Vec<F> = rhs_grand_product_chain.par_chunks(PARALLELIZATION_CHUNK_SIZE).map(
        |slice: &[F]| {
            *slice.last().unwrap()
        }
    ).collect();

    assert_eq!(lhs_intermediates.len(), lhs_grand_product_chain.chunks(PARALLELIZATION_CHUNK_SIZE).len());
    assert_eq!(rhs_intermediates.len(), rhs_grand_product_chain.chunks(PARALLELIZATION_CHUNK_SIZE).len());

    // accumulate intermediate products
    // we should multiply element [1] by element [0],
    // element [2] by [0] * [1],
    // etc
    let mut acc_lhs = F::ONE;
    for el in lhs_intermediates.iter_mut() {
        let tmp = *el;
        el.mul_assign(&acc_lhs);
        acc_lhs.mul_assign(&tmp);
    }

    let mut acc_rhs = F::ONE;
    for el in rhs_intermediates.iter_mut() {
        let tmp = *el;
        el.mul_assign(&acc_rhs);
        acc_rhs.mul_assign(&tmp);
    }

    match (lhs_intermediates.last(), rhs_intermediates.last()) {
        (Some(lhs), Some(rhs)) => {
            assert_eq!(lhs, rhs);
        },
        (None, None) => {
        },
        _ => unreachable!(),
    }

    lhs_grand_product_chain.par_chunks_mut(PARALLELIZATION_CHUNK_SIZE).skip(1).zip(lhs_intermediates.par_chunks(1)).for_each(
        |(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        }
    );

    rhs_grand_product_chain.par_chunks_mut(PARALLELIZATION_CHUNK_SIZE).skip(1).zip(rhs_intermediates.par_chunks(1)).for_each(
        |(dst, src)| {
            let src = src[0];
            for dst in dst.iter_mut() {
                dst.mul_assign(&src);
            }
        }
    );

    // sanity check
    match (lhs_grand_product_chain.last(), rhs_grand_product_chain.last()) {
        (Some(lhs), Some(rhs)) => {
            assert_eq!(lhs, rhs);
        },
        (None, None) => {
        },
        _ => unreachable!(),
    }

    (lhs_grand_product_chain, rhs_grand_product_chain)
}

pub fn transpose_chunks<T: Clone>(
    original: &Vec<Vec<T>>,
    chunk_size: usize,
) -> Vec<Vec<&[T]>> {
    let capacity = original[0].chunks(chunk_size).len();
    let mut transposed = vec![Vec::with_capacity(original.len()); capacity];
    for outer in original.iter() {
        for (dst, chunk) in transposed.iter_mut().zip(outer.chunks(chunk_size)) {
            dst.push(chunk);
        }
    }

    transposed
}
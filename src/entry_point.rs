use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use sync_vm::franklin_crypto::bellman::SynthesisError;
use sync_vm::project_ref;
use sync_vm::vm::primitives::uint256::UInt256;
use sync_vm::vm::vm_cycle::cycle::vm_process_pending;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
use sync_vm::vm::vm_state::GlobalContext;
use zk_evm::aux_structures::*;
use zk_evm::ethereum_types::*;
use zk_evm::vm_state::CallStackEntry;
use zk_evm::vm_state::VmState;
use zk_evm::zkevm_opcode_defs::system_params::INITIAL_FRAME_FORMAL_EH_LOCATION;
use zk_evm::zkevm_opcode_defs::*;

use super::*;

// Define initial contexts to work with

pub fn initial_out_of_circuit_context(
    initial_pc: u16,
    initial_ergs: u32,
    this_address: Address,
    msg_sender: Address,
    code_address: Address,
) -> CallStackEntry {
    CallStackEntry {
        this_address,
        msg_sender,
        code_address,
        base_memory_page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_BASE_PAGE),
        code_page: MemoryPage(zk_evm::zkevm_opcode_defs::BOOTLOADER_CODE_PAGE),
        sp: INITIAL_SP_ON_FAR_CALL as u16,
        pc: initial_pc,
        exception_handler_location: INITIAL_FRAME_FORMAL_EH_LOCATION,
        ergs_remaining: initial_ergs,
        this_shard_id: 0,
        caller_shard_id: 0,
        code_shard_id: 0,
        is_static: false,
        is_local_frame: false,
        context_u128_value: 0,
        heap_bound: zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_MAX_MEMORY, // so bootloader doesn't pay for resizes
        aux_heap_bound: zk_evm::zkevm_opcode_defs::system_params::BOOTLOADER_MAX_MEMORY, // so bootloader doesn't pay for resizes
    }
}

use sync_vm::franklin_crypto::bellman::pairing::Engine;
use sync_vm::franklin_crypto::plonk::circuit::allocated_num::Num;
use sync_vm::franklin_crypto::plonk::circuit::boolean::Boolean;
use sync_vm::vm::primitives::*;
use sync_vm::vm::vm_state::execution_context::FullExecutionContext;

pub fn initial_in_circuit_context<E: Engine>(
    initial_pc: u16,
    initial_ergs: u32,
    this_address: Address,
    msg_sender: Address,
    code_address: Address,
    initial_rollback_queue_value: E::Fr,
) -> FullExecutionContext<E> {
    let mut ctx = FullExecutionContext::uninitialized();

    ctx.saved_context.common_part.base_page =
        UInt32::from_uint(zk_evm::zkevm_opcode_defs::BOOTLOADER_BASE_PAGE);
    ctx.saved_context.common_part.code_page =
        UInt32::from_uint(zk_evm::zkevm_opcode_defs::BOOTLOADER_CODE_PAGE);

    ctx.saved_context.common_part.pc = UInt16::from_uint(initial_pc);
    ctx.saved_context.common_part.sp = UInt16::from_uint(INITIAL_SP_ON_FAR_CALL as u16);
    ctx.saved_context.common_part.exception_handler_loc =
        UInt16::from_uint(INITIAL_FRAME_FORMAL_EH_LOCATION);
    ctx.saved_context.common_part.ergs_remaining = UInt32::from_uint(initial_ergs);

    ctx.saved_context.common_part.code_address =
        UInt160::from_uint(u160_from_address(code_address));
    ctx.saved_context.common_part.this = UInt160::from_uint(u160_from_address(this_address));
    ctx.saved_context.common_part.caller = UInt160::from_uint(u160_from_address(msg_sender));

    // circuit specific bit
    ctx.saved_context.common_part.reverted_queue_tail = Num::Constant(initial_rollback_queue_value);
    ctx.saved_context.common_part.reverted_queue_head =
        ctx.saved_context.common_part.reverted_queue_tail;

    ctx
}

pub fn out_to_in_circuit_context_on_call<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    out_of_circuit_context: CallStackEntry,
    initial_rollback_queue_value: E::Fr,
) -> FullExecutionContext<E> {
    let mut ctx = FullExecutionContext::uninitialized();

    ctx.saved_context.common_part.base_page =
        UInt32::from_uint(out_of_circuit_context.base_memory_page.0);
    ctx.saved_context.common_part.code_page = UInt32::from_uint(out_of_circuit_context.code_page.0);

    ctx.saved_context.common_part.pc = UInt16::from_uint(out_of_circuit_context.pc);
    ctx.saved_context.common_part.exception_handler_loc =
        UInt16::from_uint(out_of_circuit_context.exception_handler_location);
    ctx.saved_context.common_part.ergs_remaining =
        UInt32::from_uint(out_of_circuit_context.ergs_remaining);

    ctx.saved_context.common_part.code_address =
        UInt160::from_uint(u160_from_address(out_of_circuit_context.code_address));
    ctx.saved_context.common_part.this =
        UInt160::from_uint(u160_from_address(out_of_circuit_context.this_address));
    ctx.saved_context.common_part.caller =
        UInt160::from_uint(u160_from_address(out_of_circuit_context.msg_sender));

    ctx.saved_context.common_part.heap_upper_bound =
        UInt32::from_uint(out_of_circuit_context.heap_bound);
    ctx.saved_context.common_part.aux_heap_upper_bound =
        UInt32::from_uint(out_of_circuit_context.aux_heap_bound);

    // circuit specific bit
    ctx.saved_context.common_part.reverted_queue_tail = Num::Constant(initial_rollback_queue_value);
    ctx.saved_context.common_part.reverted_queue_head =
        ctx.saved_context.common_part.reverted_queue_tail;

    ctx.saved_context.common_part.is_kernel_mode =
        Boolean::alloc(cs, Some(out_of_circuit_context.is_kernel_mode())).unwrap();

    ctx
}

/// Allocated execution context with uninitialized rollback queue head/tail/length
pub fn alloc_execution_context<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    out_of_circuit_context: Option<CallStackEntry>,
) -> Result<FullExecutionContext<E>, SynthesisError> {
    let mut ctx = FullExecutionContext::uninitialized();

    let base_page = project_ref!(out_of_circuit_context, base_memory_page).map(|el| el.0);
    ctx.saved_context.common_part.base_page = UInt32::allocate(cs, base_page)?;
    let code_page = project_ref!(out_of_circuit_context, code_page).map(|el| el.0);
    ctx.saved_context.common_part.code_page = UInt32::allocate(cs, code_page)?;

    let heap_bound = project_ref!(out_of_circuit_context, heap_bound).cloned();
    ctx.saved_context.common_part.heap_upper_bound = UInt32::allocate(cs, heap_bound)?;
    let aux_heap_bound = project_ref!(out_of_circuit_context, aux_heap_bound).cloned();
    ctx.saved_context.common_part.aux_heap_upper_bound = UInt32::allocate(cs, aux_heap_bound)?;

    ctx.saved_context.common_part.pc =
        UInt16::allocate(cs, project_ref!(out_of_circuit_context, pc).cloned())?;
    ctx.saved_context.common_part.sp =
        UInt16::allocate(cs, project_ref!(out_of_circuit_context, sp).cloned())?;
    ctx.saved_context.common_part.exception_handler_loc = UInt16::allocate(
        cs,
        project_ref!(out_of_circuit_context, exception_handler_location).cloned(),
    )?;
    ctx.saved_context.common_part.ergs_remaining = UInt32::allocate(
        cs,
        project_ref!(out_of_circuit_context, ergs_remaining).cloned(),
    )?;

    ctx.saved_context.common_part.code_address = UInt160::allocate(
        cs,
        project_ref!(out_of_circuit_context, code_address)
            .cloned()
            .map(u160_from_address),
    )?;
    ctx.saved_context.common_part.this = UInt160::allocate(
        cs,
        project_ref!(out_of_circuit_context, this_address)
            .cloned()
            .map(u160_from_address),
    )?;
    ctx.saved_context.common_part.caller = UInt160::allocate(
        cs,
        project_ref!(out_of_circuit_context, msg_sender)
            .cloned()
            .map(u160_from_address),
    )?;

    let is_static_execution = project_ref!(out_of_circuit_context, is_static).cloned();
    ctx.saved_context.common_part.is_static_execution = Boolean::alloc(cs, is_static_execution)?;

    let is_local_call = project_ref!(out_of_circuit_context, is_local_frame).cloned();
    ctx.saved_context.extension.is_local_call = Boolean::alloc(cs, is_local_call)?;

    let is_kernel_mode = out_of_circuit_context.map(|el| el.is_kernel_mode());

    ctx.saved_context.common_part.is_kernel_mode = Boolean::alloc(cs, is_kernel_mode)?;

    Ok(ctx)
}

use sync_vm::vm::ports::ArithmeticFlagsPort;

pub fn alloc_arithmetic_port<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    flags_witness: Option<zk_evm::flags::Flags>,
) -> Result<ArithmeticFlagsPort<E>, SynthesisError> {
    let overflow_or_less_than = Boolean::alloc(
        cs,
        project_ref!(flags_witness, overflow_or_less_than_flag).cloned(),
    )?;
    let equal = Boolean::alloc(cs, project_ref!(flags_witness, equality_flag).cloned())?;
    let greater_than = Boolean::alloc(cs, project_ref!(flags_witness, greater_than_flag).cloned())?;

    let new = ArithmeticFlagsPort {
        overflow_or_less_than,
        equal,
        greater_than,
        _marker: std::marker::PhantomData,
    };

    Ok(new)
}

use zk_evm::block_properties::BlockProperties;

pub fn create_out_of_circuit_global_context(
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
) -> BlockProperties {
    BlockProperties {
        default_aa_code_hash,
        zkporter_is_available,
    }
}

pub fn create_in_circuit_global_context<E: Engine>(
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
) -> GlobalContext<E> {
    GlobalContext {
        zkporter_is_available: Boolean::constant(zkporter_is_available),
        default_aa_code_hash: UInt256::constant_from_biguint(u256_to_biguint(default_aa_code_hash)),
    }
}

use crate::witness::oracle::VmInCircuitAuxilaryParameters;
use crate::witness::oracle::VmInstanceWitness;
use crate::witness::oracle::VmWitnessOracle;

// pub fn create_in_circuit_vm<
//     E: Engine,
//     CS: ConstraintSystem<E>,
//     R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
// >(
//     cs: &mut CS,
//     _round_function: &R,
//     initial_rollback_queue_value: E::Fr,
//     initial_callstack_state_for_start: ([E::Fr; 3], CallStackEntry),
//     initial_context_for_start: CallStackEntry,
// ) -> sync_vm::vm::vm_state::VmLocalState<E, 3> {
//     // we need to prepare some global state and push initial context
//     // use sync_vm::vm::vm_cycle::register_view::Register;
//     use sync_vm::vm::primitives::register_view::Register;
//     use sync_vm::vm::vm_state::callstack::Callstack;
//     use sync_vm::vm::vm_state::PendingRoundFunctions;

//     let bool_false = Boolean::alloc(cs, Some(false)).unwrap();

//     let mut initial_callstack = Callstack::<E, 3>::empty();
//     let (initial_callstack_sponge_state, _empty_context) = initial_callstack_state_for_start;

//     let initial_callstack_sponge =
//         Num::alloc_multiple(cs, Some(initial_callstack_sponge_state)).unwrap();
//     initial_callstack.stack_sponge_state = initial_callstack_sponge;
//     initial_callstack.context_stack_depth = UInt16::from_uint(1);

//     let initial_context = out_to_in_circuit_context_on_call(
//         cs,
//         initial_context_for_start,
//         initial_rollback_queue_value,
//     );
//     initial_callstack.current_context = initial_context;

//     let initial_flags = ArithmeticFlagsPort::<E> {
//         overflow_or_less_than: bool_false,
//         equal: bool_false,
//         greater_than: bool_false,
//         _marker: std::marker::PhantomData,
//     };

//     let zero_u128 = UInt128::allocate(cs, Some(0)).unwrap();
//     let empty_reg = Register {
//         inner: [zero_u128; 2],
//     };

//     let state = sync_vm::vm::vm_state::VmLocalState {
//         previous_code_word: [UInt64::<E>::zero(); 4],
//         registers: [empty_reg; zk_evm::zkevm_opcode_defs::REGISTERS_COUNT],
//         flags: initial_flags,
//         timestamp: UInt32::<E>::from_uint(STARTING_TIMESTAMP),
//         memory_page_counter: UInt32::<E>::from_uint(STARTING_BASE_PAGE),
//         tx_number_in_block: UInt16::<E>::zero(),
//         previous_super_pc: UInt16::<E>::zero(),
//         did_call_or_ret_recently: Boolean::constant(true),
//         tx_origin: UInt160::<E>::zero(),
//         ergs_per_pubdata_byte: UInt32::<E>::zero(),
//         callstack: initial_callstack,
//         pending_sponges: PendingRoundFunctions::<E, 3>::empty(),
//         memory_queue_state: [Num::<E>::zero(); 3],
//         memory_queue_length: UInt32::<E>::zero(),
//         code_decommittment_queue_state: [Num::<E>::zero(); 3],
//         code_decommittment_queue_length: UInt32::<E>::zero(),
//         pending_arithmetic_operations: vec![],
//     };

//     state
// }

pub fn run_vm_instance<
    E: Engine,
    CS: ConstraintSystem<E>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    round_function: &R,
    in_circuit_global_context: &GlobalContext<E>,
    snapshot_data: VmInstanceWitness<E, VmWitnessOracle<E>>,
) -> sync_vm::vm::vm_state::VmGlobalState<E, 3> {
    // we need to prepare some global state and push initial context
    // use sync_vm::vm::vm_cycle::register_view::Register;
    use sync_vm::vm::primitives::register_view::Register;
    use sync_vm::vm::vm_state::callstack::Callstack;
    use sync_vm::vm::vm_state::PendingRoundFunctions;

    let VmInstanceWitness {
        initial_state,
        witness_oracle,
        auxilary_initial_parameters,
        cycles_range,
        final_state,
        auxilary_final_parameters,
    } = snapshot_data;

    let VmInCircuitAuxilaryParameters {
        callstack_state: (initial_callstack_sponge_state, initial_context_for_start),
        decommittment_queue_state,
        memory_queue_state: memory_queue_state_witness,
        storage_log_queue_state,
        current_frame_rollback_queue_tail,
        current_frame_rollback_queue_head,
        current_frame_rollback_queue_segment_length,
    } = auxilary_initial_parameters;

    let mut initial_callstack = Callstack::<E, 3>::empty();

    let initial_callstack_sponge =
        Num::alloc_multiple(cs, Some(initial_callstack_sponge_state)).unwrap();
    initial_callstack.stack_sponge_state = initial_callstack_sponge;
    initial_callstack.context_stack_depth =
        UInt32::allocate(cs, Some(initial_state.callstack.depth() as u32)).unwrap();

    let mut initial_context = alloc_execution_context(cs, Some(initial_context_for_start)).unwrap();
    // set forward and rollback queue properties

    initial_context.log_queue_forward_tail =
        Num::alloc(cs, Some(storage_log_queue_state.tail_state)).unwrap();
    initial_context.log_queue_forward_part_length =
        UInt32::allocate(cs, Some(storage_log_queue_state.num_items)).unwrap();

    initial_context
        .saved_context
        .common_part
        .reverted_queue_head = Num::alloc(cs, Some(current_frame_rollback_queue_head)).unwrap();
    initial_context
        .saved_context
        .common_part
        .reverted_queue_tail = Num::alloc(cs, Some(current_frame_rollback_queue_tail)).unwrap();
    initial_context
        .saved_context
        .common_part
        .reverted_queue_segment_len =
        UInt32::allocate(cs, Some(current_frame_rollback_queue_segment_length)).unwrap();

    initial_callstack.current_context = initial_context;

    let initial_flags = alloc_arithmetic_port(cs, Some(initial_state.flags)).unwrap();

    let mut regs = [Register::<E>::zero(); zk_evm::zkevm_opcode_defs::REGISTERS_COUNT];
    for (dst, src) in regs.iter_mut().zip(initial_state.registers.iter()) {
        let low = (src.value.0[0] as u128) | (src.value.0[1] as u128);
        let high = (src.value.0[2] as u128) | (src.value.0[3] as u128);

        let low = UInt128::allocate(cs, Some(low)).unwrap();
        let high = UInt128::allocate(cs, Some(high)).unwrap();
        dst.inner[0] = low;
        dst.inner[1] = high;
    }

    let mut previous_code_word = [UInt64::<E>::zero(); 4];
    for (i, dst) in previous_code_word.iter_mut().enumerate() {
        let value = initial_state.previous_code_word.0[i];
        *dst = UInt64::allocate(cs, Some(value)).unwrap();
    }

    let timestamp = UInt32::allocate(cs, Some(initial_state.timestamp)).unwrap();
    let memory_page_counter =
        UInt32::allocate(cs, Some(initial_state.memory_page_counter)).unwrap();
    let tx_number_in_block = UInt16::allocate(cs, Some(initial_state.tx_number_in_block)).unwrap();
    let previous_super_pc = UInt16::allocate(cs, Some(initial_state.previous_super_pc)).unwrap();
    let did_call_or_ret_recently =
        Boolean::alloc(cs, Some(initial_state.did_call_or_ret_recently)).unwrap();
    let ergs_per_pubdata_byte =
        UInt32::allocate(cs, Some(initial_state.current_ergs_per_pubdata_byte)).unwrap();

    let memory_queue_state =
        Num::alloc_multiple(cs, Some(memory_queue_state_witness.tail)).unwrap();
    let memory_queue_length =
        UInt32::allocate(cs, Some(memory_queue_state_witness.length)).unwrap();

    let code_decommittment_queue_state =
        Num::alloc_multiple(cs, Some(decommittment_queue_state.tail)).unwrap();
    let code_decommittment_queue_length =
        UInt32::allocate(cs, Some(decommittment_queue_state.length)).unwrap();

    let context_composite_0 =
        UInt64::allocate(cs, Some(initial_state.context_u128_register as u64)).unwrap();
    let context_composite_1 =
        UInt64::allocate(cs, Some((initial_state.context_u128_register >> 64) as u64)).unwrap();

    let mut state = sync_vm::vm::vm_state::VmLocalState {
        previous_code_word,
        registers: regs,
        flags: initial_flags,
        timestamp,
        memory_page_counter,
        tx_number_in_block,
        previous_super_pc,
        did_call_or_ret_recently,
        pending_exception: Boolean::constant(false),
        ergs_per_pubdata_byte,
        callstack: initial_callstack,
        pending_sponges: PendingRoundFunctions::<E, 3>::empty(), // we guarantee that those are empty
        memory_queue_state,
        memory_queue_length,
        code_decommittment_queue_state,
        code_decommittment_queue_length,
        context_composite_u128: [context_composite_0, context_composite_1],
        pending_arithmetic_operations: vec![], // also guaranteed to be empty
    };

    let mut oracle = witness_oracle;
    use sync_vm::vm::vm_cycle::cycle::vm_cycle;

    for _ in cycles_range {
        state = vm_cycle(
            cs,
            state,
            &mut oracle,
            round_function,
            &in_circuit_global_context,
        )
        .unwrap();
    }

    let final_state_no_pending = vm_process_pending(cs, state, round_function).unwrap();

    assert_expected_final_state(
        &final_state_no_pending,
        final_state,
        auxilary_final_parameters,
    );

    final_state_no_pending
}

pub fn assert_expected_final_state<E: Engine>(
    vm_state: &sync_vm::vm::vm_state::VmGlobalState<E, 3>,
    out_of_circuit_state: zk_evm::vm_state::VmLocalState,
    auxilary_final_parameters: VmInCircuitAuxilaryParameters<E>,
) {
    use sync_vm::traits::CSWitnessable;

    let wit = vm_state.create_witness().unwrap();

    for (reg_idx, (circuit, not_circuit)) in wit
        .registers
        .iter()
        .zip(out_of_circuit_state.registers.iter())
        .enumerate()
    {
        compare_reg_values(reg_idx + 1, circuit.inner, not_circuit.value);
    }

    // compare flags
    let flags = wit.flags;
    assert_eq!(
        flags.overflow_or_less_than, out_of_circuit_state.flags.overflow_or_less_than_flag,
        "OF flag divergence"
    );
    assert_eq!(
        flags.equal, out_of_circuit_state.flags.equality_flag,
        "EQ flag divergence"
    );
    assert_eq!(
        flags.greater_than, out_of_circuit_state.flags.greater_than_flag,
        "GT flag divergence"
    );

    // compare callstack top element, state and depth
    let callstack_depth = wit.callstack.context_stack_depth;
    assert_eq!(
        callstack_depth as usize,
        out_of_circuit_state.callstack.depth()
    );

    let callstack_state_encoding = wit.callstack.stack_sponge_state;
    assert_eq!(
        callstack_state_encoding,
        auxilary_final_parameters.callstack_state.0
    );

    // compare individual fields of callstack
    let current_callstack_entry = auxilary_final_parameters.callstack_state.1;
    let current_callstack_vm_witness = wit.callstack.current_context.saved_context.clone();

    // code pages
    assert_eq!(
        current_callstack_entry.base_memory_page.0,
        current_callstack_vm_witness.common_part.base_page
    );
    assert_eq!(
        current_callstack_entry.code_page.0,
        current_callstack_vm_witness.common_part.code_page
    );

    // pc and sp related parts
    assert_eq!(
        current_callstack_entry.pc,
        current_callstack_vm_witness.common_part.pc
    );
    assert_eq!(
        current_callstack_entry.exception_handler_location,
        current_callstack_vm_witness
            .common_part
            .exception_handler_loc
    );
    assert_eq!(
        current_callstack_entry.ergs_remaining,
        current_callstack_vm_witness.common_part.ergs_remaining,
        "invalid remaning ergs"
    );

    // boolean flags of properties
    assert_eq!(
        current_callstack_entry.is_local_frame,
        current_callstack_vm_witness.extension.is_local_call
    );
    assert_eq!(
        current_callstack_entry.is_static,
        current_callstack_vm_witness.common_part.is_static_execution
    );
    assert_eq!(
        current_callstack_entry.is_kernel_mode(),
        current_callstack_vm_witness.common_part.is_kernel_mode
    );

    // addresses
    assert_eq!(
        current_callstack_entry.code_address,
        address_from_u160(current_callstack_vm_witness.common_part.code_address)
    );
    assert_eq!(
        current_callstack_entry.this_address,
        address_from_u160(current_callstack_vm_witness.common_part.this)
    );
    assert_eq!(
        current_callstack_entry.msg_sender,
        address_from_u160(current_callstack_vm_witness.common_part.caller)
    );

    // shards
    assert_eq!(
        current_callstack_entry.code_shard_id,
        current_callstack_vm_witness.common_part.code_shard_id
    );
    assert_eq!(
        current_callstack_entry.this_shard_id,
        current_callstack_vm_witness.common_part.this_shard_id
    );
    assert_eq!(
        current_callstack_entry.caller_shard_id,
        current_callstack_vm_witness.common_part.caller_shard_id
    );

    // context u128
    // assert_eq!(current_callstack_entry.context_u128_value, current_callstack_vm_witness.common_part.caller_shard_id);

    // non-callstack saved part of the state

    // counters
    // assert_eq!(out_of_circuit_state.monotonic_cycle_counter, ); // cycle counter doesn't exist in VM
    assert_eq!(out_of_circuit_state.timestamp, wit.timestamp);
    assert_eq!(
        out_of_circuit_state.memory_page_counter,
        wit.memory_page_counter
    );

    // previous pc, previous code word
    assert_eq!(
        out_of_circuit_state.previous_super_pc,
        wit.previous_super_pc
    );
    assert_eq!(
        out_of_circuit_state.previous_code_word.0,
        wit.previous_code_word
    );

    // jump marker
    assert_eq!(
        out_of_circuit_state.did_call_or_ret_recently,
        wit.did_call_or_ret_recently
    );

    // ergs per pubdata byte
    assert_eq!(
        out_of_circuit_state.current_ergs_per_pubdata_byte,
        wit.ergs_per_pubdata_byte
    );
    // tx number in block
    assert_eq!(
        out_of_circuit_state.tx_number_in_block,
        wit.tx_number_in_block
    );
    // state and depth of the forward storage queue
    assert_eq!(
        auxilary_final_parameters.storage_log_queue_state.tail_state,
        wit.callstack.current_context.log_queue_forward_tail
    );
    assert_eq!(
        auxilary_final_parameters.storage_log_queue_state.num_items,
        wit.callstack.current_context.log_queue_forward_part_length
    );
    // memory queue
    assert_eq!(
        auxilary_final_parameters.memory_queue_state.tail,
        wit.memory_queue_state
    );
    assert_eq!(
        auxilary_final_parameters.memory_queue_state.length,
        wit.memory_queue_length
    );
    // decommittment queue
    assert_eq!(
        auxilary_final_parameters.decommittment_queue_state.tail,
        wit.code_decommittment_queue_state
    );
    assert_eq!(
        auxilary_final_parameters.decommittment_queue_state.length,
        wit.code_decommittment_queue_length
    );
    // reverted part of the log

    assert_eq!(
        auxilary_final_parameters.current_frame_rollback_queue_head,
        current_callstack_vm_witness.common_part.reverted_queue_head
    );
    assert_eq!(
        auxilary_final_parameters.current_frame_rollback_queue_tail,
        current_callstack_vm_witness.common_part.reverted_queue_tail
    );
    assert_eq!(
        auxilary_final_parameters.current_frame_rollback_queue_segment_length,
        current_callstack_vm_witness
            .common_part
            .reverted_queue_segment_len
    );
}

fn compare_reg_values(reg_idx: usize, in_circuit: [u128; 2], out_of_circuit: U256) {
    let l0_a = in_circuit[0] as u64;
    let l1_a = (in_circuit[0] >> 64) as u64;
    let l2_a = in_circuit[1] as u64;
    let l3_a = (in_circuit[1] >> 64) as u64;

    let equal = out_of_circuit.0[0] == l0_a
        && out_of_circuit.0[1] == l1_a
        && out_of_circuit.0[2] == l2_a
        && out_of_circuit.0[3] == l3_a;
    if !equal {
        println!(
            "Limb 0 in circuit = 0x{:016x}, out = 0x{:016x}",
            l0_a, out_of_circuit.0[0]
        );
        println!(
            "Limb 1 in circuit = 0x{:016x}, out = 0x{:016x}",
            l1_a, out_of_circuit.0[1]
        );
        println!(
            "Limb 2 in circuit = 0x{:016x}, out = 0x{:016x}",
            l2_a, out_of_circuit.0[2]
        );
        println!(
            "Limb 3 in circuit = 0x{:016x}, out = 0x{:016x}",
            l3_a, out_of_circuit.0[3]
        );

        panic!("Failed as reg {}:", reg_idx);
    }
}

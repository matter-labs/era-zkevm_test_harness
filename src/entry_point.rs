use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::bellman::SynthesisError;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use sync_vm::project_ref;
use sync_vm::vm::primitives::uint256::UInt256;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
use sync_vm::vm::vm_state::GlobalContext;
use zk_evm::aux_structures::*;
use zk_evm::ethereum_types::*;
use zk_evm::vm_state::CallStackEntry;
use zk_evm::vm_state::VmState;

use super::*;

pub const STARTING_CODE_PAGE: u32 = 1024;
pub const STARTING_CALLDATA_PAGE: u32 = STARTING_CODE_PAGE + 1;
pub const STARTING_BASE_PAGE: u32 = STARTING_CODE_PAGE + 2;

pub const STARTING_MONOTONIC_PAGES_COUNTER: u32 = 2048;

pub const STARTING_TIMESTAMP: u32 = 8;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

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
        base_memory_page: MemoryPage(STARTING_BASE_PAGE),
        code_page: MemoryPage(STARTING_CODE_PAGE),
        calldata_page: MemoryPage(STARTING_CALLDATA_PAGE),
        sp: 0u16,
        pc: initial_pc,
        exception_handler_location: u16::MAX,
        ergs_remaining: initial_ergs,
        this_shard_id: 0,
        caller_shard_id: 0,
        code_shard_id: 0,
        is_static: false,
        is_local_frame: false,
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

    ctx.saved_context.common_part.base_page = UInt32::from_uint(STARTING_BASE_PAGE);
    ctx.saved_context.common_part.calldata_page = UInt32::from_uint(STARTING_CALLDATA_PAGE);
    ctx.saved_context.common_part.code_page = UInt32::from_uint(STARTING_CODE_PAGE);

    ctx.saved_context.common_part.pc = UInt16::from_uint(initial_pc);
    ctx.saved_context.common_part.exception_handler_loc = UInt16::from_uint(u16::MAX);
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
    ctx.saved_context.common_part.calldata_page =
        UInt32::from_uint(out_of_circuit_context.calldata_page.0);
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
    ctx.saved_context.common_part.base_page =
        UInt32::allocate(cs, base_page)?;
    let calldata_page = project_ref!(out_of_circuit_context, calldata_page).map(|el| el.0);
    ctx.saved_context.common_part.calldata_page =
        UInt32::allocate(cs, calldata_page)?;
    let code_page = project_ref!(out_of_circuit_context, code_page).map(|el| el.0);
    ctx.saved_context.common_part.code_page = UInt32::allocate(cs, code_page)?;

    ctx.saved_context.common_part.pc = UInt16::allocate(cs, project_ref!(out_of_circuit_context, pc).cloned())?;
    ctx.saved_context.common_part.exception_handler_loc =
        UInt16::allocate(cs, project_ref!(out_of_circuit_context, exception_handler_location).cloned())?;
    ctx.saved_context.common_part.ergs_remaining =
        UInt32::allocate(cs, project_ref!(out_of_circuit_context, ergs_remaining).cloned())?;

    ctx.saved_context.common_part.code_address =
        UInt160::allocate(cs, project_ref!(out_of_circuit_context, code_address).cloned().map(u160_from_address))?;
    ctx.saved_context.common_part.this =
    UInt160::allocate(cs, project_ref!(out_of_circuit_context, this_address).cloned().map(u160_from_address))?;
    ctx.saved_context.common_part.caller =
        UInt160::allocate(cs, project_ref!(out_of_circuit_context, msg_sender).cloned().map(u160_from_address))?;

    let is_kernel_mode = out_of_circuit_context.map(|el| el.is_kernel_mode());

    ctx.saved_context.common_part.is_kernel_mode =
        Boolean::alloc(cs, is_kernel_mode)?;

    Ok(ctx)
}

use sync_vm::vm::ports::ArithmeticFlagsPort;

pub fn alloc_arithmetic_port<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    flags_witness: Option<zk_evm::flags::Flags>,
) -> Result<ArithmeticFlagsPort<E>, SynthesisError> {
    let overflow_or_less_than = Boolean::alloc(cs, project_ref!(flags_witness, overflow_or_less_than_flag).cloned())?;
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
    block_number: u64,
    block_timestamp: u64,
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
    ergs_per_pubdata_byte_limit_in_block: u32,
    ergs_per_code_decommittment_word: u16,
) -> BlockProperties {
    BlockProperties {
        default_aa_code_hash,
        block_number,
        block_timestamp,
        ergs_per_pubdata_byte_limit_in_block,
        zkporter_is_available,
        ergs_per_code_decommittment_word,
    }
}

pub fn create_in_circuit_global_context<E: Engine>(
    block_number: u64,
    block_timestamp: u64,
    zkporter_is_available: bool,
    default_aa_code_hash: U256,
    ergs_per_pubdata_byte_limit_in_block: u32,
    ergs_per_code_decommittment_word: u16,
) -> GlobalContext<E> {
    GlobalContext {
        block_number: UInt64::from_uint(block_number),
        block_timestamp: UInt64::from_uint(block_timestamp),
        ergs_per_pubdata_byte_in_block: UInt32::from_uint(ergs_per_pubdata_byte_limit_in_block),
        ergs_per_code_decommittment_word: UInt16::from_uint(ergs_per_code_decommittment_word),
        zkporter_is_available: Boolean::constant(zkporter_is_available),
        default_aa_code_hash: UInt256::constant_from_biguint(u256_to_biguint(default_aa_code_hash)),
    }
}

use crate::witness::oracle::VmInCircuitAuxilaryParameters;
use crate::witness::oracle::VmInstanceWitness;
use crate::witness::oracle::VmWitnessOracle;
use crate::witness::tracer::WitnessTracer;
use zk_evm::precompiles::DefaultPrecompilesProcessor;
use zk_evm::testing::decommitter::SimpleDecommitter;
use zk_evm::testing::event_sink::InMemoryEventSink;
use zk_evm::testing::memory::SimpleMemory;
use zk_evm::testing::storage::InMemoryStorage;

pub struct Tools<const B: bool> {
    pub storage: InMemoryStorage,
    pub memory: SimpleMemory,
    pub event_sink: InMemoryEventSink,
    pub precompiles_processor: DefaultPrecompilesProcessor<B>,
    pub decommittment_processor: SimpleDecommitter<B>,
    pub witness_tracer: WitnessTracer,
}

pub fn create_default_testing_tools() -> Tools<true> {
    let storage = InMemoryStorage::new();
    let memory = SimpleMemory::new();
    let event_sink = InMemoryEventSink::new();
    let precompiles_processor = DefaultPrecompilesProcessor::<true>;
    let decommittment_processor = SimpleDecommitter::<true>::new();
    let witness_tracer = WitnessTracer::new(10);

    Tools::<true> {
        storage,
        memory,
        event_sink,
        precompiles_processor,
        decommittment_processor,
        witness_tracer,
    }
}

/// We expect that storage/memory/decommitter were prefilled
pub fn create_out_of_circuit_vm<'a, const B: bool>(
    tools: &'a mut Tools<B>,
    block_properties: &'a BlockProperties,
    caller_address: Address,
    entry_point_address: Address,
) -> VmState<
    'a,
    InMemoryStorage,
    SimpleMemory,
    InMemoryEventSink,
    DefaultPrecompilesProcessor<B>,
    SimpleDecommitter<B>,
    WitnessTracer,
> {
    let mut vm = VmState::empty_state(
        &mut tools.storage,
        &mut tools.memory,
        &mut tools.event_sink,
        &mut tools.precompiles_processor,
        &mut tools.decommittment_processor,
        &mut tools.witness_tracer,
        block_properties,
    );

    let initial_context = initial_out_of_circuit_context(
        0,
        u32::MAX,
        entry_point_address,
        caller_address,
        entry_point_address,
    );

    vm.push_bootloader_context(0, initial_context);

    vm.local_state.current_ergs_per_pubdata_byte = 0; // uninitialized yet, but we do not care
    vm.local_state.timestamp = STARTING_TIMESTAMP;
    vm.local_state.memory_page_counter = STARTING_MONOTONIC_PAGES_COUNTER;
    vm.local_state.monotonic_cycle_counter = INITIAL_MONOTONIC_CYCLE_COUNTER;

    vm
}

pub fn create_in_circuit_vm<
    E: Engine,
    CS: ConstraintSystem<E>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    _round_function: &R,
    initial_rollback_queue_value: E::Fr,
    initial_callstack_state_for_start: ([E::Fr; 3], CallStackEntry),
    initial_context_for_start: CallStackEntry,
) -> sync_vm::vm::vm_state::VmLocalState<E, 3> {
    // we need to prepare some global state and push initial context
    // use sync_vm::vm::vm_cycle::register_view::Register;
    use sync_vm::vm::ports::ArithmeticFlagsPort;
    use sync_vm::vm::primitives::register_view::Register;
    use sync_vm::vm::vm_state::callstack::Callstack;
    use sync_vm::vm::vm_state::PendingRoundFunctions;

    let bool_false = Boolean::alloc(cs, Some(false)).unwrap();

    let mut initial_callstack = Callstack::<E, 3>::empty();
    let (initial_callstack_sponge_state, _empty_context) = initial_callstack_state_for_start;

    let initial_callstack_sponge =
        Num::alloc_multiple(cs, Some(initial_callstack_sponge_state)).unwrap();
    initial_callstack.stack_sponge_state = initial_callstack_sponge;
    initial_callstack.context_stack_depth = UInt16::from_uint(1);

    let initial_context = out_to_in_circuit_context_on_call(
        cs,
        initial_context_for_start,
        initial_rollback_queue_value,
    );
    initial_callstack.current_context = initial_context;

    let initial_flags = ArithmeticFlagsPort::<E> {
        overflow_or_less_than: bool_false,
        equal: bool_false,
        greater_than: bool_false,
        _marker: std::marker::PhantomData,
    };

    let zero_u128 = UInt128::allocate(cs, Some(0)).unwrap();
    let empty_reg = Register {
        inner: [zero_u128; 2],
    };

    let state = sync_vm::vm::vm_state::VmLocalState {
        previous_code_word: [UInt64::<E>::zero(); 4],
        registers: [empty_reg; zk_evm::zkevm_opcode_defs::REGISTERS_COUNT],
        flags: initial_flags,
        timestamp: UInt32::<E>::from_uint(STARTING_TIMESTAMP),
        memory_page_counter: UInt32::<E>::from_uint(STARTING_MONOTONIC_PAGES_COUNTER),
        tx_number_in_block: UInt16::<E>::zero(),
        previous_super_pc: UInt16::<E>::zero(),
        did_call_or_ret_recently: Boolean::constant(true),
        tx_origin: UInt160::<E>::zero(),
        ergs_per_pubdata_byte: UInt32::<E>::zero(),
        callstack: initial_callstack,
        pending_sponges: PendingRoundFunctions::<E, 3>::empty(),
        memory_queue_state: [Num::<E>::zero(); 3],
        memory_queue_length: UInt32::<E>::zero(),
        code_decommittment_queue_state: [Num::<E>::zero(); 3],
        code_decommittment_queue_length: UInt32::<E>::zero(),
        pending_arithmetic_operations: vec![],
    };

    state
}

pub fn run_vm_instance<
    E: Engine,
    CS: ConstraintSystem<E>,
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>,
>(
    cs: &mut CS,
    round_function: &R,
    in_circuit_global_context: &GlobalContext<E>,
    snapshot_data: VmInstanceWitness<E, VmWitnessOracle<E>>,
) -> sync_vm::vm::vm_state::VmLocalState<E, 3> {
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
        auxilary_final_parameters 
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
    initial_callstack.current_context.returndata_page = UInt32::allocate(cs, Some(initial_state.callstack.returndata_page.0)).unwrap();
    initial_callstack.current_context.log_queue_forward_tail = Num::alloc(cs, Some(storage_log_queue_state.tail_state)).unwrap();
    initial_callstack.current_context.log_queue_forward_part_length = UInt32::allocate(cs, Some(storage_log_queue_state.num_items)).unwrap();

    let initial_callstack_sponge =
        Num::alloc_multiple(cs, Some(initial_callstack_sponge_state)).unwrap();
    initial_callstack.stack_sponge_state = initial_callstack_sponge;
    initial_callstack.context_stack_depth = UInt16::allocate(cs, Some(initial_state.callstack.depth() as u16)).unwrap();

    let mut initial_context = alloc_execution_context(
        cs,
        Some(initial_context_for_start),
    ).unwrap();
    // set rollback queue properties
    initial_context.saved_context.common_part.reverted_queue_head = Num::alloc(cs, Some(current_frame_rollback_queue_head)).unwrap();
    initial_context.saved_context.common_part.reverted_queue_tail = Num::alloc(cs, Some(current_frame_rollback_queue_tail)).unwrap();
    initial_context.saved_context.common_part.reverted_queue_segment_len = UInt32::allocate(cs, Some(current_frame_rollback_queue_segment_length)).unwrap();

    initial_callstack.current_context = initial_context;

    let initial_flags = alloc_arithmetic_port(cs, Some(initial_state.flags)).unwrap();

    let mut regs = [Register::<E>::zero(); zk_evm::zkevm_opcode_defs::REGISTERS_COUNT];
    for (dst, src) in regs.iter_mut().zip(initial_state.registers.iter()) {
        let low = (src.0[0] as u128) | (src.0[1] as u128);
        let high = (src.0[2] as u128) | (src.0[3] as u128);

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
    let memory_page_counter = UInt32::allocate(cs, Some(initial_state.memory_page_counter)).unwrap();
    let tx_number_in_block = UInt16::allocate(cs, Some(initial_state.tx_number_in_block)).unwrap();
    let previous_super_pc = UInt16::allocate(cs, Some(initial_state.previous_super_pc)).unwrap();
    let did_call_or_ret_recently = Boolean::alloc(cs, Some(initial_state.did_call_or_ret_recently)).unwrap();
    let tx_origin = UInt160::allocate(cs, Some(u160_from_address(initial_state.tx_origin))).unwrap();
    let ergs_per_pubdata_byte = UInt32::allocate(cs, Some(initial_state.current_ergs_per_pubdata_byte)).unwrap();

    let memory_queue_state =
        Num::alloc_multiple(cs, Some(memory_queue_state_witness.tail)).unwrap();
    let memory_queue_length = UInt32::allocate(cs, Some(memory_queue_state_witness.length)).unwrap();

    let code_decommittment_queue_state =
    Num::alloc_multiple(cs, Some(decommittment_queue_state.tail)).unwrap();
    let code_decommittment_queue_length = UInt32::allocate(cs, Some(decommittment_queue_state.length)).unwrap();

    let mut state = sync_vm::vm::vm_state::VmLocalState {
        previous_code_word,
        registers: regs,
        flags: initial_flags,
        timestamp,
        memory_page_counter,
        tx_number_in_block,
        previous_super_pc,
        did_call_or_ret_recently,
        tx_origin,
        ergs_per_pubdata_byte,
        callstack: initial_callstack,
        pending_sponges: PendingRoundFunctions::<E, 3>::empty(), // we guarantee that those are empty
        memory_queue_state,
        memory_queue_length,
        code_decommittment_queue_state,
        code_decommittment_queue_length,
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

    state
}

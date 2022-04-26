use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use sync_vm::vm::vm_cycle::witness_oracle::u256_to_biguint;
use sync_vm::vm::vm_state::GlobalContext;
use zk_evm::ethereum_types::*;
use zk_evm::aux_structures::*;
use zk_evm::vm_state::CallStackEntry;
use sync_vm::vm::primitives::uint256::UInt256;
use zk_evm::vm_state::VmState;
use zk_evm::precompiles::BOOTLOADER_FORMAL_ADDRESS;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;

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
use sync_vm::vm::vm_state::execution_context::FullExecutionContext;
use sync_vm::vm::primitives::*;

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

    ctx.saved_context.common_part.code_address = UInt160::from_uint(u160_from_address(code_address));
    ctx.saved_context.common_part.this = UInt160::from_uint(u160_from_address(this_address));
    ctx.saved_context.common_part.caller = UInt160::from_uint(u160_from_address(msg_sender));

    // circuit specific bit
    ctx.saved_context.common_part.reverted_queue_tail = Num::Constant(initial_rollback_queue_value);
    ctx.saved_context.common_part.reverted_queue_head = ctx.saved_context.common_part.reverted_queue_tail;

    ctx
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
        ergs_per_code_decommittment_word
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

use zk_evm::testing::event_sink::InMemoryEventSink;
use zk_evm::testing::storage::InMemoryStorage;
use zk_evm::testing::memory::SimpleMemory;
use zk_evm::precompiles::DefaultPrecompilesProcessor;
use zk_evm::testing::decommitter::SimpleDecommitter;
use crate::witness::tracer::WitnessTracer;

pub struct Tools<const B: bool>{
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
    let witness_tracer = WitnessTracer::new();

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


    let bootloader_address = *BOOTLOADER_FORMAL_ADDRESS;

    let initial_context = initial_out_of_circuit_context(
        0,
        u32::MAX,
        bootloader_address,
        bootloader_address,
        bootloader_address
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
    R: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>
>(
    cs: &mut CS,
    round_function: &R,
    initial_rollback_queue_value: E::Fr,
) -> sync_vm::vm::vm_state::VmLocalState<E, 3> {
    // we need to prepare some global state and push initial context
    // use sync_vm::vm::vm_cycle::register_view::Register;
    use sync_vm::vm::primitives::register_view::Register;
    use sync_vm::vm::ports::ArithmeticFlagsPort;
    use sync_vm::vm::vm_state::callstack::Callstack;
    use sync_vm::vm::vm_state::PendingRoundFunctions;

    let bool_false = Boolean::alloc(cs, Some(false)).unwrap();
    let bool_true = Boolean::alloc(cs, Some(true)).unwrap();

    let mut initial_callstack = Callstack::<E, 3>::empty();
    let mut initial_context = initial_callstack.current_context.saved_context.clone();
    // set the head-tail, and segment length is 0
    initial_context.common_part.reverted_queue_head = Num::Constant(initial_rollback_queue_value);
    initial_context.common_part.reverted_queue_tail = Num::Constant(initial_rollback_queue_value);
    // and we start/end in kernel mode
    initial_context.common_part.is_kernel_mode = Boolean::constant(true);

    dbg!(Num::get_value_multiple(&initial_callstack.stack_sponge_state));
    // simulate push

    let bootloader_address = *BOOTLOADER_FORMAL_ADDRESS;
    let mut new_context = initial_in_circuit_context(
        0,
        u32::MAX,
        bootloader_address,
        bootloader_address,
        bootloader_address,
        initial_rollback_queue_value,
    );
    initial_callstack.context_stack_depth = UInt16::from_uint(1);
    new_context.saved_context.common_part.is_kernel_mode = bool_true; // formal address of the bootloader implies kernel

    // push the initial (empty) context
    use sync_vm::traits::CircuitFixedLengthEncodable;
    let encoding = initial_context.encode(cs).unwrap();
    dbg!(Num::get_value_multiple(&encoding));
    let state = round_function.round_function_absorb_nums_multiple_rounds(
        cs,
        initial_callstack.stack_sponge_state,
        &encoding
    ).unwrap();
    initial_callstack.stack_sponge_state = state;
    initial_callstack.current_context = new_context;
    dbg!(Num::get_value_multiple(&initial_callstack.stack_sponge_state));

    let initial_flags = ArithmeticFlagsPort::<E> {
        overflow_or_less_than: bool_false,
        equal: bool_false,
        greater_than: bool_false,
        _marker: std::marker::PhantomData
    };
    
    let zero_u128 = UInt128::allocate(cs, Some(0)).unwrap();
    let empty_reg = Register {inner: [zero_u128; 2]};

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
    };

    state
}
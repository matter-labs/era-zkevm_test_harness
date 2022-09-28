use zk_evm::reference_impls::event_sink::InMemoryEventSink;
use zk_evm::precompiles::DefaultPrecompilesProcessor;
use zk_evm::reference_impls::decommitter::SimpleDecommitter;
use crate::witness::tracer::WitnessTracer;
use zk_evm::abstractions::Storage;

/// Set should only differ due to another storage that would be sustituted from outside,
/// and all other tools can be as simple as possible
pub struct ProvingToolset<S: Storage> {
    pub storage: S,
    pub memory: SimpleMemory,
    pub event_sink: InMemoryEventSink,
    pub precompiles_processor: DefaultPrecompilesProcessor<true>,
    pub decommittment_processor: SimpleDecommitter<true>,
    pub witness_tracer: WitnessTracer,
    pub config: GeometryConfig,
}

use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone, Debug, Default)]
pub struct GeometryConfig {
    pub cycles_per_vm_snapshot: u32,
    pub limit_for_code_decommitter_sorter: u32,
    pub limit_for_log_demuxer: u32,
    pub limit_for_storage_sorter: u32,
    pub limit_for_events_or_l1_messages_sorter: u32,
    pub limit_for_l1_messages_merklizer: u32,
    pub cycles_per_ram_permutation: u32,
    pub cycles_per_code_decommitter: u32,
    pub cycles_per_storage_application: u32,
    pub limit_for_initial_writes_pubdata_hasher: u32,
    pub limit_for_repeated_writes_pubdata_hasher: u32,
    pub cycles_per_keccak256_circuit: u32,
    pub cycles_per_sha256_circuit: u32,
    pub cycles_per_ecrecover_circuit: u32,
}

pub fn create_tools<S: Storage>(storage: S, config: &GeometryConfig) -> ProvingToolset<S> {
    let memory = SimpleMemory::new_without_preallocations();
    let event_sink = InMemoryEventSink::new();
    let precompiles_processor = DefaultPrecompilesProcessor::<true>;
    let decommittment_processor = SimpleDecommitter::<true>::new();
    let witness_tracer = WitnessTracer::new(config.cycles_per_vm_snapshot);

    ProvingToolset {
        storage,
        memory,
        event_sink,
        precompiles_processor,
        decommittment_processor,
        witness_tracer,
        config: config.clone()
    }
}

use crate::ethereum_types::Address;
use zk_evm::block_properties::BlockProperties;
use zk_evm::vm_state::{VmState, PrimitiveValue};
use crate::entry_point::initial_out_of_circuit_context;
use zk_evm::zkevm_opcode_defs::*;
use zk_evm::reference_impls::memory::SimpleMemory;

/// We expect that storage/memory/decommitter were prefilled
pub fn create_out_of_circuit_vm<'a, S: Storage>(
    tools: &'a mut ProvingToolset<S>,
    block_properties: &'a BlockProperties,
    caller_address: Address,
    entry_point_address: Address,
) -> VmState<
    'a,
    S,
    SimpleMemory,
    InMemoryEventSink,
    DefaultPrecompilesProcessor<true>,
    SimpleDecommitter<true>,
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

    vm.push_bootloader_context(crate::INITIAL_MONOTONIC_CYCLE_COUNTER-1, initial_context);

    vm.local_state.current_ergs_per_pubdata_byte = 0; // uninitialized yet, but we do not care
    vm.local_state.timestamp = STARTING_TIMESTAMP;
    vm.local_state.memory_page_counter = STARTING_BASE_PAGE;
    vm.local_state.monotonic_cycle_counter = crate::INITIAL_MONOTONIC_CYCLE_COUNTER;

    // we also FORMALLY mark r1 as "pointer" type, even though we will NOT have any calldata
    let formal_ptr = FatPointer {
        offset: 0,
        memory_page: zk_evm::zkevm_opcode_defs::BOOTLOADER_CALLDATA_PAGE,
        start: 0,
        length: 0
    };
    let formal_ptr_encoding = formal_ptr.to_u256();
    vm.local_state.registers[0] = PrimitiveValue {
        value: formal_ptr_encoding,
        is_pointer: true,
    };

    vm
}
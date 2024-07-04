use circuit_definitions::Field;

// TODO add tests after cleanup

use core::slice::Iter;
use crate::witness::vm_snapshot::VmSnapshot;
use crate::boojum::gadgets::queue::QueueState;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;

use crate::boojum::gadgets::queue::QueueStateWitness;
use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::witness::utils::transform_sponge_like_queue_state;
use crate::zk_evm::aux_structures::MemoryQuery;
use crate::witness::aux_data_structs::MemoryQueueState;

/// TODO docs
pub struct MemoryQueueWitnessesForVmCircuitBuilder<'a> {
    inner: Vec<QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    vm_snapshots: &'a Vec<VmSnapshot>,
    vm_memory_queries_accumulated_it: Iter<'a, (u32, MemoryQuery)>,
    current_snapshot: usize,
    current_snapshot_start_cycle: u32,
    last_witness: QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>
}

// TODO refactor
impl<'a> MemoryQueueWitnessesForVmCircuitBuilder<'a> {
    pub fn new(
        vm_snapshots: &'a Vec<VmSnapshot>,
        vm_memory_queries_accumulated: &'a Vec<(u32, MemoryQuery)>,
) -> Self {
        assert!(!vm_snapshots.is_empty());
        
        Self {
            inner: Vec::with_capacity(vm_snapshots.windows(2).len() + 1),
            vm_snapshots,
            vm_memory_queries_accumulated_it: vm_memory_queries_accumulated.iter(),
            current_snapshot: 0,
            current_snapshot_start_cycle: vm_snapshots[0].at_cycle,
            last_witness: QueueState::placeholder_witness()
        }
    }

    pub fn into_circuits(mut self) -> Vec<QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>> {
        let amount_of_circuits = self.vm_snapshots.windows(2).len();

        while self.inner.len() < amount_of_circuits {
            self.inner.push(self.last_witness.clone());          
        }

        // special for last vm snapshot
        self.inner.push(self.last_witness);

        assert_eq!(self.inner.len(), self.vm_snapshots.windows(2).len() + 1);

        self.inner
    }

    pub fn push(&mut self, state: MemoryQueueState<Field>) {
        let (cycle, _) = self.vm_memory_queries_accumulated_it.next().unwrap();

        while *cycle >= self.current_snapshot_start_cycle {
            self.current_snapshot += 1;
            self.current_snapshot_start_cycle = self.vm_snapshots[self.current_snapshot].at_cycle;

            self.inner.push(self.last_witness.clone());
        }

        self.last_witness = transform_sponge_like_queue_state(state);
    }
}
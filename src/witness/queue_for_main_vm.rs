use circuit_definitions::Field;
use circuit_sequencer_api::INITIAL_MONOTONIC_CYCLE_COUNTER;

use crate::witness::advancing_range::TupleFirst;

/// Used to store queries that will be used for the main VM witness generation.
/// This data structure internally sorts queries by main VM circuit instances.
#[derive(Clone, Debug)]
pub struct QueueForMainVm<T: TupleFirst> {
    cycles_per_vm_snapshot: usize,
    inner: Vec<Vec<T>>
}

impl<T: TupleFirst> QueueForMainVm<T> {
    pub fn new(cycles_per_vm_snapshot: usize) -> Self {
        Self {
            cycles_per_vm_snapshot,
            inner: Default::default()
        }
    }

    pub fn last(&self) -> Option<&T> {
        let last_batch = self.inner.last();
        if last_batch.is_none() {
            return None;
        }

        last_batch.unwrap().last()
    }

    pub fn from_iter<I: IntoIterator<Item = T>>(cycles_per_vm_snapshot: usize, iterator: I) -> Self {
       let mut _self = Self {
            cycles_per_vm_snapshot,
            inner: Default::default()
        };

        let mut iterator = iterator.into_iter();

        while let Some(element) = iterator.next() {
            _self.push(element);
        }

        _self
    }

    /// Will ignore queries before INITIAL_MONOTONIC_CYCLE_COUNTER
    pub fn push(&mut self, val: T) {
        let cycle = val.first() as usize;

        // we should not have any snapshots before INITIAL_MONOTONIC_CYCLE_COUNTER
        if cycle < INITIAL_MONOTONIC_CYCLE_COUNTER as usize {
            return;
        }

        let batch_index = (cycle - INITIAL_MONOTONIC_CYCLE_COUNTER as usize) / self.cycles_per_vm_snapshot;

        while self.inner.len() <= batch_index {
            self.seal_last_batch();
            self.push_new_batch();
        }

        let batch = &mut self.inner[batch_index];
        batch.push(val);
    }

    pub fn into_batches(mut self, amount_of_circuits: usize) -> Vec<Vec<T>> {
        while self.inner.len() < amount_of_circuits {
            self.seal_last_batch();
            self.push_new_batch();
        }

        self.inner
    }

    pub fn get_batch(&self, batch_index: usize) -> Option<&Vec<T>> {
        self.inner.get(batch_index)
    }

    pub fn get_batch_mut(&mut self, batch_index: usize) -> Option<&mut Vec<T>> {
        if batch_index >= self.inner.len() {
            return None;
        }

        let batch = &mut self.inner[batch_index];
        Some(batch)
    }

    pub fn iter(&self) -> SplittedQueueIterator<T> {
        SplittedQueueIterator {
            queue: self,
            batch_index: 0,
            inner_index: 0
        }
    }

    fn push_new_batch(&mut self) {
        self.inner.push(Vec::with_capacity(self.cycles_per_vm_snapshot / 2));
    }

    fn seal_last_batch(&mut self) {
        let len = self.inner.len();
        if len == 0 {
            return;
        }

        self.inner[len - 1].shrink_to_fit();
    }
}

impl<T: TupleFirst> IntoIterator for QueueForMainVm<T> {
    type Item = T;
    type IntoIter = SplittedQueueIntoIter<T>;

    fn into_iter(self) -> SplittedQueueIntoIter<T> {
        SplittedQueueIntoIter { 
            queue: self,
            batch_index: 0
         }
    }
}

impl<T: TupleFirst> Extend<T> for QueueForMainVm<T> {
    #[inline]
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let mut iterator = iter.into_iter();

        while let Some(element) = iterator.next() {
            self.push(element);
        }
    }
}

pub struct SplittedQueueIterator<'a, T: TupleFirst> {
    queue: &'a QueueForMainVm<T>,
    batch_index: usize,
    inner_index: usize,
}

impl<'a, T: TupleFirst> Iterator for SplittedQueueIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = self.queue.get_batch(self.batch_index);
        if batch.is_none() {
            return None;
        }

        if self.inner_index >= batch.unwrap().len(){
            self.batch_index += 1;
            self.inner_index = 0;
            batch = self.queue.get_batch(self.batch_index);
            if batch.is_none() {
                return None;
            }
        }
        
        batch.unwrap().get(self.inner_index)
    }
}

pub struct SplittedQueueIntoIter<T: TupleFirst> {
    queue: QueueForMainVm<T>,
    batch_index: usize
}

impl<T: TupleFirst> Iterator for SplittedQueueIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO can be optimized
        let batch = self.queue.get_batch_mut(self.batch_index);
        if batch.is_none() {
            return None;
        }

        let mut batch = batch.unwrap();

        if batch.is_empty(){
            self.batch_index += 1;
            let next_batch = self.queue.get_batch_mut(self.batch_index);
            if next_batch.is_none() {
                return None;
            }
            batch = next_batch.unwrap();
        }

        let batch: &mut Vec<T> = batch;
        if batch.is_empty() {
            return None;
        }

        let result = batch.remove(0);
        Some(result)
    }
}

/// TODO docs
pub struct QueueStatesForCircuit<T> {
    cycles_per_circuit: usize,
    inner: Vec<T>,
    len: usize,
}

impl<T> QueueStatesForCircuit<T> {
    pub fn new(cycles_per_circuit: usize) -> Self {
        Self {
            cycles_per_circuit,
            inner: Default::default(),
            len: 0
        }
    }

    // TODO with_exact_capacity
    pub fn with_flat_capacity(cycles_per_circuit: usize, capacity: usize) -> Self {
        let num_circuits = (capacity + cycles_per_circuit - 1)
        / cycles_per_circuit;

        let mut _self = Self::new(cycles_per_circuit);
        _self.inner.reserve_exact(num_circuits);
        _self
    }

    pub fn reserve_exact_flat(&mut self, additional: usize) {
        let num_circuits = (self.len + additional + self.cycles_per_circuit - 1)
        / self.cycles_per_circuit;

        self.inner.reserve_exact(num_circuits - self.inner.capacity());
    }

    pub fn into_circuits(self) -> Vec<T> {
        self.inner
    }

    pub fn last(&self) -> Option<&T> {
        self.inner.last()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, val: T) {
        let circuit_id = self.len / self.cycles_per_circuit;
        if self.inner.len() <= circuit_id {
            self.inner.push(val);
        } else {
            self.inner[circuit_id] = val;
        }

        self.len += 1;
    }
}

use core::slice::Iter;
use crate::witness::vm_snapshot::VmSnapshot;
use crate::boojum::gadgets::queue::QueueState;
use circuit_definitions::boojum::gadgets::traits::allocatable::CSAllocatable;
use circuit_definitions::encodings::memory_query::MemoryQueueState;
use crate::boojum::gadgets::queue::QueueStateWitness;
use crate::zkevm_circuits::base_structures::vm_state::FULL_SPONGE_QUEUE_STATE_WIDTH;
use crate::witness::utils::transform_sponge_like_queue_state;
use crate::zk_evm::aux_structures::MemoryQuery;

/// TODO docs
pub struct MemoryQueueWitnessesForVmCircuitBuilder<'a> {
    inner: Vec<QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>>,
    vm_snapshots: &'a Vec<VmSnapshot>,
    vm_memory_queries_accumulated_it: Iter<'a, (u32, MemoryQuery)>,
    current_snapshot: usize,
    current_snapshot_start_cycle: u32,
    last: Option<MemoryQueueState<Field>>
}

impl<'a> MemoryQueueWitnessesForVmCircuitBuilder<'a> {
    pub fn new(
        vm_snapshots: &'a Vec<VmSnapshot>,
        vm_memory_queries_accumulated: &'a Vec<(u32, MemoryQuery)>,
) -> Self {
        Self {
            inner: Vec::with_capacity(vm_snapshots.windows(2).len() + 1),
            vm_snapshots,
            vm_memory_queries_accumulated_it: vm_memory_queries_accumulated.iter(),
            current_snapshot: 0,
            current_snapshot_start_cycle: 0,
            last: None
        }
    }

    pub fn into_circuits(mut self) -> Vec<QueueStateWitness<Field, FULL_SPONGE_QUEUE_STATE_WIDTH>> {
        // special for last vm snapshot
        if let Some(last_state) = self.last  {
            self.inner.push(
                transform_sponge_like_queue_state(last_state)
            );
        } else {
            self.inner.push(QueueState::placeholder_witness());
        }
        assert!(self.inner.len() == self.vm_snapshots.windows(2).len() + 1);

        self.inner
    }

    pub fn push(&mut self, state: MemoryQueueState<Field>) {
        let (cycle, _) = self.vm_memory_queries_accumulated_it.next().unwrap();
        if *cycle >= self.current_snapshot_start_cycle {
            self.current_snapshot += 1;
            self.current_snapshot_start_cycle = self.vm_snapshots[self.current_snapshot].at_cycle;

            if let Some(last_state) = self.last {
                self.inner.push(
                    transform_sponge_like_queue_state(last_state)
                );
            } else {
                self.inner.push(QueueState::placeholder_witness());
            }
        }

        self.last = Some(state);
    }
}
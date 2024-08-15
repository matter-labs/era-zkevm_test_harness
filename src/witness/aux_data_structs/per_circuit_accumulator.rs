use crate::witness::aux_data_structs::TupleFirst;
use circuit_sequencer_api::INITIAL_MONOTONIC_CYCLE_COUNTER;

#[derive(Clone, Debug)]
struct PerCircuitAccumulatorContainer<T> {
    cycles_per_circuit: usize,
    circuits_data: Vec<Vec<T>>,
    accumulated: usize,
}

impl<T> PerCircuitAccumulatorContainer<T> {
    pub fn new(cycles_per_circuit: usize) -> Self {
        Self {
            cycles_per_circuit,
            circuits_data: Default::default(),
            accumulated: 0,
        }
    }

    pub fn with_flat_capacity(cycles_per_circuit: usize, flat_capacity: usize) -> Self {
        assert!(cycles_per_circuit != 0);

        let num_circuits = (flat_capacity + cycles_per_circuit - 1) / cycles_per_circuit;

        // TODO reserve in sub-vectors
        let mut _self = Self::new(cycles_per_circuit);
        _self.circuits_data.reserve_exact(num_circuits);
        _self
    }

    pub fn len(&self) -> usize {
        self.accumulated
    }

    pub fn amount_of_circuits_accumulated(&self) -> usize {
        self.circuits_data.len()
    }

    pub fn last(&self) -> Option<&T> {
        let last_batch = self.circuits_data.last();
        last_batch?;

        last_batch.unwrap().last()
    }

    pub fn push_for_circuit(&mut self, circuit_index: usize, val: T) {
        while self.circuits_data.len() <= circuit_index {
            self.seal_last_batch();
            self.push_new_batch();
        }

        self.circuits_data[circuit_index].push(val);
        self.accumulated += 1;
    }

    pub fn into_circuits(mut self, amount_of_circuits: usize) -> Vec<Vec<T>> {
        while self.circuits_data.len() < amount_of_circuits {
            self.seal_last_batch();
            self.push_new_batch();
        }

        self.seal_last_batch();
        self.circuits_data
    }

    pub fn get_batch(&self, batch_index: usize) -> Option<&Vec<T>> {
        self.circuits_data.get(batch_index)
    }

    pub fn get_batch_mut(&mut self, batch_index: usize) -> Option<&mut Vec<T>> {
        if batch_index >= self.circuits_data.len() {
            return None;
        }

        let batch = &mut self.circuits_data[batch_index];
        Some(batch)
    }

    fn push_new_batch(&mut self) {
        self.circuits_data
            .push(Vec::with_capacity(self.cycles_per_circuit));
    }

    fn seal_last_batch(&mut self) {
        let len = self.circuits_data.len();
        if len == 0 {
            return;
        }

        self.circuits_data[len - 1].shrink_to_fit();
    }

    pub fn iter(&self) -> PerCircuitAccumulatorIterator<T> {
        PerCircuitAccumulatorIterator {
            container: self,
            batch_index: 0,
            inner_index: 0,
        }
    }

    pub fn into_iter(self) -> PerCircuitAccumulatorIntoIter<T> {
        PerCircuitAccumulatorIntoIter {
            container: self,
            batch_index: 0,
        }
    }
}

pub struct PerCircuitAccumulatorIterator<'a, T> {
    container: &'a PerCircuitAccumulatorContainer<T>,
    batch_index: usize,
    inner_index: usize,
}

impl<'a, T> Iterator for PerCircuitAccumulatorIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let mut batch = self.container.get_batch(self.batch_index);
        batch?;

        if self.inner_index >= batch.unwrap().len() {
            self.batch_index += 1;
            self.inner_index = 0;
            batch = self.container.get_batch(self.batch_index);
            batch?;
        }

        let res = batch.unwrap().get(self.inner_index);
        self.inner_index += 1;

        res
    }
}

pub struct PerCircuitAccumulatorIntoIter<T> {
    container: PerCircuitAccumulatorContainer<T>,
    batch_index: usize,
}

impl<T: TupleFirst> Iterator for PerCircuitAccumulatorIntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO can be optimized
        let batch = self.container.get_batch_mut(self.batch_index);
        batch.as_ref()?;

        let mut batch = batch.unwrap();

        if batch.is_empty() {
            self.batch_index += 1;
            let next_batch = self.container.get_batch_mut(self.batch_index);
            next_batch.as_ref()?;
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

/// Accumulates values ​for each circuit
/// The contents of the accumulator can be easily divided into circuits
pub struct PerCircuitAccumulator<T> {
    container: PerCircuitAccumulatorContainer<T>,
}

impl<T> PerCircuitAccumulator<T> {
    pub fn with_flat_capacity(cycles_per_circuit: usize, flat_capacity: usize) -> Self {
        Self {
            container: PerCircuitAccumulatorContainer::with_flat_capacity(
                cycles_per_circuit,
                flat_capacity,
            ),
        }
    }

    pub fn len(&self) -> usize {
        self.container.len()
    }

    pub fn amount_of_circuits_accumulated(&self) -> usize {
        self.container.amount_of_circuits_accumulated()
    }

    pub fn push(&mut self, val: T) {
        assert!(self.container.cycles_per_circuit != 0);
        let idx = self.container.len();

        let circuit_index = idx / self.container.cycles_per_circuit;
        self.container.push_for_circuit(circuit_index, val);
    }

    pub fn into_circuits(self, amount_of_circuits: usize) -> Vec<Vec<T>> {
        self.container.into_circuits(amount_of_circuits)
    }

    pub fn iter(&self) -> PerCircuitAccumulatorIterator<T> {
        self.container.iter()
    }
}

use circuit_definitions::encodings::ContainerForSimulator;
impl<T> ContainerForSimulator<T> for PerCircuitAccumulator<T> {
    fn push(&mut self, val: T) {
        self.push(val);
    }
}

/// Accumulates values ​for each circuit
/// The contents of the accumulator can be easily divided into circuits
/// Uses sparse input - values arrives unevenly
#[derive(Clone, Debug)]
pub struct PerCircuitAccumulatorSparse<T: TupleFirst> {
    container: PerCircuitAccumulatorContainer<T>,
}

impl<T: TupleFirst> PerCircuitAccumulatorSparse<T> {
    pub fn new(cycles_per_circuit: usize) -> Self {
        Self {
            container: PerCircuitAccumulatorContainer::new(cycles_per_circuit),
        }
    }

    pub fn from_iter<I: IntoIterator<Item = T>>(cycles_per_circuit: usize, iterator: I) -> Self {
        let mut _self = Self::new(cycles_per_circuit);

        let iterator = iterator.into_iter();

        for element in iterator {
            _self.push(element);
        }

        _self
    }

    pub fn last(&self) -> Option<&T> {
        self.container.last()
    }

    pub fn into_circuits(self, amount_of_circuits: usize) -> Vec<Vec<T>> {
        self.container.into_circuits(amount_of_circuits)
    }

    /// Will ignore queries before INITIAL_MONOTONIC_CYCLE_COUNTER
    pub fn push(&mut self, val: T) {
        let cycle = val.first() as usize;

        // we should not have any snapshots before INITIAL_MONOTONIC_CYCLE_COUNTER
        if cycle < INITIAL_MONOTONIC_CYCLE_COUNTER as usize {
            // TODO replace with initial snapshot cycle?
            return;
        }

        let circuit_index =
            (cycle - INITIAL_MONOTONIC_CYCLE_COUNTER as usize) / self.container.cycles_per_circuit;

        self.container.push_for_circuit(circuit_index, val);
    }

    pub fn into_iter(self) -> PerCircuitAccumulatorIntoIter<T> {
        self.container.into_iter()
    }
}

impl<T: TupleFirst> Extend<T> for PerCircuitAccumulatorSparse<T> {
    #[inline]
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let iterator = iter.into_iter();

        for element in iterator {
            self.push(element);
        }
    }
}

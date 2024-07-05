use crate::witness::aux_data_structs::TupleFirst;
use circuit_sequencer_api::INITIAL_MONOTONIC_CYCLE_COUNTER;

#[derive(Default)]
struct OnePerCircuitAccumulatorContainer<T> {
    cycles_per_circuit: usize,
    circuits_data: Vec<T>,
    accumulated: usize,
}

impl<T> OnePerCircuitAccumulatorContainer<T> {
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

        let mut _self = Self::new(cycles_per_circuit);
        _self.circuits_data.reserve_exact(num_circuits);
        _self
    }

    pub fn reserve_exact(&mut self, additional: usize) {
        self.circuits_data.reserve_exact(additional);
    }

    pub fn reserve_exact_flat(&mut self, additional: usize) {
        let num_circuits =
            (self.accumulated + additional + self.cycles_per_circuit - 1) / self.cycles_per_circuit;

        self.circuits_data
            .reserve_exact(num_circuits - self.circuits_data.capacity());
    }

    pub fn len(&self) -> usize {
        self.accumulated
    }

    pub fn last(&self) -> Option<&T> {
        self.circuits_data.last()
    }

    pub fn push_for_circuit(&mut self, circuit_index: usize, val: T) {
        if self.circuits_data.len() <= circuit_index {
            self.circuits_data.push(val);
        } else {
            self.circuits_data[circuit_index] = val;
        }

        self.accumulated += 1;
    }

    pub fn into_circuits(self) -> Vec<T> {
        self.circuits_data
    }
}

/// Accumulates values ​​and saves only the last value for each circuit
pub struct LastPerCircuitAccumulator<T> {
    container: OnePerCircuitAccumulatorContainer<T>,
}

impl<T> LastPerCircuitAccumulator<T> {
    pub fn new(cycles_per_circuit: usize) -> Self {
        Self {
            container: OnePerCircuitAccumulatorContainer::new(cycles_per_circuit),
        }
    }

    pub fn with_flat_capacity(cycles_per_circuit: usize, flat_capacity: usize) -> Self {
        Self {
            container: OnePerCircuitAccumulatorContainer::with_flat_capacity(
                cycles_per_circuit,
                flat_capacity,
            ),
        }
    }

    pub fn reserve_exact_flat(&mut self, additional: usize) {
        self.container.reserve_exact_flat(additional);
    }

    pub fn into_circuits(self) -> Vec<T> {
        self.container.into_circuits()
    }

    pub fn last(&self) -> Option<&T> {
        self.container.last()
    }

    pub fn len(&self) -> usize {
        self.container.len()
    }

    pub fn push(&mut self, val: T) {
        assert!(self.container.cycles_per_circuit != 0);
        let circuit_id = self.container.len() / self.container.cycles_per_circuit;
        self.container.push_for_circuit(circuit_id, val);
    }
}

impl<T> Default for LastPerCircuitAccumulator<T> {
    fn default() -> Self {
        Self::new(0)
    }
}

#[derive(Default)]
/// Accumulates values ​​and saves only the entry value for each circuit
/// Uses sparse input - values arrives unevenly
pub struct CircuitsEntryAccumulatorSparse<T: TupleFirst>
where
    T: Clone,
{
    container: OnePerCircuitAccumulatorContainer<T>,
    last: T,
}

// TODO can be optimized for sparse values
impl<T: TupleFirst> CircuitsEntryAccumulatorSparse<T>
where
    T: Clone,
{
    pub fn new(cycles_per_circuit: usize, initial_value: T) -> Self {
        Self {
            container: OnePerCircuitAccumulatorContainer::new(cycles_per_circuit),
            last: initial_value,
        }
    }

    pub fn from_iter<I: IntoIterator<Item = T>>(
        cycles_per_circuit: usize,
        initial_value: T,
        iterator: I,
    ) -> Self {
        let mut _self = Self::new(cycles_per_circuit, initial_value);
        let iterator = iterator.into_iter();

        for element in iterator {
            _self.push(element);
        }

        _self
    }

    pub fn extend<I: IntoIterator<Item = T>>(&mut self, iterator: I) {
        let iterator = iterator.into_iter();
        for element in iterator {
            self.push(element);
        }
    }

    pub fn last(&self) -> &T {
        &self.last
    }

    pub fn push(&mut self, val: T) {
        let cycle = val.first() as usize;
        if cycle < INITIAL_MONOTONIC_CYCLE_COUNTER as usize {
            self.last = val;
            return;
        }

        let circuit_index =
            (cycle - INITIAL_MONOTONIC_CYCLE_COUNTER as usize) / self.container.cycles_per_circuit;

        self.fill_gap(circuit_index);
        self.last = val;
    }

    pub fn into_circuits(mut self, amount_of_circuits: usize) -> Vec<T> {
        if self.container.len() < amount_of_circuits {
            self.container
                .reserve_exact(amount_of_circuits - self.container.len());
        }

        self.fill_gap(amount_of_circuits - 1);

        self.container.into_circuits()
    }

    fn fill_gap(&mut self, to_index: usize) {
        while self.container.len() <= to_index {
            self.container
                .push_for_circuit(self.container.len(), self.last.clone());
        }
    }
}

use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use derivative::Derivative;
use crate::pairing::Engine;
use crate::ff::{Field, PrimeField};

// for we need to encode some structures as packed field elements
pub trait OutOfCircuitFixedLengthEncodable<E: Engine, const N: usize> {
    fn encoding_witness(&self) -> [E::Fr; N];
}

// all encodings must match circuit counterparts
pub mod decommittment_request;
pub mod memory_query;
pub mod log_query;

#[derive(Derivative)]
#[derivative(Debug, Clone(bound=""), Copy(bound=""))]
pub struct QueueIntermediateStates<E: Engine, const SW: usize, const ROUNDS: usize> {
    pub head: E::Fr,
    pub tail: E::Fr,
    pub num_items: u32,
    pub round_function_execution_pairs: [([E::Fr; SW], [E::Fr; SW]); ROUNDS] 
}

pub struct QueueSimulator<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const ROUNDS: usize> {
    pub head: E::Fr,
    pub tail: E::Fr,
    pub num_items: u32,
    pub witness: Vec<([E::Fr; N], E::Fr, I)>, 
}

impl<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const ROUNDS: usize> QueueSimulator<E, I, N, ROUNDS> {
    pub fn empty() -> Self {
        Self {
            head: E::Fr::zero(),
            tail: E::Fr::zero(),
            num_items: 0,
            witness: vec![]
        }
    }

    pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize, const SW: usize>(
        &mut self, 
        element: I,
        round_function: &R
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize, const SW: usize>(
        &mut self, 
        element: I,
        round_function: &R
    ) -> (
        E::Fr, // old tail
        QueueIntermediateStates<E, SW, ROUNDS> // new head/tail, as well as round function ins/outs
    ) {
        let old_tail = self.tail;
        let encoding = element.encoding_witness();
        let mut to_hash = vec![];
        to_hash.extend_from_slice(&encoding);
        to_hash.push(self.tail);

        let states = round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(
            &to_hash
        );
        let new_tail = R::simulate_state_into_commitment(states.last().map(|el| el.1).unwrap());
        self.witness.push((encoding, new_tail, element));
        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = QueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            num_items: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap()
        };

        (old_tail, intermediate_info)
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound=""), Copy(bound=""))]
pub struct SpongeLikeQueueIntermediateStates<E: Engine, const SW: usize, const ROUNDS: usize> {
    pub head: [E::Fr; SW],
    pub tail: [E::Fr; SW],
    pub num_items: u32,
    pub round_function_execution_pairs: [([E::Fr; SW], [E::Fr; SW]); ROUNDS] 
}

pub struct SpongeLikeQueueSimulator<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const SW: usize, const ROUNDS: usize> {
    pub head: [E::Fr; SW],
    pub tail: [E::Fr; SW],
    pub num_items: u32,
    pub witness: Vec<([E::Fr; N], [E::Fr; SW], I)>, 
}

impl<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const SW: usize, const ROUNDS: usize> SpongeLikeQueueSimulator<E, I, N, SW, ROUNDS> {
    pub fn empty() -> Self {
        Self {
            head: [E::Fr::zero(); SW],
            tail: [E::Fr::zero(); SW],
            num_items: 0,
            witness: vec![]
        }
    }

    pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self, 
        element: I,
        round_function: &R
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self, 
        element: I,
        round_function: &R
    ) -> (
        [E::Fr; SW], // old tail
        SpongeLikeQueueIntermediateStates<E, SW, ROUNDS>
    ) {
        let old_tail = self.tail;
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let states = round_function.simulate_absorb_multiple_rounds(
            self.tail,
            &encoding
        );
        let new_tail = states.last().map(|el| el.1).unwrap();

        self.witness.push((encoding, new_tail, element));
        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = SpongeLikeQueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            num_items: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap()
        };

        (old_tail, intermediate_info)
    }
}


pub struct SpongeLikeStackSimulator<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const SW: usize> {
    pub state: [E::Fr; SW],
    pub num_items: u32,
    pub witness: Vec<([E::Fr; N], [E::Fr; SW], I)>, 
}

impl<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const SW: usize> SpongeLikeStackSimulator<E, I, N, SW> {
    pub fn empty() -> Self {
        Self {
            state: [E::Fr::zero(); SW],
            num_items: 0,
            witness: vec![]
        }
    }

    pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self, 
        element: I,
        round_function: &R
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self, 
        element: I,
        round_function: &R
    ) -> Vec<([E::Fr; SW], [E::Fr; SW])> {
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let states = round_function.simulate_absorb_multiple_rounds(
            self.state,
            &encoding
        );
        let new_state = states.last().map(|el| el.1).unwrap();

        self.witness.push((encoding, self.state, element));
        self.num_items += 1;
        self.state = new_state;

        states
    }

    pub fn pop_and_output_intermediate_data<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self, 
        round_function: &R
    ) -> (I, Vec<([E::Fr; SW], [E::Fr; SW])>) {
        assert!(N % AW == 0);
        let popped = self.witness.pop().unwrap();
        self.num_items -= 1;

        let (_element_encoding, previous_state, element) = popped;
        let encoding = element.encoding_witness();

        let states = round_function.simulate_absorb_multiple_rounds(
            previous_state,
            &encoding
        );
        let new_state = states.last().map(|el| el.1).unwrap();
        assert_eq!(new_state, self.state);

        self.state = previous_state;

        (element, states)
    }
}
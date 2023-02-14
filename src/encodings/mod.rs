use std::collections::VecDeque;

use crate::ff::{Field, PrimeField};
use crate::pairing::Engine;
use derivative::Derivative;
use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;

// for we need to encode some structures as packed field elements
pub trait OutOfCircuitFixedLengthEncodable<E: Engine, const N: usize>: Clone {
    fn encoding_witness(&self) -> [E::Fr; N];
}

// all encodings must match circuit counterparts
pub mod callstack_entry;
pub mod decommittment_request;
pub mod initial_storage_write;
pub mod log_query;
pub mod memory_query;
pub mod recursion_request;
pub mod repeated_storage_write;

pub use self::log_query::*;

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
pub struct QueueIntermediateStates<E: Engine, const SW: usize, const ROUNDS: usize> {
    pub head: E::Fr,
    pub tail: E::Fr,
    pub previous_head: E::Fr,
    pub previous_tail: E::Fr,
    pub num_items: u32,
    pub round_function_execution_pairs: [([E::Fr; SW], [E::Fr; SW]); ROUNDS],
}

impl<E: Engine, const SW: usize, const ROUNDS: usize> QueueIntermediateStates<E, SW, ROUNDS> {
    pub fn empty() -> Self {
        Self {
            head: E::Fr::zero(),
            tail: E::Fr::zero(),
            previous_head: E::Fr::zero(),
            previous_tail: E::Fr::zero(),
            num_items: 0,
            round_function_execution_pairs: [([E::Fr::zero(); SW], [E::Fr::zero(); SW]); ROUNDS],
        }
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone(bound = ""), Default(bound = ""), Debug)]
#[serde(bound = "")]
pub struct QueueSimulator<
    E: Engine,
    I: OutOfCircuitFixedLengthEncodable<E, N>,
    const N: usize,
    const ROUNDS: usize,
> {
    pub head: E::Fr,
    pub tail: E::Fr,
    pub num_items: u32,
    #[serde(bound(serialize = "[E::Fr; N]: serde::Serialize, I: serde::Serialize"))]
    #[serde(bound(
        deserialize = "[E::Fr; N]: serde::de::DeserializeOwned, I: serde::de::DeserializeOwned"
    ))]
    pub witness: VecDeque<([E::Fr; N], E::Fr, I)>,
}

impl<E: Engine, I: OutOfCircuitFixedLengthEncodable<E, N>, const N: usize, const ROUNDS: usize>
    QueueSimulator<E, I, N, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: E::Fr::zero(),
            tail: E::Fr::zero(),
            num_items: 0,
            witness: VecDeque::new(),
        }
    }

    pub fn split(mut self, at: u32) -> (Self, Self) {
        if at >= self.num_items {
            let mut artificial_empty = Self::empty();
            artificial_empty.head = self.tail;
            artificial_empty.tail = self.tail;
            return (self, artificial_empty);
        }

        let first_wit: VecDeque<_> = self.witness.drain(..(at as usize)).collect();
        let rest_wit = self.witness;

        let splitting_point = rest_wit.front().unwrap().1;

        let first = Self {
            head: self.head,
            tail: splitting_point,
            num_items: at,
            witness: first_wit,
        };

        let rest = Self {
            head: splitting_point,
            tail: self.tail,
            num_items: self.num_items - at,
            witness: rest_wit,
        };

        (first, rest)
    }

    pub fn merge(first: Self, second: Self) -> Self {
        assert_eq!(first.tail, second.head);

        let mut wit = first.witness;
        wit.extend(second.witness);

        Self {
            head: first.head,
            tail: second.tail,
            num_items: first.num_items + second.num_items,
            witness: wit,
        }
    }

    pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize, const SW: usize>(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitArithmeticRoundFunction<E, AW, SW>,
        const AW: usize,
        const SW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) -> (
        E::Fr,                                  // old tail
        QueueIntermediateStates<E, SW, ROUNDS>, // new head/tail, as well as round function ins/outs
    ) {
        let old_tail = self.tail;
        let encoding = element.encoding_witness();
        let mut to_hash = vec![];
        to_hash.extend_from_slice(&encoding);
        to_hash.push(self.tail);

        let states =
            round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&to_hash);
        let new_tail = R::simulate_state_into_commitment(states.last().map(|el| el.1).unwrap());
        self.witness.push_back((encoding, old_tail, element));

        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = QueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            previous_head: self.head, // unchanged
            previous_tail: old_tail,
            num_items: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap(),
        };

        (old_tail, intermediate_info)
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitArithmeticRoundFunction<E, AW, SW>,
        const AW: usize,
        const SW: usize,
    >(
        &mut self,
        round_function: &R,
    ) -> (
        I, // old tail
        QueueIntermediateStates<E, SW, ROUNDS>,
    ) {
        let old_head = self.head;
        let (_, _, element) = self.witness.pop_front().unwrap();

        let encoding = element.encoding_witness();
        let mut to_hash = vec![];
        to_hash.extend_from_slice(&encoding);
        to_hash.push(self.head);

        let states =
            round_function.simulate_absorb_multiple_rounds_into_empty_with_specialization(&to_hash);
        let new_head = R::simulate_state_into_commitment(states.last().map(|el| el.1).unwrap());

        self.num_items -= 1;
        self.head = new_head;

        if self.num_items == 0 {
            assert_eq!(self.head, self.tail);
        }

        let intermediate_info = QueueIntermediateStates {
            head: self.head,
            tail: self.tail,
            previous_head: old_head,
            previous_tail: self.tail,
            num_items: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap(),
        };

        (element, intermediate_info)
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
pub struct SpongeLikeQueueIntermediateStates<E: Engine, const SW: usize, const ROUNDS: usize> {
    pub head: [E::Fr; SW],
    pub tail: [E::Fr; SW],
    pub old_head: [E::Fr; SW],
    pub old_tail: [E::Fr; SW],
    pub num_items: u32,
    pub round_function_execution_pairs: [([E::Fr; SW], [E::Fr; SW]); ROUNDS],
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""))]
pub struct SpongeLikeQueueSimulator<
    E: Engine,
    I: OutOfCircuitFixedLengthEncodable<E, N>,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub head: [E::Fr; SW],
    pub tail: [E::Fr; SW],
    pub num_items: u32,
    pub witness: VecDeque<([E::Fr; N], [E::Fr; SW], I)>,
}

impl<
        E: Engine,
        I: OutOfCircuitFixedLengthEncodable<E, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > Default for SpongeLikeQueueSimulator<E, I, N, SW, ROUNDS>
{
    fn default() -> Self {
        Self::empty()
    }
}

impl<
        E: Engine,
        I: OutOfCircuitFixedLengthEncodable<E, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > SpongeLikeQueueSimulator<E, I, N, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: [E::Fr::zero(); SW],
            tail: [E::Fr::zero(); SW],
            num_items: 0,
            witness: VecDeque::new(),
        }
    }

    pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitArithmeticRoundFunction<E, AW, SW>,
        const AW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) -> (
        [E::Fr; SW], // old tail
        SpongeLikeQueueIntermediateStates<E, SW, ROUNDS>,
    ) {
        let old_tail = self.tail;
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let states = round_function.simulate_absorb_multiple_rounds(self.tail, &encoding);
        let new_tail = states.last().map(|el| el.1).unwrap();

        self.witness.push_back((encoding, new_tail, element));
        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = SpongeLikeQueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            old_head: self.head,
            old_tail,
            num_items: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap(),
        };

        (old_tail, intermediate_info)
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitArithmeticRoundFunction<E, AW, SW>,
        const AW: usize,
    >(
        &mut self,
        round_function: &R,
    ) -> (
        I, // old tail
        SpongeLikeQueueIntermediateStates<E, SW, ROUNDS>,
    ) {
        let old_head = self.head;
        assert!(N % AW == 0);
        let (_, _, element) = self.witness.pop_front().unwrap();
        let encoding = element.encoding_witness();

        let states = round_function.simulate_absorb_multiple_rounds(self.head, &encoding);
        let new_head = states.last().map(|el| el.1).unwrap();

        self.num_items -= 1;
        self.head = new_head;

        if self.num_items == 0 {
            assert_eq!(self.head, self.tail);
        }

        let intermediate_info = SpongeLikeQueueIntermediateStates {
            head: self.head,
            tail: self.tail,
            old_head,
            old_tail: self.tail,
            num_items: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap(),
        };

        (element, intermediate_info)
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
#[serde(bound = "")]
pub struct SpongeLikeStackIntermediateStates<E: Engine, const SW: usize, const ROUNDS: usize> {
    pub is_push: bool,
    #[serde(with = "sync_vm::utils::BigArraySerde")]
    pub previous_state: [E::Fr; SW],
    #[serde(with = "sync_vm::utils::BigArraySerde")]
    pub new_state: [E::Fr; SW],
    pub depth: u32,
    #[serde(skip)]
    #[serde(default = "empty_array_of_arrays::<E, SW, ROUNDS>")]
    pub round_function_execution_pairs: [([E::Fr; SW], [E::Fr; SW]); ROUNDS],
}

fn empty_array_of_arrays<E: Engine, const SW: usize, const ROUNDS: usize>(
) -> [([E::Fr; SW], [E::Fr; SW]); ROUNDS] {
    [([E::Fr::zero(); SW], [E::Fr::zero(); SW]); ROUNDS]
}

pub struct SpongeLikeStackSimulator<
    E: Engine,
    I: OutOfCircuitFixedLengthEncodable<E, N>,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub state: [E::Fr; SW],
    pub num_items: u32,
    pub witness: Vec<([E::Fr; N], [E::Fr; SW], I)>,
}

impl<
        E: Engine,
        I: OutOfCircuitFixedLengthEncodable<E, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > SpongeLikeStackSimulator<E, I, N, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            state: [E::Fr::zero(); SW],
            num_items: 0,
            witness: vec![],
        }
    }

    pub fn push<R: CircuitArithmeticRoundFunction<E, AW, SW>, const AW: usize>(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitArithmeticRoundFunction<E, AW, SW>,
        const AW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) -> SpongeLikeStackIntermediateStates<E, SW, ROUNDS> {
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let old_state = self.state;

        let states = round_function.simulate_absorb_multiple_rounds(self.state, &encoding);
        let new_state = states.last().map(|el| el.1).unwrap();

        self.witness.push((encoding, self.state, element));
        self.num_items += 1;
        self.state = new_state;

        let intermediate_info = SpongeLikeStackIntermediateStates {
            is_push: true,
            previous_state: old_state,
            new_state,
            depth: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap(),
        };

        intermediate_info
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitArithmeticRoundFunction<E, AW, SW>,
        const AW: usize,
    >(
        &mut self,
        round_function: &R,
    ) -> (I, SpongeLikeStackIntermediateStates<E, SW, ROUNDS>) {
        assert!(N % AW == 0);

        let current_state = self.state;

        let popped = self.witness.pop().unwrap();
        self.num_items -= 1;

        let (_element_encoding, previous_state, element) = popped;
        let encoding = element.encoding_witness();

        let states = round_function.simulate_absorb_multiple_rounds(previous_state, &encoding);
        let new_state = states.last().map(|el| el.1).unwrap();
        assert_eq!(new_state, self.state);

        self.state = previous_state;

        let intermediate_info = SpongeLikeStackIntermediateStates {
            is_push: false,
            previous_state: current_state,
            new_state: previous_state,
            depth: self.num_items,
            round_function_execution_pairs: states.try_into().unwrap(),
        };

        (element, intermediate_info)
    }
}

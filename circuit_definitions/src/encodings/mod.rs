use crate::boojum::algebraic_props::round_function::{
    absorb_multiple_rounds, AbsorptionModeOverwrite, AlgebraicRoundFunction,
};
use crate::boojum::field::SmallField;
use crate::boojum::gadgets::traits::allocatable::CSAllocatable;
use crate::boojum::gadgets::traits::round_function::*;
use crate::boojum::gadgets::u160::decompose_address_as_u32x5;
use crate::boojum::gadgets::u256::decompose_u256_as_u32x8;
use derivative::Derivative;
use std::collections::VecDeque;
use zkevm_circuits::base_structures::vm_state::{FULL_SPONGE_QUEUE_STATE_WIDTH, QUEUE_STATE_WIDTH};

// for we need to encode some structures as packed field elements
pub trait OutOfCircuitFixedLengthEncodable<F: SmallField, const N: usize>: Clone {
    fn encoding_witness(&self) -> [F; N];
}

// all encodings must match circuit counterparts
pub mod callstack_entry;
pub mod decommittment_request;
pub mod log_query;
pub mod memory_query;
pub mod recursion_request;
pub mod state_diff_record;

pub use self::log_query::*;

pub(crate) fn make_round_function_pairs<F: SmallField, const N: usize, const ROUNDS: usize>(
    initial: [F; N],
    intermediates: [[F; N]; ROUNDS],
) -> [([F; N], [F; N]); ROUNDS] {
    let mut result = [([F::ZERO; N], [F::ZERO; N]); ROUNDS];
    result[0].0 = initial;
    result[0].1 = intermediates[0];
    for idx in 1..ROUNDS {
        result[idx].0 = result[idx - 1].1;
        result[idx].1 = intermediates[idx];
    }

    result
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
pub struct QueueIntermediateStates<
    F: SmallField,
    const T: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub head: [F; T],
    pub tail: [F; T],
    pub previous_head: [F; T],
    pub previous_tail: [F; T],
    pub num_items: u32,
    pub round_function_execution_pairs: [([F; SW], [F; SW]); ROUNDS],
}

impl<F: SmallField, const T: usize, const SW: usize, const ROUNDS: usize>
    QueueIntermediateStates<F, T, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: [F::ZERO; T],
            tail: [F::ZERO; T],
            previous_head: [F::ZERO; T],
            previous_tail: [F::ZERO; T],
            num_items: 0,
            round_function_execution_pairs: [([F::ZERO; SW], [F::ZERO; SW]); ROUNDS],
        }
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(
    Clone(bound = ""),
    Default(bound = "[F; T]: Default, [F; N]: Default"),
    Debug
)]
#[serde(bound = "[F; T]: serde::Serialize + serde::de::DeserializeOwned,
    [F; N]: serde::Serialize + serde::de::DeserializeOwned,
    I: serde::Serialize + serde::de::DeserializeOwned")]
pub struct QueueSimulator<
    F: SmallField,
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const T: usize,
    const N: usize,
    const ROUNDS: usize,
> {
    pub head: [F; T],
    pub tail: [F; T],
    pub num_items: u32,
    pub witness: VecDeque<([F; N], [F; T], I)>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const T: usize,
        const N: usize,
        const ROUNDS: usize,
    > QueueSimulator<F, I, T, N, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: [F::ZERO; T],
            tail: [F::ZERO; T],
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

    pub fn push<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        _round_function: &R,
    ) -> (
        [F; T],                                    // old tail
        QueueIntermediateStates<F, T, SW, ROUNDS>, // new head/tail, as well as round function ins/outs
    ) {
        let old_tail = self.tail;
        let encoding = element.encoding_witness();
        let mut to_hash = Vec::with_capacity(N + T);
        to_hash.extend_from_slice(&encoding);
        to_hash.extend(self.tail);

        let mut state = R::initial_state();
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &to_hash,
        );
        let new_tail =
            <R as AlgebraicRoundFunction<F, AW, SW, CW>>::state_into_commitment::<T>(&state);
        self.witness.push_back((encoding, old_tail, element));

        let states = make_round_function_pairs(R::initial_state(), states);

        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = QueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            previous_head: self.head, // unchanged
            previous_tail: old_tail,
            num_items: self.num_items,
            round_function_execution_pairs: states,
        };

        (old_tail, intermediate_info)
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        &mut self,
        _round_function: &R,
    ) -> (I, QueueIntermediateStates<F, T, SW, ROUNDS>) {
        let old_head = self.head;
        let (_, _, element) = self.witness.pop_front().unwrap();

        let encoding = element.encoding_witness();
        let mut to_hash = Vec::with_capacity(N + T);
        to_hash.extend_from_slice(&encoding);
        to_hash.extend(self.head);

        let mut state = R::initial_state();
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &to_hash,
        );
        let new_head =
            <R as AlgebraicRoundFunction<F, AW, SW, CW>>::state_into_commitment::<T>(&state);

        let states = make_round_function_pairs(R::initial_state(), states);

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
            round_function_execution_pairs: states,
        };

        (element, intermediate_info)
    }

    pub fn split_by<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const SW: usize,
        const CW: usize,
    >(
        mut self,
        chunk_size: usize,
        round_function: &R,
    ) -> Vec<Self> {
        let mut result = vec![];
        if self.num_items == 0 {
            return result;
        } else {
            assert_eq!(self.witness.len(), self.num_items as usize);
        }

        while self.num_items > 0 {
            let mut subqueue = Self::empty();
            subqueue.head = self.head;
            subqueue.tail = self.head;
            for _ in 0..chunk_size {
                if self.num_items == 0 {
                    break;
                }
                let (el, _) = self.pop_and_output_intermediate_data(round_function);
                subqueue.push(el, round_function);
            }

            result.push(subqueue);
        }

        assert_eq!(self.tail, result.last().unwrap().tail);

        result
    }
}

#[derive(Derivative)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
pub struct FullWidthQueueIntermediateStates<F: SmallField, const SW: usize, const ROUNDS: usize> {
    pub head: [F; SW],
    pub tail: [F; SW],
    pub old_head: [F; SW],
    pub old_tail: [F; SW],
    pub num_items: u32,
    pub round_function_execution_pairs: [([F; SW], [F; SW]); ROUNDS],
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Debug, Clone(bound = ""))]
#[serde(bound = "[F; SW]: serde::Serialize + serde::de::DeserializeOwned,
    [F; N]: serde::Serialize + serde::de::DeserializeOwned,
    I: serde::Serialize + serde::de::DeserializeOwned")]
pub struct FullWidthQueueSimulator<
    F: SmallField,
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub head: [F; SW],
    pub tail: [F; SW],
    pub num_items: u32,
    pub witness: VecDeque<([F; N], [F; SW], I)>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > Default for FullWidthQueueSimulator<F, I, N, SW, ROUNDS>
{
    fn default() -> Self {
        Self::empty()
    }
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > FullWidthQueueSimulator<F, I, N, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            head: [F::ZERO; SW],
            tail: [F::ZERO; SW],
            num_items: 0,
            witness: VecDeque::new(),
        }
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

    pub fn push<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        _round_function: &R,
    ) -> (
        [F; SW], // old tail
        FullWidthQueueIntermediateStates<F, SW, ROUNDS>,
    ) {
        let old_tail = self.tail;
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let mut state = old_tail;
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_tail = state;

        let states = make_round_function_pairs(old_tail, states);

        self.witness.push_back((encoding, new_tail, element));
        self.num_items += 1;
        self.tail = new_tail;

        let intermediate_info = FullWidthQueueIntermediateStates {
            head: self.head,
            tail: new_tail,
            old_head: self.head,
            old_tail,
            num_items: self.num_items,
            round_function_execution_pairs: states,
        };

        (old_tail, intermediate_info)
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        _round_function: &R,
    ) -> (I, FullWidthQueueIntermediateStates<F, SW, ROUNDS>) {
        let old_head = self.head;
        assert!(N % AW == 0);
        let (_, _, element) = self.witness.pop_front().unwrap();
        let encoding = element.encoding_witness();

        let mut state = old_head;
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_head = state;

        let states = make_round_function_pairs(old_head, states);

        self.num_items -= 1;
        self.head = new_head;

        if self.num_items == 0 {
            assert_eq!(self.head, self.tail);
        }

        let intermediate_info = FullWidthQueueIntermediateStates {
            head: self.head,
            tail: self.tail,
            old_head,
            old_tail: self.tail,
            num_items: self.num_items,
            round_function_execution_pairs: states,
        };

        (element, intermediate_info)
    }

    pub fn split_by<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        mut self,
        chunk_size: usize,
        round_function: &R,
    ) -> Vec<Self> {
        let mut result = vec![];
        if self.num_items == 0 {
            return result;
        } else {
            assert_eq!(self.witness.len(), self.num_items as usize);
        }

        while self.num_items > 0 {
            let mut subqueue = Self::empty();
            subqueue.head = self.head;
            subqueue.tail = self.head;
            for _ in 0..chunk_size {
                if self.num_items == 0 {
                    break;
                }
                let (el, _) = self.pop_and_output_intermediate_data(round_function);
                subqueue.push(el, round_function);
            }

            result.push(subqueue);
        }

        assert_eq!(self.tail, result.last().unwrap().tail);

        result
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Debug, Clone(bound = ""), Copy(bound = ""))]
#[serde(bound = "")]
pub struct FullWidthStackIntermediateStates<F: SmallField, const SW: usize, const ROUNDS: usize> {
    pub is_push: bool,
    #[serde(with = "crate::boojum::serde_utils::BigArraySerde")]
    pub previous_state: [F; SW],
    #[serde(with = "crate::boojum::serde_utils::BigArraySerde")]
    pub new_state: [F; SW],
    pub depth: u32,
    #[serde(skip)]
    #[serde(default = "empty_array_of_arrays::<F, SW, ROUNDS>")]
    pub round_function_execution_pairs: [([F; SW], [F; SW]); ROUNDS],
}

fn empty_array_of_arrays<F: SmallField, const SW: usize, const ROUNDS: usize>(
) -> [([F; SW], [F; SW]); ROUNDS] {
    [([F::ZERO; SW], [F::ZERO; SW]); ROUNDS]
}

pub struct FullWidthStackSimulator<
    F: SmallField,
    I: OutOfCircuitFixedLengthEncodable<F, N>,
    const N: usize,
    const SW: usize,
    const ROUNDS: usize,
> {
    pub state: [F; SW],
    pub num_items: u32,
    pub witness: Vec<([F; N], [F; SW], I)>,
}

impl<
        F: SmallField,
        I: OutOfCircuitFixedLengthEncodable<F, N>,
        const N: usize,
        const SW: usize,
        const ROUNDS: usize,
    > FullWidthStackSimulator<F, I, N, SW, ROUNDS>
{
    pub fn empty() -> Self {
        Self {
            state: [F::ZERO; SW],
            num_items: 0,
            witness: vec![],
        }
    }

    pub fn push<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        round_function: &R,
    ) {
        let _ = self.push_and_output_intermediate_data(element, round_function);
    }

    pub fn push_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        element: I,
        _round_function: &R,
    ) -> FullWidthStackIntermediateStates<F, SW, ROUNDS> {
        assert!(N % AW == 0);
        let encoding = element.encoding_witness();

        let old_state = self.state;

        let mut state = old_state;
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_state = state;

        let states = make_round_function_pairs(old_state, states);

        self.witness.push((encoding, self.state, element));
        self.num_items += 1;
        self.state = new_state;

        let intermediate_info = FullWidthStackIntermediateStates {
            is_push: true,
            previous_state: old_state,
            new_state,
            depth: self.num_items,
            round_function_execution_pairs: states,
        };

        intermediate_info
    }

    pub fn pop_and_output_intermediate_data<
        R: CircuitRoundFunction<F, AW, SW, CW> + AlgebraicRoundFunction<F, AW, SW, CW>,
        const AW: usize,
        const CW: usize,
    >(
        &mut self,
        _round_function: &R,
    ) -> (I, FullWidthStackIntermediateStates<F, SW, ROUNDS>) {
        assert!(N % AW == 0);

        let current_state = self.state;

        let popped = self.witness.pop().unwrap();
        self.num_items -= 1;

        let (_element_encoding, previous_state, element) = popped;
        let encoding = element.encoding_witness();

        let mut state = previous_state;
        let states = absorb_multiple_rounds::<F, R, AbsorptionModeOverwrite, AW, SW, CW, ROUNDS>(
            &mut state, &encoding,
        );
        let new_state = state;
        assert_eq!(new_state, self.state);

        let states = make_round_function_pairs(previous_state, states);

        self.state = previous_state;

        let intermediate_info = FullWidthStackIntermediateStates {
            is_push: false,
            previous_state: current_state,
            new_state: previous_state,
            depth: self.num_items,
            round_function_execution_pairs: states,
        };

        (element, intermediate_info)
    }
}

pub trait CircuitEquivalentReflection<F: SmallField>: Clone {
    type Destination: Clone + CSAllocatable<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness;
}

pub trait BytesSerializable<const N: usize>: Clone {
    fn serialize(&self) -> [u8; N];
}

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key<const N: usize>(pub [u32; N]);

pub(crate) trait IntoSmallField<F: SmallField>: Sized {
    fn into_field(self) -> F;
}

impl<F: SmallField> IntoSmallField<F> for bool {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

impl<F: SmallField> IntoSmallField<F> for u8 {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

impl<F: SmallField> IntoSmallField<F> for u16 {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

impl<F: SmallField> IntoSmallField<F> for u32 {
    #[inline(always)]
    fn into_field(self) -> F {
        F::from_u64_unchecked(self as u64)
    }
}

#[inline(always)]
pub(crate) fn scale_and_accumulate<F: SmallField, T: IntoSmallField<F>>(
    dst: &mut F,
    src: T,
    shift: usize,
) {
    let mut tmp = src.into_field();
    tmp.mul_assign(&F::SHIFTS[shift]);
    dst.add_assign(&tmp);
}

#[inline(always)]
pub(crate) fn linear_combination<F: SmallField>(input: &[(F, F)]) -> F {
    let mut result = F::ZERO;
    for (a, b) in input.iter() {
        let mut tmp = *a;
        tmp.mul_assign(&b);
        result.add_assign(&tmp);
    }

    result
}

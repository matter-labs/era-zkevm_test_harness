use boojum::implementations::poseidon2::Poseidon2Goldilocks;
use crossbeam::atomic::AtomicCell;
use boojum::field::SmallField;
use boojum::gadgets::poseidon::CircuitRoundFunction;
use boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use boojum::cs::traits::cs::ConstraintSystem;
use zkevm_circuits::base_structures::decommit_query::DecommitQuery;
use zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use boojum::gadgets::num::Num;
use zkevm_circuits::base_structures::log_query::LogQuery;
use zkevm_circuits::base_structures::memory_query::MemoryQuery;
use boojum::gadgets::traits::allocatable::*;
use boojum::gadgets::u256::UInt256;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;

pub mod concrete_circuits;

pub trait ZkSyncUniformSynthesisFunction<F: SmallField>: Clone 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]: 
{ 
    type Witness: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned;
    type Config: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned;
    type RoundFunction: CircuitRoundFunction<F, 8, 12, 4> + AlgebraicRoundFunction<F, 8, 12, 4>;

    fn description() -> String;

    // fn get_setup_function_dyn<
    //     'a, 
    //     CS: ConstraintSystem<F> + 'a,
    // >() -> Box<dyn FnOnce(&mut CS) -> () + 'a> {
    //     Box::new(|_| {
    //         Ok(())
    //     })
    // }

    fn get_synthesis_function_dyn<
        'a, 
        CS: ConstraintSystem<F> + 'a,
    >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a>;
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct ZkSyncUniformCircuitCircuitInstance<
    F: SmallField,
    S: ZkSyncUniformSynthesisFunction<F>,
> where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]: 
{
    #[serde(serialize_with = "serialize_atomic_cell")]
    #[serde(deserialize_with = "deserialize_atomic_cell")]
    pub witness: AtomicCell<Option<S::Witness>>,
    #[serde(serialize_with = "serialize_arc")]
    #[serde(deserialize_with = "deserialize_arc")]
    pub config: std::sync::Arc<S::Config>,
    #[serde(serialize_with = "serialize_arc")]
    #[serde(deserialize_with = "deserialize_arc")]
    #[serde(bound(serialize = "S::RoundFunction: serde::Serialize"))]
    #[serde(bound(deserialize = "S::RoundFunction: serde::de::DeserializeOwned"))]
    pub round_function: std::sync::Arc<S::RoundFunction>,

    pub expected_public_input: Option<F>,
}

impl<F: SmallField, S: ZkSyncUniformSynthesisFunction<F>> ZkSyncUniformCircuitCircuitInstance<F, S> 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]:  
{
    pub fn new(witness: Option<S::Witness>, config: S::Config, round_function: S::RoundFunction, expected_public_input: Option<F>) -> Self {
        Self { witness: AtomicCell::new(witness), config: std::sync::Arc::new(config), round_function: std::sync::Arc::new(round_function), expected_public_input }
    }

    pub fn debug_witness(&self) {
        let wit = self.witness.take();
        dbg!(&wit);
        self.witness.store(wit);
    }

    pub fn clone_witness(&self) -> Option<S::Witness> {
        let wit = self.witness.take();
        let ww = wit.clone();
        self.witness.store(wit);

        ww
    }

    pub fn erase_witness(&self) {
        let _ = self.witness.take();
    }
}

fn serialize_atomic_cell<T: serde::Serialize, S>(t: &AtomicCell<Option<T>>, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    let el = t.take();
    let res = match &el {
        Some(el) => serializer.serialize_some(el),
        None => serializer.serialize_none(),
    };
    
    t.store(el);

    res
}

fn serialize_arc<T: serde::Serialize, S>(t: &std::sync::Arc<T>, serializer: S) -> Result<S::Ok, S::Error> where S: serde::Serializer {
    (*t).serialize(serializer)
}

fn deserialize_atomic_cell<'de, D, T: serde::Deserialize<'de>>(deserializer: D) -> Result<AtomicCell<T>, D::Error> where D: serde::Deserializer<'de> {
    let res = T::deserialize(deserializer)?;
    let cell = AtomicCell::new(res);

    Ok(cell)
}

fn deserialize_arc<'de, D, T: serde::Deserialize<'de>>(deserializer: D) -> Result<std::sync::Arc<T>, D::Error> where D: serde::Deserializer<'de> {
    let res = T::deserialize(deserializer)?;
    let arc = std::sync::Arc::new(res);

    Ok(arc)
}

impl<
    F: SmallField, 
    S: ZkSyncUniformSynthesisFunction<F>,
> Clone for ZkSyncUniformCircuitCircuitInstance<F, S> 
where [(); <LogQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <MemoryQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <DecommitQuery<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN]:,
    [(); <UInt256<F> as CSAllocatableExt<F>>::INTERNAL_STRUCT_LEN + 1]: 
{ 
    fn clone(&self) -> Self {
        let wit = self.witness.take();
        let ww = wit.clone();
        self.witness.store(wit);

        Self {
            witness: AtomicCell::new(ww),
            config: std::sync::Arc::clone(&self.config),
            round_function: std::sync::Arc::clone(&self.round_function),
            expected_public_input: self.expected_public_input.clone(),
        }
    }
}


// impl<
//     F: SmallField, 
//     S: ZkSyncUniformSynthesisFunction<E>,
// > Circuit<E> for ZkSyncUniformCircuitCircuitInstance<E, S> {
//     type MainGate = SelectorOptimizedWidth4MainGateWithDNext;
//     // always two gates
//     fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
//         Ok(
//             vec![
//                 Self::MainGate::default().into_internal(),
//                 Rescue5CustomGate::default().into_internal()
//             ]
//         )
//     }
//     fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
//         let witness = self.witness.take();
//         let ww = witness.clone();
//         self.witness.store(witness);
//         let config: S::Config = (*self.config).clone();
//         let round_function = &*self.round_function;
//         let setup_fn = S::get_setup_function_dyn();
//         let synthesis_fn = S::get_synthesis_function_dyn();
//         // let synthesis_fn = S::get_synthesis_function();
//         setup_fn(cs)?;
//         let public_input_var = synthesis_fn(cs, ww, round_function, config)?;

//         if let Some(expected_input) = self.expected_public_input.as_ref() {
//             if let Some(wit_value) = public_input_var.get_value() {
//                 assert_eq!(*expected_input, wit_value, "we expected public input to be {}, but circuit returned {}", expected_input, wit_value);
//             }
//         }

//         Ok(())
//     }
// }
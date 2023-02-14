use sync_vm::circuit_structures::traits::CircuitArithmeticRoundFunction;
use sync_vm::franklin_crypto::bellman::plonk::better_better_cs::gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext;
use sync_vm::franklin_crypto::plonk::circuit::custom_rescue_gate::Rescue5CustomGate;
use sync_vm::franklin_crypto::plonk::circuit::tables::inscribe_default_range_table_for_bit_width_over_first_three_columns;
use sync_vm::vm::vm_cycle::add_all_tables;
use sync_vm::vm::vm_cycle::entry_point::vm_circuit_entry_point;
use sync_vm::vm::vm_cycle::witness_oracle::WitnessOracle;
use crate::bellman::Engine;
use crate::bellman::plonk::better_better_cs::cs::ConstraintSystem;
use crate::franklin_crypto::plonk::circuit::allocated_num::{AllocatedNum, Num};
use crate::bellman::SynthesisError;
use crossbeam::atomic::AtomicCell;

pub mod concrete_circuits;

use crate::bellman::plonk::better_better_cs::cs::Circuit;
use crate::bellman::plonk::better_better_cs::cs::Gate;
use crate::bellman::plonk::better_better_cs::cs::GateInternal;

pub trait ZkSyncUniformSynthesisFunction<E: Engine>: Clone {
    type Witness: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned;
    type Config: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned;
    type RoundFunction: CircuitArithmeticRoundFunction<E, 2, 3, StateElement = Num<E>>;

    fn description() -> String;

    fn get_setup_function_dyn<'a, CS: ConstraintSystem<E> + 'a>(
    ) -> Box<dyn FnOnce(&mut CS) -> Result<(), SynthesisError> + 'a> {
        Box::new(|_| Ok(()))
    }

    fn get_synthesis_function_dyn<'a, CS: ConstraintSystem<E> + 'a>() -> Box<
        dyn FnOnce(
                &mut CS,
                Option<Self::Witness>,
                &Self::RoundFunction,
                Self::Config,
            ) -> Result<AllocatedNum<E>, SynthesisError>
            + 'a,
    >;
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct ZkSyncUniformCircuitCircuitInstance<E: Engine, S: ZkSyncUniformSynthesisFunction<E>> {
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

    pub expected_public_input: Option<E::Fr>,
}

impl<E: Engine, S: ZkSyncUniformSynthesisFunction<E>> ZkSyncUniformCircuitCircuitInstance<E, S> {
    pub fn new(
        witness: Option<S::Witness>,
        config: S::Config,
        round_function: S::RoundFunction,
        expected_public_input: Option<E::Fr>,
    ) -> Self {
        Self {
            witness: AtomicCell::new(witness),
            config: std::sync::Arc::new(config),
            round_function: std::sync::Arc::new(round_function),
            expected_public_input,
        }
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

fn serialize_atomic_cell<T: serde::Serialize, S>(
    t: &AtomicCell<Option<T>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let el = t.take();
    let res = match &el {
        Some(el) => serializer.serialize_some(el),
        None => serializer.serialize_none(),
    };

    t.store(el);

    res
}

fn serialize_arc<T: serde::Serialize, S>(
    t: &std::sync::Arc<T>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    (*t).serialize(serializer)
}

fn deserialize_atomic_cell<'de, D, T: serde::Deserialize<'de>>(
    deserializer: D,
) -> Result<AtomicCell<T>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let res = T::deserialize(deserializer)?;
    let cell = AtomicCell::new(res);

    Ok(cell)
}

fn deserialize_arc<'de, D, T: serde::Deserialize<'de>>(
    deserializer: D,
) -> Result<std::sync::Arc<T>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let res = T::deserialize(deserializer)?;
    let arc = std::sync::Arc::new(res);

    Ok(arc)
}

impl<E: Engine, S: ZkSyncUniformSynthesisFunction<E>> Clone
    for ZkSyncUniformCircuitCircuitInstance<E, S>
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

impl<E: Engine, S: ZkSyncUniformSynthesisFunction<E>> Circuit<E>
    for ZkSyncUniformCircuitCircuitInstance<E, S>
{
    type MainGate = SelectorOptimizedWidth4MainGateWithDNext;
    // always two gates
    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate::default().into_internal(),
        ])
    }
    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let witness = self.witness.take();
        let ww = witness.clone();
        self.witness.store(witness);
        let config: S::Config = (*self.config).clone();
        let round_function = &*self.round_function;
        let setup_fn = S::get_setup_function_dyn();
        let synthesis_fn = S::get_synthesis_function_dyn();
        // let synthesis_fn = S::get_synthesis_function();
        setup_fn(cs)?;
        let public_input_var = synthesis_fn(cs, ww, round_function, config)?;

        if let Some(expected_input) = self.expected_public_input.as_ref() {
            if let Some(wit_value) = public_input_var.get_value() {
                assert_eq!(
                    *expected_input, wit_value,
                    "we expected public input to be {}, but circuit returned {}",
                    expected_input, wit_value
                );
            }
        }

        Ok(())
    }
}

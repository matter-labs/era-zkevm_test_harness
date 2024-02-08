use crate::boojum::algebraic_props::round_function::AlgebraicRoundFunction;
use crate::boojum::cs::cs_builder::*;
use crate::boojum::cs::traits::cs::ConstraintSystem;
use crate::boojum::cs::CSGeometry;
use crate::boojum::cs::*;
use crate::boojum::field::{FieldExtension, SmallField};
use crate::boojum::gadgets::num::Num;
use crate::boojum::gadgets::traits::allocatable::*;
use crate::boojum::gadgets::traits::round_function::*;
use crate::boojum::gadgets::traits::witnessable::WitnessHookable;
use crate::boojum::gadgets::u256::UInt256;
use crate::boojum::implementations::poseidon2::Poseidon2Goldilocks;
use crossbeam::atomic::AtomicCell;
use zkevm_circuits::base_structures::decommit_query::DecommitQuery;
use zkevm_circuits::base_structures::log_query::LogQuery;
use zkevm_circuits::base_structures::memory_query::MemoryQuery;
use zkevm_circuits::base_structures::vm_state::saved_context::ExecutionContextRecord;
use zkevm_circuits::fsm_input_output::circuit_inputs::INPUT_OUTPUT_COMMITMENT_LENGTH;
use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord;

pub mod aux_layer;
pub mod base_layer;
pub mod recursion_layer;
pub mod verifier_builder;

pub trait ZkSyncUniformSynthesisFunction<F: SmallField>:
    crate::boojum::cs::traits::circuit::CircuitBuilder<F>
    + 'static
    + Clone
    + serde::Serialize
    + serde::de::DeserializeOwned
{
    type Witness: Clone
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::default::Default;
    type Config: Clone + std::fmt::Debug + serde::Serialize + serde::de::DeserializeOwned;
    type RoundFunction: BuildableCircuitRoundFunction<F, 8, 12, 4>
        + AlgebraicRoundFunction<F, 8, 12, 4>
        + serde::Serialize
        + serde::de::DeserializeOwned;

    fn description() -> String;

    fn size_hint() -> (Option<usize>, Option<usize>) {
        (Some(1 << 20), Some(1 << 26))
    }

    fn add_tables<CS: ConstraintSystem<F>>(cs: &mut CS);

    fn synthesize_into_cs_inner<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        witness: Self::Witness,
        round_function: &Self::RoundFunction,
        config: Self::Config,
    ) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH];

    // fn get_synthesis_function_dyn<
    //     'a,
    //     CS: ConstraintSystem<F> + 'a,
    // >() -> Box<dyn FnOnce(&mut CS, Self::Witness, &Self::RoundFunction, Self::Config) -> [Num<F>; INPUT_OUTPUT_COMMITMENT_LENGTH] + 'a>
    // where Self: 'a {
    //     Box::new(Self::synthesize_into_cs_inner)
    // }
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct ZkSyncUniformCircuitInstance<F: SmallField, S: ZkSyncUniformSynthesisFunction<F>> {
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

    pub expected_public_input: Option<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
}

impl<F: SmallField, S: ZkSyncUniformSynthesisFunction<F>> ZkSyncUniformCircuitInstance<F, S> {
    pub fn new(
        witness: Option<S::Witness>,
        config: S::Config,
        round_function: S::RoundFunction,
        expected_public_input: Option<[F; INPUT_OUTPUT_COMMITMENT_LENGTH]>,
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

    pub fn geometry_proxy(&self) -> CSGeometry {
        S::geometry()
    }

    pub fn size_hint(&self) -> (Option<usize>, Option<usize>) {
        S::size_hint()
    }

    pub fn synthesize_proxy<CS: ConstraintSystem<F>>(self, cs: &mut CS) {
        let Self {
            witness,
            config,
            round_function,
            expected_public_input,
        } = self;
        let witness = witness.take();
        let ww = witness.unwrap_or_default();
        let config: S::Config = (*config).clone();
        let public_input_var = S::synthesize_into_cs_inner(cs, ww, &round_function, config);

        if let Some(expected_input) = expected_public_input.as_ref() {
            if let Some(wit_value) = public_input_var.witness_hook(&*cs)() {
                assert_eq!(
                    *expected_input, wit_value,
                    "we expected public input to be {:?}, but circuit returned {:?}",
                    expected_input, wit_value
                );
            }
        }
    }

    pub fn add_tables_proxy<CS: ConstraintSystem<F>>(&self, cs: &mut CS) {
        S::add_tables(cs);
    }

    pub fn configure_builder_proxy<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        &self,
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        S::configure_builder(builder)
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

impl<F: SmallField, S: ZkSyncUniformSynthesisFunction<F>> Clone
    for ZkSyncUniformCircuitInstance<F, S>
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

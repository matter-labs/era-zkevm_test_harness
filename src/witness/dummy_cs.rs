use std::{any::TypeId, collections::HashMap, marker::PhantomData};

use circuit_definitions::boojum::{config::{CSConfig, CSResolverConfig, DoEvaluateWitenss, DontEvaluateWitenss, DontKeepSetup, DontPerformRuntimeAsserts, ProvingCSConfig, Resolver}, cs::{gates::{ConstantToVariableMappingTool, ConstantToVariableMappingToolMarker, Poseidon2RoundFunctionFlattenedEvaluator}, implementations::lookup_table::{LookupTable, LookupTableWrapper, Wrappable}, traits::{cs::{ConstraintSystem, DstBuffer}, evaluator::GateConstraintEvaluator, gate::Gate}, CSGeometry, GateConfigurationHolder, GateTool, LookupParameters, Place, StaticToolboxHolder, Tool, Variable, Witness}, dag::{CSWitnessValues, CircuitResolver, DefaultCircuitResolver, NullCircuitResolver}, field::{self, SmallField}, gadgets::{tables::BinopTable, u32::UInt32DecompositionTooling}, utils::PipeOp};
use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug)]
pub struct DummyCSConfig;

impl CSConfig for DummyCSConfig {
    type WitnessConfig = DoEvaluateWitenss;
    type DebugConfig = DontPerformRuntimeAsserts;
    type SetupConfig = DontKeepSetup;
    type ResolverConfig = Resolver<DontPerformRuntimeAsserts>;
}

pub struct CSDummyImplementation<F: 'static + Send + Sync> {
    _marker: PhantomData<F>,
    storage: HashMap<Place, F>,
    next_available_place_idx: u64,
    toolbox: (Tool<ConstantToVariableMappingToolMarker, ConstantToVariableMappingTool<F>>, ()),
    pub(crate) dynamic_tools:
        HashMap<TypeId, (TypeId, Box<dyn std::any::Any + Send + Sync + 'static>)>,
    pub(crate) lookup_table_marker_into_id: HashMap<TypeId, u32>,
}

impl<F: 'static + Send + Sync> CSDummyImplementation<F> {
    pub fn new() -> Self {
        let toolbox = ().add_tool(ConstantToVariableMappingTool::<F>::new());
        let mut lookup_table_marker_into_id: HashMap<_,_> = Default::default();
        lookup_table_marker_into_id.insert(std::any::TypeId::of::<BinopTable>(), 0);
        Self {
            _marker: PhantomData,
            storage: Default::default(),
            next_available_place_idx: 0,
            toolbox,
            dynamic_tools: Default::default(),
            lookup_table_marker_into_id
        }
    }
}

pub struct DummyGateConfigurationHolder<F> {
    _marker: PhantomData<F>
}

impl<F: SmallField> GateConfigurationHolder<F> for DummyGateConfigurationHolder<F> {
    fn is_gate_allowed<G: Gate<F>>(&self) -> bool {
        true
    }

    fn is_type_id_included(&self, _type_id: std::any::TypeId) -> bool {
        todo!()
    }

    fn add_gate<G: Gate<F>, T: 'static + Send + Sync + Clone>(
        self,
        _placement_strategy: circuit_definitions::boojum::cs::traits::gate::GatePlacementStrategy,
        _params: <<G as Gate<F>>::Evaluator as GateConstraintEvaluator<F>>::UniqueParameterizationParams,
        _aux: T,
    ) -> (circuit_definitions::boojum::cs::GateTypeEntry<F, G, T>, Self) {
        todo!()
    }

    fn get_params<G: Gate<F>>(
        &self,
    ) -> Option<
        <<G as Gate<F>>::Evaluator as GateConstraintEvaluator<F>>::UniqueParameterizationParams,
    > {
        todo!()
    }

    fn placement_strategy_for_type_id(&self, _type_id: std::any::TypeId) -> Option<circuit_definitions::boojum::cs::traits::gate::GatePlacementStrategy> {
        todo!()
    }

    fn gather_row_finalization_functions<CS: ConstraintSystem<F>>(
        &self,
        _dst: &mut Vec<circuit_definitions::boojum::cs::traits::gate::GateRowCleanupFunction<CS>>,
    ) {
        todo!()
    }

    fn gather_columns_finalization_functions<CS: ConstraintSystem<F>>(
        &self,
        _dst: &mut Vec<circuit_definitions::boojum::cs::traits::gate::GateColumnsCleanupFunction<CS>>,
    ) {
        todo!()
    }

    fn get_tooling<G: Gate<F>>(&self) -> Option<&G::Tools> {
        todo!()
    }

    fn get_tooling_mut<G: Gate<F>>(&mut self) -> Option<&mut G::Tools> {
        todo!()
    }

    fn get_aux_data<G: Gate<F>, T: 'static + Send + Sync + Clone>(&self) -> Option<&T> {
        todo!()
    }

    fn get_aux_data_mut<G: Gate<F>, T: 'static + Send + Sync + Clone>(&mut self) -> Option<&mut T> {
        todo!()
    }
}

impl<
        F: SmallField,
    > ConstraintSystem<F> for CSDummyImplementation<F>
{
    type Config = DummyCSConfig;
    type WitnessSource = NullCircuitResolver<F, <DummyCSConfig as CSConfig>::ResolverConfig>;
    type GatesConfig = DummyGateConfigurationHolder<F>;
    type StaticToolbox = (Tool<ConstantToVariableMappingToolMarker, ConstantToVariableMappingTool<F>>, ());

    #[inline(always)]
    fn get_gates_config(&self) -> &Self::GatesConfig {
        unimplemented!();
    }

    #[inline(always)]
    fn get_gates_config_mut(&mut self) -> &mut Self::GatesConfig {
        unimplemented!();
    }

    #[inline(always)]
    fn get_static_toolbox(&self) -> &Self::StaticToolbox {
        unimplemented!();
    }

    #[inline(always)]
    fn get_static_toolbox_mut(&mut self) -> &mut Self::StaticToolbox {
        &mut self.toolbox
    }

    // for 1 variable
    #[inline]
    fn alloc_variable_without_value(&mut self) -> Variable {
        let var = Variable::from_variable_index(self.next_available_place_idx);
        self.next_available_place_idx += 1;

        var
    }
    #[inline]
    fn alloc_multiple_variables_without_values<const N: usize>(&mut self) -> [Variable; N] {
        debug_assert!(N < u32::MAX as usize);
        let current_idx = self.next_available_place_idx;
        self.next_available_place_idx += N as u64;

        let result: [Variable; N] =
            std::array::from_fn(|i| Variable::from_variable_index(current_idx + (i as u64)));

        result
    }
    #[inline]
    fn alloc_witness_without_value(&mut self) -> Witness {
        unimplemented!();
    }
    #[inline]
    fn alloc_multiple_witnesses_without_values<const N: usize>(&mut self) -> [Witness; N] {
        unimplemented!();
    }

    #[inline]
    fn set_values<const N: usize>(&mut self, places: &[Place; N], values: [F; N]) {
        for (i, place) in places.iter().enumerate() {
            self.storage.insert(*place, values[i]);
        }
    }

    #[inline]
    fn set_values_with_dependencies<
        const INS: usize,
        const OUTS: usize,
        FN: FnOnce([F; INS]) -> [F; OUTS] + 'static + Send + Sync,
    >(
        &mut self,
        dependencies: &[Place; INS],
        outputs: &[Place; OUTS],
        value_fn: FN,
    ) {
        let get_value = |place| {
            let wit = self.get_value(place);
    
            if let CSWitnessValues::Ready(x) = wit {
                return x[0];
            } else {
                unreachable!();
            }
        };

        let ins = dependencies.map(|x| get_value(x));
        let outputs_values = value_fn(ins);
        self.set_values(outputs, outputs_values);
    }

    #[track_caller]
    #[inline]
    fn set_values_with_dependencies_vararg<
        FN: FnOnce(&[F], &mut DstBuffer<'_, '_, F>) + 'static + Send + Sync,
    >(
        &mut self,
        dependencies: &[Place],
        outputs: &[Place],
        value_fn: FN,
    ) {
        let get_value = |place| {
            let wit = self.get_value(place);
    
            if let CSWitnessValues::Ready(x) = wit {
                return x[0];
            } else {
                unreachable!();
            }
        };

        let ins: Vec<_> = dependencies.iter().map(|x| get_value(*x)).collect();
        let mut outputs_values = vec![];
        value_fn(&ins, &mut DstBuffer::Vector(&mut outputs_values));
        
        for (output, value) in outputs.iter().zip(outputs_values) {
            self.set_values(&[*output], [value])
        }
    }

    // Getters
    #[inline]
    fn get_value(&self, place: Place) -> CSWitnessValues<F, 1, Self::WitnessSource> {
        let res = self.storage.get(&place);

        if res.is_some() {
            return CSWitnessValues::Ready([*res.unwrap()]);
        } else {
            unreachable!();
        }
    }

    #[inline]
    fn get_value_for_multiple<const N: usize>(
        &self,
        _for_places: [Place; N],
    ) -> CSWitnessValues<F, N, Self::WitnessSource> {
        unimplemented!();
    }

    // Public input
    #[inline]
    fn set_public(&mut self, _column: usize, _row: usize) {
        unimplemented!();
    }

    // Gate tooling
    #[inline]
    fn add_dynamic_tool<M: 'static + Send + Sync, TT: GateTool>(&mut self, tool: TT) {
        let marker_id = std::any::TypeId::of::<M>();
        let type_id = std::any::TypeId::of::<TT>();
        let as_box_any = Box::new(tool) as Box<dyn std::any::Any + Send + Sync + 'static>;
        let existing = self.dynamic_tools.insert(marker_id, (type_id, as_box_any));
        assert!(existing.is_none());
    }
    #[inline]
    fn get_dynamic_tool<M: 'static + Send + Sync, TT: GateTool>(&self) -> Option<&TT> {
        let marker_id = std::any::TypeId::of::<M>();
        let type_id = std::any::TypeId::of::<TT>();
        let (expected_type_id, as_any_ref) = self
            .dynamic_tools
            .get(&marker_id)
            .map(|el| (&el.0, &el.1))
            .unzip();
        if let Some(expected_type_id) = expected_type_id {
            if expected_type_id != &type_id {
                panic!(
                    "Trying to get tooling for marker {} with mismathing type",
                    std::any::type_name::<M>()
                );
            }
        }
        as_any_ref.map(|el| {
            el.downcast_ref().expect(&format!(
                "must downcast to proper tool type for type ID {:?} and marker {}",
                type_id,
                std::any::type_name::<M>(),
            ))
        })
    }
    #[inline]
    fn get_dynamic_tool_mut<M: 'static + Send + Sync, TT: GateTool>(&mut self) -> Option<&mut TT> {
        let marker_id = std::any::TypeId::of::<M>();
        let type_id = std::any::TypeId::of::<TT>();
        let (expected_type_id, as_any_ref) = self
            .dynamic_tools
            .get_mut(&marker_id)
            .map(|el| (&mut el.0, &mut el.1))
            .unzip();
        if let Some(expected_type_id) = expected_type_id {
            if expected_type_id != &type_id {
                panic!(
                    "Trying to get tooling for marker {} with mismathing type",
                    std::any::type_name::<M>()
                );
            }
        }
        as_any_ref.map(|el| {
            el.downcast_mut().expect(&format!(
                "must downcast to proper tool type for type ID {:?} and marker {}",
                type_id,
                std::any::type_name::<M>(),
            ))
        })
    }
    #[inline]
    fn take_dynamic_tool<M: 'static + Send + Sync, TT: GateTool>(&mut self) -> Option<TT> {
        unimplemented!();
    }
    #[inline]
    fn get_params(&self) -> CSGeometry {
        unimplemented!();
    }
    #[inline]
    fn get_lookup_params(&self) -> LookupParameters {
        unimplemented!();
    }

    #[inline]
    fn gate_is_allowed<G: Gate<F>>(&self) -> bool {
        true
    }

    #[inline]
    fn get_gate_params<G: Gate<F>>(
        &self,
    ) -> <G::Evaluator as GateConstraintEvaluator<F>>::UniqueParameterizationParams {
        unimplemented!();
    }

    #[inline]
    fn next_available_row(&self) -> usize {
        unimplemented!();
    }
    #[inline]
    fn place_variable(&mut self, _var: Variable, _row: usize, _column: usize) {
        unimplemented!();
    }
    #[inline]
    fn place_constants<const N: usize>(
        &mut self,
        _gate_constants: &[F; N],
        _row: usize,
        _offset: usize,
    ) {
        unimplemented!();
    }
    #[inline]
    fn place_witness(&mut self, _witness: Witness,_row: usize, _column: usize) {
        unimplemented!();
    }
    #[inline]
    fn place_gate<G: Gate<F>>(&mut self, _gate: &G, _row: usize) {
        unimplemented!();
    }

    #[inline]
    fn place_variable_specialized<G: Gate<F>>(
        &mut self,
        _var: Variable,
        _repetition: usize,
        _row: usize,
        _column: usize,
    ) {
        unimplemented!();
    }
    #[inline]
    fn place_witness_specialized<G: Gate<F>>(
        &mut self,
        _witness: Witness,
        _repetition: usize,
        _row: usize,
        _column: usize,
    ) {
        unimplemented!();
    }
    #[inline(always)]
    fn place_gate_specialized<G: Gate<F>>(&mut self, _gate: &G, _repetition: usize, _row: usize) {
        unimplemented!();
    }
    #[inline]
    fn place_constants_specialized<G: Gate<F>, const N: usize>(
        &mut self,
        _constants: &[F; N],
        _repetition: usize,
        _row: usize,
        _offset: usize,
    ) {
        unimplemented!();
    }
    #[inline]
    fn place_multiple_variables_into_row_specialized<G: Gate<F>, const N: usize>(
        &mut self,
        _vars: &[Variable; N],
        _repetition: usize,
        _row: usize,
        _starting_column: usize,
    ) {
        unimplemented!();
    }

    fn perform_lookup<const KEYS: usize, const VALUES: usize>(
        &mut self,
        table_id: u32,
        keys: &[Variable; KEYS],
    ) -> [Variable; VALUES]
    where
        [(); KEYS + VALUES]:,
    {
        if table_id != 0 {
            unimplemented!();
        }

        // BINARYOP "lookup"
        let get_value = |variable| {
            let wit = self.get_value(Place::from_variable(variable));
    
            if let CSWitnessValues::Ready(x) = wit {
                return x[0];
            } else {
                unreachable!();
            }
        };

        let key_0 = get_value(keys[0]);
        let key_1 = get_value(keys[1]);

        let a = key_0.as_u64_reduced() as u8;
        let b = key_1.as_u64_reduced() as u8;

        let xor_result = a ^ b;
        let or_result = a | b;
        let and_result = a & b;
        let value = (xor_result as u64) << 32 | (or_result as u64) << 16 | (and_result as u64);
        
        let var = self.alloc_single_variable_from_witness(F::from_u64_unchecked(value));
        [var; VALUES]
        
    }

    fn enforce_lookup<const N: usize>(&mut self, _table_id: u32,_keys_and_valuess: &[Variable; N]) {
        unimplemented!();
    }

    fn place_multiple_variables_into_row<const N: usize>(
        &mut self,
        _var: &[Variable; N],
        _row: usize,
        _starting_column: usize,
    ) {
        unimplemented!();
    }

    // Lookup table related things
    fn add_lookup_table<M: 'static + Send + Sync, const N: usize>(
        &mut self,
        _table: LookupTable<F, N>,
    ) -> u32
    where
        LookupTable<F, N>: Wrappable<F>,
    {
        unimplemented!();
    }
    #[inline]
    fn get_table_id_for_marker<M: 'static + Send + Sync>(&self) -> Option<u32> {
        self.lookup_table_marker_into_id
            .get(&std::any::TypeId::of::<M>())
            .copied()
    }
    #[inline]
    fn get_table(&self, _table_num: u32) -> std::sync::Arc<LookupTableWrapper<F>> {
        unimplemented!();
    }
}
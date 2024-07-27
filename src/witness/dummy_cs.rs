use std::{collections::HashMap, marker::PhantomData};

use circuit_definitions::boojum::{config::{CSConfig, CSResolverConfig, ProvingCSConfig}, cs::{gates::{ConstantToVariableMappingTool, ConstantToVariableMappingToolMarker, Poseidon2RoundFunctionFlattenedEvaluator}, implementations::lookup_table::{LookupTable, LookupTableWrapper, Wrappable}, traits::{cs::{ConstraintSystem, DstBuffer}, evaluator::GateConstraintEvaluator, gate::Gate}, CSGeometry, GateConfigurationHolder, GateTool, LookupParameters, Place, StaticToolboxHolder, Tool, Variable, Witness}, dag::{CSWitnessValues, CircuitResolver, DefaultCircuitResolver, NullCircuitResolver}, field::{self, SmallField}};

pub struct CSDummyImplementation<F: 'static + Send + Sync> {
    _marker: PhantomData<F>,
    storage: HashMap<Place, F>,
    next_available_place_idx: u64
}

impl<F: 'static + Send + Sync> CSDummyImplementation<F> {
    pub fn new() -> Self {
        Self {
            _marker: PhantomData,
            storage: Default::default(),
            next_available_place_idx: 0
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
    type Config = ProvingCSConfig;
    type WitnessSource = NullCircuitResolver<F, <ProvingCSConfig as CSConfig>::ResolverConfig>;
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
        unimplemented!();
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
        unimplemented!();
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
        _dependencies: &[Place; INS],
        _outputs: &[Place; OUTS],
        _value_fn: FN,
    ) {
        unimplemented!();
    }

    #[track_caller]
    #[inline]
    fn set_values_with_dependencies_vararg<
        FN: FnOnce(&[F], &mut DstBuffer<'_, '_, F>) + 'static + Send + Sync,
    >(
        &mut self,
        _dependencies: &[Place],
        _outputs: &[Place],
        _value_fn: FN,
    ) {
        unimplemented!();
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
    fn add_dynamic_tool<M: 'static + Send + Sync, TT: GateTool>(&mut self, _tool: TT) {
        unimplemented!();
    }
    #[inline]
    fn get_dynamic_tool<M: 'static + Send + Sync, TT: GateTool>(&self) -> Option<&TT> {
        unimplemented!();
    }
    #[inline]
    fn get_dynamic_tool_mut<M: 'static + Send + Sync, TT: GateTool>(&mut self) -> Option<&mut TT> {
        unimplemented!();
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
        false
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
        _table_id: u32,
        _keys: &[Variable; KEYS],
    ) -> [Variable; VALUES]
    where
        [(); KEYS + VALUES]:,
    {
        unimplemented!();
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
        unimplemented!();
    }
    #[inline]
    fn get_table(&self, _table_num: u32) -> std::sync::Arc<LookupTableWrapper<F>> {
        unimplemented!();
    }
}
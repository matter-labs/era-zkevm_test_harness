use super::*;

pub struct CompressionMode3;

impl ProofCompressionFunction for CompressionMode3 {
    // no PoW from the previous step
    type PreviousLayerPoW = NoPow;

    // no PoW on this step too
    type ThisLayerPoW = NoPow;
    type ThisLayerHasher = H;
    type ThisLayerTranscript = TR;

    fn this_layer_transcript_parameters(
    ) -> <Self::ThisLayerTranscript as Transcript<F>>::TransciptParameters {
        ();
    }

    fn description_for_compression_step() -> String {
        "Compression mode 3: no lookup, just enough copiable width, moderate-high LDE factor, Poseidon gate"
        .to_string()
    }

    fn size_hint_for_compression_step() -> (usize, usize) {
        (1 << 12, 1 << 22)
    }

    fn geometry_for_compression_step() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 68,
            // num_witness_columns: 0,
            num_witness_columns: 62,
            num_constant_columns: 4,
            max_allowed_constraint_degree: 8,
        }
    }

    fn lookup_parameters_for_compression_step() -> LookupParameters {
        LookupParameters::NoLookup
    }

    fn configure_builder_for_compression_step<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        let builder = ConstantsAllocatorGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        // let builder = BooleanConstraintGate::configure_builder(
        //     builder,
        //     GatePlacementStrategy::UseGeneralPurposeColumns,
        // );
        // This reduces quotient complexity
        let builder = BoundedBooleanConstraintGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            10,
        );
        let builder =
            R::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);
        let builder = ZeroCheckGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
            true,
        );
        let builder = FmaGateInBaseFieldWithoutConstant::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = FmaGateInExtensionWithoutConstant::<F, EXT>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = SelectionGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ParallelSelectionGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ConditionalSwapGate::<4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = PublicInputGate::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder = ReductionGate::<_, 4>::configure_builder(
            builder,
            GatePlacementStrategy::UseGeneralPurposeColumns,
        );
        let builder =
            NopGate::configure_builder(builder, GatePlacementStrategy::UseGeneralPurposeColumns);

        builder
    }

    fn proof_config_for_compression_step() -> ProofConfig {
        ProofConfig {
            fri_lde_factor: 1024,
            merkle_tree_cap_size: 16,
            fri_folding_schedule: None,
            security_level: crate::L1_SECURITY_BITS,
            pow_bits: 0,
        }
    }

    fn previous_step_builder_for_compression<CS: ConstraintSystem<F> + 'static>(
    ) -> Box<dyn ErasedBuilderForRecursiveVerifier<GoldilocksField, EXT, CS>> {
        use crate::circuit_definitions::aux_layer::compression::CompressionMode2CircuitBuilder;
        CompressionMode2CircuitBuilder::dyn_recursive_verifier_builder::<EXT, CS>()
    }
}

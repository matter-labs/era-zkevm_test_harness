use super::*;

pub struct CompressionMode1ForWrapper;

impl ProofCompressionFunction for CompressionMode1ForWrapper {
    // no PoW from the previous step
    type PreviousLayerPoW = NoPow;

    // no PoW on this step too
    type ThisLayerPoW = NoPow;
    type ThisLayerHasher = CompressionTreeHasherForWrapper;
    type ThisLayerTranscript = CompressionTranscriptForWrapper;

    fn this_layer_transcript_parameters(
    ) -> <Self::ThisLayerTranscript as Transcript<F>>::TransciptParameters {
        ();
    }

    fn description_for_compression_step() -> String {
        "Compression mode 1: no lookup, just enough copiable width, moderate LDE factor, still special boolean column, and Poseidon2 gate"
        .to_string()
    }

    fn size_hint_for_compression_step() -> (usize, usize) {
        (1 << 16, 1 << 24)
    }

    fn geometry_for_compression_step() -> CSGeometry {
        CSGeometry {
            num_columns_under_copy_permutation: 52,
            num_witness_columns: 78,
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
        let builder = BooleanConstraintGate::configure_builder(
            builder,
            GatePlacementStrategy::UseSpecializedColumns {
                num_repetitions: 1,
                share_constants: false,
            },
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
            fri_lde_factor: 2,
            merkle_tree_cap_size: 16,
            fri_folding_schedule: None,
            security_level: crate::L1_SECURITY_BITS,
            pow_bits: 0,
        }
    }

    fn previous_step_builder_for_compression<CS: ConstraintSystem<F> + 'static>(
    ) -> Box<dyn ErasedBuilderForRecursiveVerifier<GoldilocksField, EXT, CS>> {
        SchedulerCircuitBuilder::<Self::PreviousLayerPoW>::dyn_recursive_verifier_builder::<EXT, CS>(
        )
    }
}

use std::alloc::Global;

use self::recursion_layer::circuit_def::*;

use super::*;

use crate::boojum::algebraic_props::round_function::AbsorptionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::cs::implementations::pow::NoPow;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::cs::implementations::transcript::Transcript;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::field::goldilocks::GoldilocksField;
use crate::circuit_definitions::implementations::verifier::VerificationKeyCircuitGeometry;
use derivative::*;

use crate::boojum::config::SetupCSConfig;
use crate::boojum::cs::traits::circuit::*;
use crate::circuit_definitions::gates::*;
use crate::circuit_definitions::traits::circuit::ErasedBuilderForRecursiveVerifier;
use crate::zkevm_circuits::boojum::cs::implementations::prover::ProofConfig;

type F = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorptionModeOverwrite>;

pub type FRIProofVerificationPrecompileTranscript = GoldilocksPoisedon2Transcript;
pub type FRIProofVerificationPrecompilePoW = NoPow;

// we define a formal circuit builder for what's expected to be user's proofs. Even though user's
// gates can be anything, it's always possible to perform few compression steps to match the required format

pub fn proof_config_for_fri_proofs_precompile() -> ProofConfig {
    ProofConfig {
        fri_lde_factor: 2,
        merkle_tree_cap_size: 1,
        fri_folding_schedule: None,
        security_level: crate::L1_SECURITY_BITS * 2, // if one not uses conjecture it's exactly x2
        pow_bits: 0,
    }
}

pub const FRI_PROOF_VERIFICATION_PRECOMPILE_DOMAIN_SIZE: u64 = 1u64 << 20;

pub fn verification_key_geometry_for_fri_proofs_precompile() -> VerificationKeyCircuitGeometry {
    let proof_config = proof_config_for_fri_proofs_precompile();

    // we use CS as our calculator
    let geometry = FormalFRIProofCircuit::geometry();
    let (max_trace_len, num_vars) = (FRI_PROOF_VERIFICATION_PRECOMPILE_DOMAIN_SIZE as usize, 1);
    let builder_impl =
        CsReferenceImplementationBuilder::<F, F, SetupCSConfig>::new(geometry, max_trace_len);
    let cs_builder = new_builder::<_, F>(builder_impl);
    let builder = FormalFRIProofCircuit::configure_builder(cs_builder);
    let mut cs = builder.build(num_vars);
    // reserve enough fixed locations for public inputs
    for _ in 0..INPUT_OUTPUT_COMMITMENT_LENGTH {
        PublicInputGate::reserve_public_input_location(&mut cs);
    }
    let assembly = cs.into_assembly_base::<Global>();
    let selectors_placement = assembly.compute_selectors_and_constants_placement();
    // same logic as in the setup
    let (max_constraint_contribution_degree, number_of_constant_polys_for_general_purpose_gates) =
        selectors_placement.compute_stats();
    let public_inputs = assembly.public_inputs;

    let extra_polys_for_selectors =
        number_of_constant_polys_for_general_purpose_gates - geometry.num_constant_columns;

    let quotient_degree_from_constraits = if max_constraint_contribution_degree > 0 {
        max_constraint_contribution_degree - 1
    } else {
        0
    };

    VerificationKeyCircuitGeometry {
        parameters: FormalFRIProofCircuit::geometry(),
        lookup_parameters: FormalFRIProofCircuit::lookup_parameters(),
        domain_size: FRI_PROOF_VERIFICATION_PRECOMPILE_DOMAIN_SIZE,
        total_tables_len: 0, // no lookup
        public_inputs_locations: public_inputs,
        extra_constant_polys_for_selectors: extra_polys_for_selectors,
        table_ids_column_idxes: vec![],
        quotient_degree: quotient_degree_from_constraits,
        selectors_placement: selectors_placement,
        fri_lde_factor: proof_config.fri_lde_factor,
        cap_size: proof_config.merkle_tree_cap_size,
    }
}

#[derive(Derivative, serde::Serialize, serde::Deserialize)]
#[derivative(Clone, Debug(bound = ""))]
#[serde(bound = "")]
pub struct FormalFRIProofCircuit;

impl crate::boojum::cs::traits::circuit::CircuitBuilder<F> for FormalFRIProofCircuit {
    fn geometry() -> CSGeometry {
        geometry_for_recursion_step()
    }

    fn lookup_parameters() -> LookupParameters {
        lookup_parameters_recursion_step()
    }

    fn configure_builder<
        T: CsBuilderImpl<F, T>,
        GC: GateConfigurationHolder<F>,
        TB: StaticToolboxHolder,
    >(
        builder: CsBuilder<T, F, GC, TB>,
    ) -> CsBuilder<T, F, impl GateConfigurationHolder<F>, impl StaticToolboxHolder> {
        configure_builder_recursion_step(builder)
    }
}

pub fn verifier_builder_for_fri_proofs_precompile<CS: ConstraintSystem<F> + 'static>(
) -> Box<dyn ErasedBuilderForRecursiveVerifier<F, EXT, CS>> {
    CircuitBuilderProxy::<F, FormalFRIProofCircuit>::dyn_recursive_verifier_builder()
}

pub fn transcript_params_for_fri_proofs_precompile() -> <TR as Transcript<F>>::TransciptParameters {
    ()
}

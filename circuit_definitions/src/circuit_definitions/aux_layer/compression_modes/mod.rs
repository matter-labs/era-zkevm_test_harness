use super::*;

use crate::boojum::algebraic_props::round_function::AbsorbtionModeOverwrite;
use crate::boojum::algebraic_props::sponge::GoldilocksPoseidon2Sponge;
use crate::boojum::cs::implementations::pow::NoPow;
use crate::boojum::cs::implementations::transcript::GoldilocksPoisedon2Transcript;
use crate::boojum::cs::implementations::transcript::Transcript;
use crate::boojum::field::goldilocks::GoldilocksExt2;
use crate::boojum::field::goldilocks::GoldilocksField;
use crate::boojum::gadgets::recursion::circuit_pow::*;
use crate::boojum::gadgets::recursion::recursive_transcript::*;
use crate::boojum::gadgets::recursion::recursive_tree_hasher::CircuitGoldilocksPoseidon2Sponge;
use crate::circuit_definitions::gates::*;
use crate::circuit_definitions::implementations::pow::PoWRunner;
use crate::circuit_definitions::implementations::proof::Proof;
use crate::circuit_definitions::recursion_layer::scheduler::SchedulerCircuitBuilder;
use crate::circuit_definitions::traits::circuit::ErasedBuilderForRecursiveVerifier;
use crate::circuit_definitions::traits::gate::GatePlacementStrategy;
use crate::zkevm_circuits::recursion::compression::*;
use derivative::*;
use zkevm_circuits::boojum::cs::implementations::prover::ProofConfig;
use zkevm_circuits::boojum::cs::oracle::TreeHasher;
use crate::circuit_definitions::aux_layer::compression::ProofCompressionFunction;

type F = GoldilocksField;
type P = GoldilocksField;
type TR = GoldilocksPoisedon2Transcript;
type R = Poseidon2Goldilocks;
type CTR = CircuitAlgebraicSpongeBasedTranscript<GoldilocksField, 8, 12, 4, R>;
type EXT = GoldilocksExt2;
type H = GoldilocksPoseidon2Sponge<AbsorbtionModeOverwrite>;
type RH = CircuitGoldilocksPoseidon2Sponge;

pub mod mode_1;
pub mod mode_2;
pub mod mode_3;
pub mod mode_to_l1;

pub use self::mode_1::*;
pub use self::mode_2::*;
pub use self::mode_3::*;
pub use self::mode_to_l1::*;
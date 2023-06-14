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

// We should balance the final verification cost that would be a complex function of:
// - rate. It decreases number of queries, but increases query depth. Although in practice we
// always win, e.g. for before-extension depth 16, if we aim for 80 bits of security, and use LDE of 2^5
// we do 16 queries of depth 21 (assuming cap at 64, it's ~240 hashes), and with LDE of 2^8 we do 10 queries
// of depth 24 (assuming cap at 64, it's 180 hashes)
// - circuit surface area. If we have circuit 2x more narrow, and 2x longer we have +1 to query depth (don't forget to
// multiply by number of queries), but we also have 2x smaller number of elements in the leaf (also mul by number of queries, so we can just compare
// one against another)
// - number of columns under copy-permutation. Every such column increases leaf size for setup by 1, and also roughly 2 columns per 8 copied columns
// in stage 2 of the proof. E.g if we have a circuit with 40 copiable + 90 non-copiable of size 2^14, and one with 48 copiable of 2^16,
// then we would have witness of 130 in leafs (17 round functions) in witness, 5 round functions from setup, 5 from stage 2 - so 27 round functions
// in leafs. For 48 x 2^16 case we have 6 round functions in leafs, 6 in setup, and 6 from stage 2 - 18 in total. For that we pay with extra depth
// in each of those oracles, so +6 more. We still marginally win, but also usually we have "simpler" gates in this case, so we have
// less terms in quotient

pub mod mode_1;
pub mod mode_2;
pub mod mode_3;
pub mod mode_4;
pub mod mode_to_l1;

pub use self::mode_1::*;
pub use self::mode_2::*;
pub use self::mode_3::*;
pub use self::mode_4::*;
pub use self::mode_to_l1::*;
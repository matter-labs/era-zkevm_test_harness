use super::*;
use crate::ethereum_types::U256;

use crate::witness::individual_circuits::memory_related::decommit_code::decommitter_memory_queries_amount;
use crate::witness::individual_circuits::memory_related::ecrecover::ecrecover_memory_queries_amount;
use crate::witness::individual_circuits::memory_related::keccak256_round_function::keccak256_memory_queries_amount;
use crate::witness::individual_circuits::memory_related::secp256r1_verify::secp256r1_memory_queries_amount;
use crate::witness::individual_circuits::memory_related::sha256_round_function::sha256_memory_queries_amount;
use crate::zk_evm::aux_structures::DecommittmentQuery;
use crate::zk_evm::aux_structures::LogQuery as LogQuery_;
use crate::zk_evm::zk_evm_abstractions::precompiles::ecrecover::ECRecoverRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::keccak256::Keccak256RoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::secp256r1_verify::Secp256r1VerifyRoundWitness;
use crate::zk_evm::zk_evm_abstractions::precompiles::sha256::Sha256RoundWitness;

pub(crate) mod decommit_code;
pub(crate) mod ecrecover;
pub(crate) mod keccak256_round_function;
pub(crate) mod ram_permutation;
pub(crate) mod secp256r1_verify;
pub(crate) mod sha256_round_function;
pub(crate) mod sort_decommit_requests;

pub(crate) fn amount_of_implicit_memory_queries(
    deduplicated_decommit_requests_with_data: &Vec<(DecommittmentQuery, Vec<U256>)>,
    ecrecover_witnesses: &Vec<(u32, LogQuery_, ECRecoverRoundWitness)>,
    keccak_round_function_witnesses: &Vec<(u32, LogQuery_, Vec<Keccak256RoundWitness>)>,
    secp256r1_verify_witnesses: &Vec<(u32, LogQuery_, Secp256r1VerifyRoundWitness)>,
    sha256_round_function_witnesses: &Vec<(u32, LogQuery_, Vec<Sha256RoundWitness>)>,
) -> usize {
    decommitter_memory_queries_amount(deduplicated_decommit_requests_with_data)
        + ecrecover_memory_queries_amount(ecrecover_witnesses)
        + keccak256_memory_queries_amount(keccak_round_function_witnesses)
        + secp256r1_memory_queries_amount(secp256r1_verify_witnesses)
        + sha256_memory_queries_amount(sha256_round_function_witnesses)
}

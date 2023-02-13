#![feature(allocator_api)]
#![feature(const_trait_impl)]
#![feature(const_mut_refs)]
#![feature(const_refs_to_cell)]
#![feature(const_for)]
#![feature(const_swap)]
#![feature(inline_const)]
#![feature(const_intoiterator_identity)]
#![feature(slice_swap_unchecked)]
#![feature(const_option)]
#![feature(const_eval_limit)]
#![const_eval_limit = "100000000"]
#![feature(const_slice_index)]
#![feature(core_intrinsics)]
#![feature(const_eval_select)]
#![feature(get_mut_unchecked)]
#![feature(array_chunks)]
#![feature(stmt_expr_attributes)]
#![feature(vec_into_raw_parts)]
#![feature(iter_collect_into)]
#![feature(strict_provenance)]
#![feature(ready_into_inner)]
#![feature(unboxed_closures)]
#![feature(portable_simd)]
#![feature(fn_traits)]
#![feature(generic_const_exprs)]
#![feature(const_type_id)]
#![feature(const_type_name)]
#![feature(iter_array_chunks)]
#![feature(iter_next_chunk)]

#![allow(unused_imports)]

pub use blake2::Blake2s256;

pub mod encodings;
pub mod entry_point;
pub mod utils;
pub mod witness;
pub mod geometry_config;
pub use zk_evm::ethereum_types;

use self::utils::*;

pub mod external_calls;
pub mod toolset;

// pub mod abstract_zksync_circuit;
// pub mod circuit_limit_estimator;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

// #[cfg(test)]
pub(crate) mod tests;

#![feature(array_chunks)]

pub mod geometry_config;
pub mod proof;
pub mod sort_storage_access;
pub mod toolset;

pub mod commitments;
pub mod utils;

pub use circuit_encodings::boojum;

pub const INITIAL_MONOTONIC_CYCLE_COUNTER: u32 = 1024;

// Export parameters needed for 4844 blobs.
pub use circuit_encodings::zkevm_circuits::eip_4844::input::{
    BLOB_CHUNK_SIZE, ELEMENTS_PER_4844_BLOCK,
};
pub use circuit_encodings::zkevm_circuits::scheduler::block_header::MAX_4844_BLOBS_PER_BLOCK;

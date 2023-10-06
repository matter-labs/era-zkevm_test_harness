use super::*;

pub(crate) const CRS_FILE_ENV_VAR: &str = "CRS_FILE";

/// Just to check if the file and environment variable are not forgotten
pub(crate) fn check_trusted_setup_file_existace() {
    let crs_file_str = std::env::var(CRS_FILE_ENV_VAR).expect("crs file env var");
    let crs_file_path = std::path::Path::new(&crs_file_str);
    let _crs_file = std::fs::File::open(&crs_file_path).expect("crs file to open");
}

/// Uploads trusted setup file to the RAM
pub fn get_trusted_setup() -> Crs<Bn256, CrsForMonomialForm> {
    let crs_file_str = std::env::var(CRS_FILE_ENV_VAR).expect("crs file env var");
    let crs_file_path = std::path::Path::new(&crs_file_str);
    let crs_file = std::fs::File::open(&crs_file_path).expect("crs file to open");
    Crs::read(&crs_file).expect("crs file for bases")
}

/// Computes wrapper public input from stark one
/// Stark PI consist of 4 7-byte elements and we just want to concatenate them
pub fn compress_stark_pi_to_snark_pi(
    stark_pi: [GoldilocksField; NUM_SCHEDULER_PUBLIC_INPUTS],
) -> Fr {
    let chunk_bit_size = (GoldilocksField::CAPACITY_BITS / 8) * 8;
    assert!(
        stark_pi.len() * chunk_bit_size <= Fr::CAPACITY as usize,
        "scalar field capacity is not enough to fit all public inputs"
    );

    let mut coeff = Fr::one();
    let mut shift = <Fr as PrimeField>::Repr::from(1);
    shift.shl(chunk_bit_size as u32);
    let shift = Fr::from_repr(shift).unwrap();

    let mut result = Fr::zero();
    for chunk in stark_pi.iter().rev() {
        let mut chunk_fr =
            Fr::from_repr(<Fr as PrimeField>::Repr::from(chunk.as_u64_reduced())).unwrap();
        chunk_fr.mul_assign(&coeff);
        result.add_assign(&chunk_fr);
        coeff.mul_assign(&shift);
    }

    result
}

pub(crate) fn get_proof_for_previous_circuit<DS: SetupDataSource + BlockDataSource>(
    source: &DS,
    circuit_type: u8,
) -> SourceResult<ZkSyncCompressionProof> {
    match circuit_type {
        1 => source.get_scheduler_proof().map(|proof| proof.into_inner()),
        circuit_type => source
            .get_compression_proof(circuit_type - 1)
            .map(|proof| proof.into_inner()),
    }
}

pub(crate) fn get_vk_for_previous_circuit<DS: SetupDataSource + BlockDataSource>(
    source: &DS,
    circuit_type: u8,
) -> SourceResult<ZkSyncCompressionVerificationKey> {
    match circuit_type {
        1 => source
            .get_recursion_layer_vk(ZkSyncRecursionLayerStorageType::SchedulerCircuit as u8)
            .map(|vk| vk.into_inner()),
        circuit_type => source
            .get_compression_vk(circuit_type - 1)
            .map(|vk| vk.into_inner()),
    }
}

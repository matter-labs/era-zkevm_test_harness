use sync_vm::franklin_crypto::plonk::circuit::utils::u64_to_fe;
use sync_vm::traits::CSWitnessable;
use sync_vm::utils::compute_shifts;
use zk_evm::aux_structures::LogQuery;
use zk_evm::ethereum_types::H160;

use crate::utils::{biguint_from_u256, u160_from_address};
use crate::witness::sort_storage_access::LogQueryLikeWithExtendedEnumeration;

use super::*;

use sync_vm::vm::primitives::small_uints::IntoFr;
use sync_vm::vm::vm_state::saved_contract_context::scale_and_accumulate;

// impl<E: Engine> IntoFr<E> for H160 {
//     fn into_fr(self) -> E::Fr {
//         let lowest = u64::from_be_bytes(self.0[0..8].try_into().unwrap());
//         let mid = u64::from_be_bytes(self.0[8..16].try_into().unwrap());
//         let highest = u32::from_be_bytes(self.0[16..20].try_into().unwrap());

//         let mut repr = E::Fr::zero().into_repr();
//         repr.as_mut()[0] = lowest;
//         repr.as_mut()[1] = mid;
//         repr.as_mut()[2] = highest as u32;

//         E::Fr::from_repr(repr).unwrap()
//     }
// }

// // BE order:
// // the whole structure can be placed in five field elements:
// // el0 = [r_w_flag | aux_byte | log_idx | key0 | actor_address]
// // el1 = [trx_idx | key1 | target_address]
// // el2 = [rvalue32 | rvalue31 | rvalue30 | rvalue2 | rvalue1 | rvalue0]
// // el3 = [wvalue32 | wvalue31 | wvalue30 | wvalue2 | wvalue1 | wvalue0]
// // el4 = [target_is_zkporter | is_service | is_revert | wvalue33 | rvalue33 | key3 | key2]

// let shifts = compute_shifts::<E::Fr>();

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.address.inner, shifts[shift]);
// shift += 160;
// lc.add_assign_number_with_coeff(&self.key.inner[0].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.shard_id.inner, shifts[shift]);
// shift += 8;
// lc.add_assign_number_with_coeff(&self.aux_byte.inner, shifts[shift]);
// shift += 8;
// lc.add_assign_boolean_with_coeff(&self.r_w_flag, shifts[shift]);
// shift += 1;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el0 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.key.inner[1].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.key.inner[2].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.key.inner[3].inner, shifts[shift]);
// shift += 64;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el1 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.read_value.inner[0].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.read_value.inner[1].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.read_value.inner[2].inner, shifts[shift]);
// shift += 64;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el2 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.written_value.inner[0].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.written_value.inner[1].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.written_value.inner[2].inner, shifts[shift]);
// shift += 64;
// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);
// let el3 = lc.into_num(cs)?;

// let mut lc = LinearCombination::zero();
// let mut shift = 0;
// lc.add_assign_number_with_coeff(&self.read_value.inner[2].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.written_value.inner[3].inner, shifts[shift]);
// shift += 64;
// lc.add_assign_number_with_coeff(&self.tx_number_in_block.inner, shifts[shift]);
// shift += 16;
// lc.add_assign_number_with_coeff(&self.timestamp.inner, shifts[shift]);
// shift += 32;
// lc.add_assign_boolean_with_coeff(&self.is_service, shifts[shift]);
// shift += 1;
// if with_revert {
//     lc.add_assign_boolean_with_coeff(&self.rollback, shifts[shift]);
// }
// let revert_falg_offset = shifts[shift];
// shift += 1;

// //dbg!(shift);
// assert!(shift <= E::Fr::CAPACITY as usize);

// let el4 = lc.into_num(cs)?;

// Ok(([el0, el1, el2, el3, el4], revert_falg_offset))

use sync_vm::glue::storage_validity_by_grand_product::{
    TimestampedStorageLogRecord, TimestampedStorageLogRecordWitness,
    EXTENDED_TIMESTAMP_ENCODING_ELEMENT, EXTENDED_TIMESTAMP_ENCODING_OFFSET,
};

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 5> for LogQuery {
    fn encoding_witness(&self) -> [<E>::Fr; 5] {
        use crate::utils::*;

        let shifts = compute_shifts::<E::Fr>();

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, u160_from_address(self.address), &shifts, shift);
        shift += 160;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.shard_id, &shifts, shift);
        shift += 8;
        scale_and_accumulate::<E, _>(&mut lc, self.aux_byte, &shifts, shift);
        shift += 8;
        scale_and_accumulate::<E, _>(&mut lc, self.rw_flag, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el0 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[2], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.key.0[3], &shifts, shift);
        shift += 64;
        assert!(shift <= E::Fr::CAPACITY as usize);
        assert_eq!(shift, EXTENDED_TIMESTAMP_ENCODING_OFFSET);
        let el1 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[2], &shifts, shift);
        shift += 64;
        //dbg!(shift);
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el2 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.written_value.0[0], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.written_value.0[1], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.written_value.0[2], &shifts, shift);
        shift += 64;
        assert!(shift <= E::Fr::CAPACITY as usize);
        let el3 = lc;

        let mut lc = E::Fr::zero();
        let mut shift = 0;
        scale_and_accumulate::<E, _>(&mut lc, self.read_value.0[3], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.written_value.0[3], &shifts, shift);
        shift += 64;
        scale_and_accumulate::<E, _>(&mut lc, self.tx_number_in_block, &shifts, shift);
        shift += 16;
        scale_and_accumulate::<E, _>(&mut lc, self.timestamp.0, &shifts, shift);
        shift += 32;
        scale_and_accumulate::<E, _>(&mut lc, self.is_service, &shifts, shift);
        shift += 1;
        scale_and_accumulate::<E, _>(&mut lc, self.rollback, &shifts, shift);
        shift += 1;
        assert!(shift <= E::Fr::CAPACITY as usize);

        let el4 = lc;

        // if self.address.0[19] == 0x02 {
        // dbg!([el0, el1, el2, el3, el4]);
        // }

        [el0, el1, el2, el3, el4]
    }
}

pub type LogQueryWithExtendedEnumeration = LogQueryLikeWithExtendedEnumeration<LogQuery>;

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 5> for LogQueryWithExtendedEnumeration {
    fn encoding_witness(&self) -> [<E>::Fr; 5] {
        let shifts = compute_shifts::<E::Fr>();

        let LogQueryWithExtendedEnumeration {
            raw_query,
            extended_timestamp,
        } = self;

        let mut result =
            <LogQuery as OutOfCircuitFixedLengthEncodable<E, 5>>::encoding_witness(raw_query);

        let mut shift = EXTENDED_TIMESTAMP_ENCODING_OFFSET;
        scale_and_accumulate::<E, _>(
            &mut result[EXTENDED_TIMESTAMP_ENCODING_ELEMENT],
            *extended_timestamp,
            &shifts,
            shift,
        );
        shift += 32;
        assert!(shift <= E::Fr::CAPACITY as usize);

        // dbg!(&result);

        result
    }
}

pub fn comparison_key<E: Engine>(query: &LogQuery) -> [E::Fr; 2] {
    use crate::franklin_crypto::plonk::circuit::bigint::biguint_to_fe;
    use num_bigint::BigUint;

    let mut k0 = BigUint::from(0u64);
    // lowest 192 bits of key
    k0 += BigUint::from(query.key.0[2]);
    k0 <<= 64;
    k0 += BigUint::from(query.key.0[1]);
    k0 <<= 64;
    k0 += BigUint::from(query.key.0[0]);

    // rest of key, address, and shard
    let mut k1 = BigUint::from(0u64);
    k1 += BigUint::from(query.shard_id as u64);
    k1 <<= 160;
    k1 += BigUint::from_bytes_be(&query.address.0);
    k1 <<= 64;
    k1 += BigUint::from(query.key.0[3]);

    [biguint_to_fe::<E::Fr>(k0), biguint_to_fe::<E::Fr>(k1)]
}

pub fn event_comparison_key<E: Engine>(query: &LogQuery) -> E::Fr {
    let mut k0: u64 = query.timestamp.0 as u64;
    k0 <<= 1;
    k0 += query.rollback as u64;

    u64_to_fe(k0)
}

pub type LogQueueSimulator<E> = QueueSimulator<E, LogQuery, 5, 3>;
pub type LogQueueState<E> = QueueIntermediateStates<E, 3, 3>;

pub type LogWithExtendedEnumerationQueueSimulator<E> =
    QueueSimulator<E, LogQueryWithExtendedEnumeration, 5, 3>;
pub type LogWithExtendedEnumerationQueueState<E> = QueueIntermediateStates<E, 3, 3>;

use sync_vm::scheduler::data_access_functions::StorageLogRecord;

pub fn log_query_into_storage_record_witness<E: Engine>(
    query: &LogQuery,
) -> <StorageLogRecord<E> as CSWitnessable<E>>::Witness {
    use sync_vm::scheduler::queues::StorageLogRecordWitness;

    StorageLogRecordWitness {
        address: u160_from_address(query.address),
        key: biguint_from_u256(query.key),
        read_value: biguint_from_u256(query.read_value),
        written_value: biguint_from_u256(query.written_value),
        r_w_flag: query.rw_flag,
        aux_byte: query.aux_byte,
        rollback: query.rollback,
        is_service: query.is_service,
        shard_id: query.shard_id,
        tx_number_in_block: query.tx_number_in_block,
        timestamp: query.timestamp.0,
        _marker: std::marker::PhantomData,
    }
}

pub fn log_query_into_timestamped_storage_record_witness<E: Engine>(
    query: &LogQueryWithExtendedEnumeration,
) -> <TimestampedStorageLogRecord<E> as CSWitnessable<E>>::Witness {
    use sync_vm::scheduler::queues::StorageLogRecordWitness;

    TimestampedStorageLogRecordWitness {
        record: log_query_into_storage_record_witness(&query.raw_query),
        timestamp: query.extended_timestamp,
    }
}

use super::initial_storage_write::CircuitEquivalentReflection;

impl<E: Engine> CircuitEquivalentReflection<E> for LogQuery {
    type Destination = StorageLogRecord<E>;
    fn reflect(&self) -> <Self::Destination as CSWitnessable<E>>::Witness {
        log_query_into_storage_record_witness(self)
    }
}

use super::initial_storage_write::BytesSerializable;

// for purposes of L1 messages
impl BytesSerializable<88> for LogQuery {
    fn serialize(&self) -> [u8; 88] {
        let mut result = [0u8; 88];
        let mut offset = 0;
        result[offset] = self.shard_id;
        offset += 1;
        result[offset] = self.is_service as u8;
        offset += 1;

        let bytes_be = self.tx_number_in_block.to_be_bytes();
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        let bytes_be = self.address.to_fixed_bytes();
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        let mut bytes_be = [0u8; 32];
        self.key.to_big_endian(&mut bytes_be);
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        let mut bytes_be = [0u8; 32];
        self.written_value.to_big_endian(&mut bytes_be);
        result[offset..(offset + bytes_be.len())].copy_from_slice(&bytes_be);
        offset += bytes_be.len();

        assert_eq!(offset, 88);

        result
    }
}

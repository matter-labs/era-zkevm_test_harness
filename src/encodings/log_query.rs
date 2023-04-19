use zk_evm::aux_structures::LogQuery;
use zk_evm::ethereum_types::H160;

use crate::witness::sort_storage_access::LogQueryLikeWithExtendedEnumeration;

use super::*;

pub fn comparison_key<F: SmallField>(query: &LogQuery) -> Key<14> {
    let key = decompose_u256_as_u32x8(query.key);
    let address = decompose_address_as_u32x5(query.address);

    let le_words = [
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        address[0],
        address[1],
        address[2],
        address[3],
        address[4],
        query.shard_id as u32,
    ];

    Key(le_words)
}

pub fn event_comparison_key(query: &LogQuery) -> Key<2> {
    let le_words = [
        query.rollback as u32,
        query.timestamp.0,
    ];

    Key(le_words)
}

// use sync_vm::glue::storage_validity_by_grand_product::{EXTENDED_TIMESTAMP_ENCODING_OFFSET, EXTENDED_TIMESTAMP_ENCODING_ELEMENT, TimestampedStorageLogRecord, TimestampedStorageLogRecordWitness};

use zkevm_circuits::base_structures::log_query::LOG_QUERY_PACKED_WIDTH;

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<F, LOG_QUERY_PACKED_WIDTH> for LogQuery {
    fn encoding_witness(&self) -> [F; LOG_QUERY_PACKED_WIDTH] {
        debug_assert!(F::CAPACITY_BITS >= 56);
        // we decompose "key" and mix it into other limbs because with high probability
        // in VM decomposition of "key" will always exist beforehand

        let mut key_bytes = [0u8; 32];
        self.key.to_little_endian(&mut key_bytes);
        let mut address_bytes = self.address.0;
        address_bytes.reverse();

        let read_value = decompose_u256_as_u32x8(self.read_value);
        let written_value = decompose_u256_as_u32x8(self.written_value);

        // we want to pack tightly, so we "base" our packing on read and written values

        let v0 = linear_combination(
            &[
                (read_value[0].into_field(), F::ONE),
                (key_bytes[0].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[1].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[2].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v1 = linear_combination(
            &[
                (read_value[1].into_field(), F::ONE),
                (key_bytes[3].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[4].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[5].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v2 = linear_combination(
            &[
                (read_value[2].into_field(), F::ONE),
                (key_bytes[6].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[7].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[8].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v3 = linear_combination(
            &[
                (read_value[3].into_field(), F::ONE),
                (key_bytes[9].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[10].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[11].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v4 = linear_combination(
            &[
                (read_value[4].into_field(), F::ONE),
                (key_bytes[12].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[13].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[14].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v5 = linear_combination(
            &[
                (read_value[5].into_field(), F::ONE),
                (key_bytes[15].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[16].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[17].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v6 = linear_combination(
            &[
                (read_value[6].into_field(), F::ONE),
                (key_bytes[18].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[19].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[20].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v7 = linear_combination(
            &[
                (read_value[7].into_field(), F::ONE),
                (key_bytes[21].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[22].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[23].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        // continue with written value

        let v8 = linear_combination(
            &[
                (written_value[0].into_field(), F::ONE),
                (key_bytes[24].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[25].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[26].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v9 = linear_combination(
            &[
                (written_value[1].into_field(), F::ONE),
                (key_bytes[27].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[28].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (key_bytes[29].into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        // continue mixing bytes, now from "address"

        let v10 = linear_combination(
            &[
                (written_value[2].into_field(), F::ONE),
                (key_bytes[30].into_field(), F::from_u64_unchecked(1u64 << 32)),
                (key_bytes[31].into_field(), F::from_u64_unchecked(1u64 << 40)),
                (
                    address_bytes[0].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        let v11 = linear_combination(
            &[
                (written_value[3].into_field(), F::ONE),
                (
                    address_bytes[1].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[2].into_field(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[3].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        let v12 = linear_combination(
            &[
                (written_value[4].into_field(), F::ONE),
                (
                    address_bytes[4].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[5].into_field(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[6].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        let v13 = linear_combination(
            &[
                (written_value[5].into_field(), F::ONE),
                (
                    address_bytes[7].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[8].into_field(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[9].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        let v14 = linear_combination(
            &[
                (written_value[6].into_field(), F::ONE),
                (
                    address_bytes[10].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[11].into_field(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[12].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        let v15 = linear_combination(
            &[
                (written_value[7].into_field(), F::ONE),
                (
                    address_bytes[13].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[14].into_field(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[15].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        // now we can pack using some other "large" items as base

        let v16 = linear_combination(
            &[
                (self.timestamp.0.into_field(), F::ONE),
                (
                    address_bytes[16].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (
                    address_bytes[17].into_field(),
                    F::from_u64_unchecked(1u64 << 40),
                ),
                (
                    address_bytes[18].into_field(),
                    F::from_u64_unchecked(1u64 << 48),
                ),
            ],
        );

        let v17 = linear_combination(
            &[
                (self.tx_number_in_block.into_field(), F::ONE), // NOTE: u16 out of circuit and u32 in circuit
                (
                    address_bytes[19].into_field(),
                    F::from_u64_unchecked(1u64 << 32),
                ),
                (self.aux_byte.into_field(), F::from_u64_unchecked(1u64 << 40)),
                (self.shard_id.into_field(), F::from_u64_unchecked(1u64 << 48)),
            ],
        );

        let v18 = linear_combination(
            &[
                (self.rw_flag.into_field(), F::ONE),
                (self.is_service.into_field(), F::TWO),
            ],
        );

        // and the final into_field() is just rollback flag itself

        let v19 = self.rollback.into_field();

        [
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18,
            v19,
        ]

    }
}

// pub type LogQueryWithExtendedEnumeration = LogQueryLikeWithExtendedEnumeration<LogQuery>;

// impl<F: SmallField> OutOfCircuitFixedLengthEncodable<E, 5> for LogQueryWithExtendedEnumeration {
//     fn encoding_witness(&self) -> [<E>::Fr; 5] {
//         let shifts = compute_shifts::<F>();

//         let LogQueryWithExtendedEnumeration {
//             raw_query,
//             extended_timestamp
//         } = self;

//         let mut result = <LogQuery as OutOfCircuitFixedLengthEncodable<E, 5>>::encoding_witness(raw_query);

//         let mut shift = EXTENDED_TIMESTAMP_ENCODING_OFFSET;
//         scale_and_accumulate::<E, _>(&mut result[EXTENDED_TIMESTAMP_ENCODING_ELEMENT], *extended_timestamp, &shifts, shift);
//         shift += 32;
//         assert!(shift <= F::CAPACITY as usize);

//         // dbg!(&result);
        
//         result
//     }
// }

pub type LogQueueSimulator<F> = QueueSimulator<F, LogQuery, QUEUE_STATE_WIDTH, LOG_QUERY_PACKED_WIDTH, 3>;
pub type LogQueueState<F> = QueueIntermediateStates<F, QUEUE_STATE_WIDTH, FULL_SPONGE_QUEUE_STATE_WIDTH, 3>;

// pub type LogWithExtendedEnumerationQueueSimulator<E> = QueueSimulator<E, LogQueryWithExtendedEnumeration, 5, 3>;
// pub type LogWithExtendedEnumerationQueueState<E> = QueueIntermediateStates<E, 3, 3>;

pub fn log_query_into_circuit_log_query_witness<F: SmallField>(query: &LogQuery) 
    -> <zkevm_circuits::base_structures::log_query::LogQuery<F> as CSAllocatable<F>>::Witness {
    use zkevm_circuits::base_structures::log_query::LogQueryWitness;

    LogQueryWitness {
        address: query.address,
        key: query.key,
        read_value: query.read_value,
        written_value: query.written_value,
        rw_flag: query.rw_flag,
        aux_byte: query.aux_byte,
        rollback: query.rollback,
        is_service: query.is_service,
        shard_id: query.shard_id,
        tx_number_in_block: query.tx_number_in_block as u32,
        timestamp: query.timestamp.0,
    }
}

impl<F: SmallField> CircuitEquivalentReflection<F> for LogQuery {
    type Destination = zkevm_circuits::base_structures::log_query::LogQuery<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness {
        log_query_into_circuit_log_query_witness(self)
    }
}

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

// pub fn log_query_into_timestamped_storage_record_witness<F: SmallField>(query: &LogQueryWithExtendedEnumeration) -> <TimestampedStorageLogRecord<E> as CSWitnessable<E>>::Witness {
//     use sync_vm::scheduler::queues::StorageLogRecordWitness;

//     TimestampedStorageLogRecordWitness {
//         record: log_query_into_storage_record_witness(&query.raw_query),
//         timestamp: query.extended_timestamp,
//     }
// }
use zk_evm::aux_structures::LogQuery;
use zk_evm::aux_structures::Timestamp;
use zk_evm::ethereum_types::H160;
use zk_evm::ethereum_types::U256;

// Proxy, as we just need read-only
pub trait LogQueryLike: 'static + Clone + Send + Sync + std::fmt::Debug {
    fn shard_id(&self) -> u8;
    fn address(&self) -> H160;
    fn key(&self) -> U256;
    fn rw_flag(&self) -> bool;
    fn rollback(&self) -> bool;
    fn read_value(&self) -> U256;
    fn written_value(&self) -> U256;
    fn create_partially_filled_from_fields(
        shard_id: u8,
        address: H160,
        key: U256,
        read_value: U256,
        written_value: U256,
        rw_flag: bool,
    ) -> Self;
}

impl LogQueryLike for LogQuery {
    fn shard_id(&self) -> u8 {
        self.shard_id
    }
    fn address(&self) -> H160 {
        self.address
    }
    fn key(&self) -> U256 {
        self.key
    }
    fn rw_flag(&self) -> bool {
        self.rw_flag
    }
    fn rollback(&self) -> bool {
        self.rollback
    }
    fn read_value(&self) -> U256 {
        self.read_value
    }
    fn written_value(&self) -> U256 {
        self.written_value
    }
    fn create_partially_filled_from_fields(
        shard_id: u8,
        address: H160,
        key: U256,
        read_value: U256,
        written_value: U256,
        rw_flag: bool,
    ) -> Self {
        // only smaller number of field matters in practice
        LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: 0,
            aux_byte: 0,
            shard_id,
            address,
            key,
            read_value,
            written_value,
            rw_flag,
            rollback: false,
            is_service: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LogQueryLikeWithExtendedEnumeration<L: LogQueryLike> {
    pub raw_query: L,
    pub extended_timestamp: u32,
}

use super::*;

use zkevm_circuits::storage_validity_by_grand_product::input::PACKED_KEY_LENGTH;

pub fn comparison_key(query: &LogQuery) -> Key<PACKED_KEY_LENGTH> {
    let key = decompose_u256_as_u32x8(query.key);
    let address = decompose_address_as_u32x5(query.address);

    let le_words = [
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], address[0], address[1],
        address[2], address[3], address[4],
    ];

    Key(le_words)
}

pub fn event_comparison_key(query: &LogQuery) -> Key<1> {
    let le_words = [query.timestamp.0];

    Key(le_words)
}

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

        let v0 = linear_combination(&[
            (read_value[0].into_field(), F::ONE),
            (key_bytes[0].into_field(), F::from_u64_unchecked(1u64 << 32)),
            (key_bytes[1].into_field(), F::from_u64_unchecked(1u64 << 40)),
            (key_bytes[2].into_field(), F::from_u64_unchecked(1u64 << 48)),
        ]);

        let v1 = linear_combination(&[
            (read_value[1].into_field(), F::ONE),
            (key_bytes[3].into_field(), F::from_u64_unchecked(1u64 << 32)),
            (key_bytes[4].into_field(), F::from_u64_unchecked(1u64 << 40)),
            (key_bytes[5].into_field(), F::from_u64_unchecked(1u64 << 48)),
        ]);

        let v2 = linear_combination(&[
            (read_value[2].into_field(), F::ONE),
            (key_bytes[6].into_field(), F::from_u64_unchecked(1u64 << 32)),
            (key_bytes[7].into_field(), F::from_u64_unchecked(1u64 << 40)),
            (key_bytes[8].into_field(), F::from_u64_unchecked(1u64 << 48)),
        ]);

        let v3 = linear_combination(&[
            (read_value[3].into_field(), F::ONE),
            (key_bytes[9].into_field(), F::from_u64_unchecked(1u64 << 32)),
            (
                key_bytes[10].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[11].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v4 = linear_combination(&[
            (read_value[4].into_field(), F::ONE),
            (
                key_bytes[12].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[13].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[14].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v5 = linear_combination(&[
            (read_value[5].into_field(), F::ONE),
            (
                key_bytes[15].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[16].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[17].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v6 = linear_combination(&[
            (read_value[6].into_field(), F::ONE),
            (
                key_bytes[18].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[19].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[20].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v7 = linear_combination(&[
            (read_value[7].into_field(), F::ONE),
            (
                key_bytes[21].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[22].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[23].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        // continue with written value

        let v8 = linear_combination(&[
            (written_value[0].into_field(), F::ONE),
            (
                key_bytes[24].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[25].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[26].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v9 = linear_combination(&[
            (written_value[1].into_field(), F::ONE),
            (
                key_bytes[27].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[28].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                key_bytes[29].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        // continue mixing bytes, now from "address"

        let v10 = linear_combination(&[
            (written_value[2].into_field(), F::ONE),
            (
                key_bytes[30].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                key_bytes[31].into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                address_bytes[0].into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v11 = linear_combination(&[
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
        ]);

        let v12 = linear_combination(&[
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
        ]);

        let v13 = linear_combination(&[
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
        ]);

        let v14 = linear_combination(&[
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
        ]);

        let v15 = linear_combination(&[
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
        ]);

        // now we can pack using some other "large" items as base

        let v16 = linear_combination(&[
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
        ]);

        let v17 = linear_combination(&[
            (self.tx_number_in_block.into_field(), F::ONE), // NOTE: u16 out of circuit and u32 in circuit
            (
                address_bytes[19].into_field(),
                F::from_u64_unchecked(1u64 << 32),
            ),
            (
                self.aux_byte.into_field(),
                F::from_u64_unchecked(1u64 << 40),
            ),
            (
                self.shard_id.into_field(),
                F::from_u64_unchecked(1u64 << 48),
            ),
        ]);

        let v18 = linear_combination(&[
            (self.rw_flag.into_field(), F::ONE),
            (self.is_service.into_field(), F::TWO),
        ]);

        // and the final into_field() is just rollback flag itself

        let v19 = self.rollback.into_field();

        [
            v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18,
            v19,
        ]
    }
}

pub type LogQueryWithExtendedEnumeration = LogQueryLikeWithExtendedEnumeration<LogQuery>;

impl<F: SmallField> OutOfCircuitFixedLengthEncodable<F, LOG_QUERY_PACKED_WIDTH>
    for LogQueryWithExtendedEnumeration
{
    fn encoding_witness(&self) -> [F; LOG_QUERY_PACKED_WIDTH] {
        let LogQueryWithExtendedEnumeration {
            raw_query,
            extended_timestamp,
        } = self;

        let mut result = <LogQuery as OutOfCircuitFixedLengthEncodable<
            F,
            LOG_QUERY_PACKED_WIDTH,
        >>::encoding_witness(raw_query);
        use zkevm_circuits::storage_validity_by_grand_product::EXTENDED_TIMESTAMP_ENCODING_OFFSET;

        let mut shift = EXTENDED_TIMESTAMP_ENCODING_OFFSET;
        use zkevm_circuits::storage_validity_by_grand_product::EXTENDED_TIMESTAMP_ENCODING_ELEMENT;
        scale_and_accumulate::<F, _>(
            &mut result[EXTENDED_TIMESTAMP_ENCODING_ELEMENT],
            *extended_timestamp,
            shift,
        );
        shift += 32;
        assert!(shift <= F::CAPACITY_BITS as usize);

        result
    }
}

use zkevm_circuits::base_structures::log_query::LOG_QUERY_ABSORBTION_ROUNDS;

pub type LogQueueSimulator<F> = QueueSimulator<
    F,
    LogQuery,
    QUEUE_STATE_WIDTH,
    LOG_QUERY_PACKED_WIDTH,
    LOG_QUERY_ABSORBTION_ROUNDS,
>;
pub type LogQueueState<F> = QueueIntermediateStates<
    F,
    QUEUE_STATE_WIDTH,
    FULL_SPONGE_QUEUE_STATE_WIDTH,
    LOG_QUERY_ABSORBTION_ROUNDS,
>;

pub type LogWithExtendedEnumerationQueueSimulator<F> = QueueSimulator<
    F,
    LogQueryWithExtendedEnumeration,
    QUEUE_STATE_WIDTH,
    LOG_QUERY_PACKED_WIDTH,
    LOG_QUERY_ABSORBTION_ROUNDS,
>;
// pub type LogQueueState<F> = QueueIntermediateStates<F, QUEUE_STATE_WIDTH, FULL_SPONGE_QUEUE_STATE_WIDTH, LOG_QUERY_ABSORBTION_ROUNDS>;

pub fn log_query_into_circuit_log_query_witness<F: SmallField>(
    query: &LogQuery,
) -> <zkevm_circuits::base_structures::log_query::LogQuery<F> as CSAllocatable<F>>::Witness {
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

pub fn log_query_into_timestamped_storage_record_witness<F: SmallField>(
    query: &LogQueryWithExtendedEnumeration
) -> <zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F> as CSAllocatable<F>>::Witness{
    use zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecordWitness;

    TimestampedStorageLogRecordWitness {
        record: log_query_into_circuit_log_query_witness(&query.raw_query),
        timestamp: query.extended_timestamp,
    }
}

impl<F: SmallField> CircuitEquivalentReflection<F> for LogQueryWithExtendedEnumeration {
    type Destination =
        zkevm_circuits::storage_validity_by_grand_product::TimestampedStorageLogRecord<F>;
    fn reflect(&self) -> <Self::Destination as CSAllocatable<F>>::Witness {
        log_query_into_timestamped_storage_record_witness(self)
    }
}

use zkevm_circuits::base_structures::log_query::L2_TO_L1_MESSAGE_BYTE_LENGTH;

// for purposes of L1 messages
impl BytesSerializable<L2_TO_L1_MESSAGE_BYTE_LENGTH> for LogQuery {
    fn serialize(&self) -> [u8; L2_TO_L1_MESSAGE_BYTE_LENGTH] {
        let mut result = [0u8; L2_TO_L1_MESSAGE_BYTE_LENGTH];
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

        assert_eq!(offset, L2_TO_L1_MESSAGE_BYTE_LENGTH);

        result
    }
}

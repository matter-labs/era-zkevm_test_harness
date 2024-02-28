use zk_evm::ethereum_types::Address;

use super::*;
use crate::ethereum_types::U256;

#[derive(Derivative)]
#[derivative(Clone, Copy, Debug, Hash)]
pub struct StateDiffRecord {
    pub address: Address,
    pub key: U256,
    pub derived_key: [u8; 32],
    pub enumeration_index: u64,
    pub initial_value: U256,
    pub final_value: U256,
}

use zkevm_circuits::base_structures::state_diff_record::STATE_DIFF_RECORD_BYTE_ENCODING_LEN;

impl StateDiffRecord {
    // the only thing we need is byte encoding
    pub fn encode(&self) -> [u8; STATE_DIFF_RECORD_BYTE_ENCODING_LEN] {
        let mut encoding = [0u8; STATE_DIFF_RECORD_BYTE_ENCODING_LEN];
        let mut offset = 0;
        let mut end = 0;

        end += 20;
        encoding[offset..end].copy_from_slice(self.address.as_fixed_bytes());
        offset = end;

        end += 32;
        self.key.to_big_endian(&mut encoding[offset..end]);
        offset = end;

        end += 32;
        encoding[offset..end].copy_from_slice(&self.derived_key);
        offset = end;

        end += 8;
        encoding[offset..end].copy_from_slice(&self.enumeration_index.to_be_bytes());
        offset = end;

        end += 32;
        self.initial_value.to_big_endian(&mut encoding[offset..end]);
        offset = end;

        end += 32;
        self.final_value.to_big_endian(&mut encoding[offset..end]);
        offset = end;

        debug_assert_eq!(offset, encoding.len());

        encoding
    }
}

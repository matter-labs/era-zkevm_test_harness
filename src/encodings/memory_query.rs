use super::*;

use zk_evm::aux_structures::MemoryQuery;

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 2> for MemoryQuery {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        todo!()
    }
}
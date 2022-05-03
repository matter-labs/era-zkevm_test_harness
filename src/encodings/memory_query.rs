use super::*;

use zk_evm::aux_structures::MemoryQuery;

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 2> for MemoryQuery {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        [E::Fr::zero(); 2]
    }
}

pub type MemoryQueueSimulator<E> = SpongeLikeQueueSimulator<E, MemoryQuery, 2, 3, 1>;
pub type MemoryQueueState<E> = SpongeLikeQueueIntermediateStates<E, 3, 1>;

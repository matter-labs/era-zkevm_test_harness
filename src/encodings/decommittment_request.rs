use zk_evm::aux_structures::DecommittmentQuery;

use super::*;

impl<E: Engine> OutOfCircuitFixedLengthEncodable<E, 2> for DecommittmentQuery {
    fn encoding_witness(&self) -> [<E>::Fr; 2] {
        [E::Fr::zero(); 2]
    }
}

pub type DecommittmentQueueSimulator<E> = SpongeLikeQueueSimulator<E, DecommittmentQuery, 2, 3>;
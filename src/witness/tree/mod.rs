use crate::witness::utils::take_queue_state_from_simulator;
use crate::witness::utils::transform_queue_witness;
pub trait EnumeratedBinaryLeaf<const LEAF_DATA_WIDTH: usize>: Clone + std::hash::Hash {
    fn empty() -> Self;
    fn empty_index() -> u64 {
        0
    }
    fn from_value(value: [u8; LEAF_DATA_WIDTH]) -> Self;
    fn current_index(&self) -> u64;
    fn set_index(&mut self, value: u64);
    fn value(&self) -> &[u8; LEAF_DATA_WIDTH];
    fn set_value(&mut self, value: &[u8; LEAF_DATA_WIDTH]);
    fn value_ref_mut(&mut self) -> &mut [u8; LEAF_DATA_WIDTH];
}

pub trait BinaryHasher<const HASH_OUTPUT_WIDTH: usize>: Clone + Send + Sync {
    fn new() -> Self;
    // fn update(&mut self, input: &[u8]);
    // fn finalize(self) -> [u8; HASH_OUTPUT_WIDTH];
    // there function takes &mut self, but should internally cleanup if necessary (reset state)
    fn node_hash(
        depth: usize,
        left_node: &[u8; HASH_OUTPUT_WIDTH],
        right_node: &[u8; HASH_OUTPUT_WIDTH],
    ) -> [u8; HASH_OUTPUT_WIDTH];
    fn leaf_hash(leaf: &[u8]) -> [u8; HASH_OUTPUT_WIDTH];
}

pub struct LeafQuery<
    const DEPTH: usize,
    const INDEX_BYTES: usize,
    const LEAF_DATA_WIDTH: usize,
    const HASH_OUTPUT_WIDTH: usize,
    L: EnumeratedBinaryLeaf<LEAF_DATA_WIDTH>,
> {
    pub leaf: L,
    pub first_write: bool,
    pub index: [u8; INDEX_BYTES],
    pub merkle_path: Box<[[u8; HASH_OUTPUT_WIDTH]; DEPTH]>, // too large
}

pub trait BinarySparseStorageTree<
    const DEPTH: usize,
    const INDEX_BYTES: usize,
    const LEAF_DATA_WIDTH: usize,
    const LEAF_METADATA_WIDTH: usize,
    const HASH_OUTPUT_WIDTH: usize,
    H: BinaryHasher<HASH_OUTPUT_WIDTH>,
    L: EnumeratedBinaryLeaf<LEAF_DATA_WIDTH>,
>
{
    fn empty() -> Self;
    fn next_enumeration_index(&self) -> u64;
    fn set_next_enumeration_index(&mut self, value: u64);
    fn root(&self) -> [u8; HASH_OUTPUT_WIDTH];
    fn get_leaf(
        &mut self,
        index: &[u8; INDEX_BYTES],
    ) -> LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>;
    fn insert_leaf(
        &mut self,
        index: &[u8; INDEX_BYTES],
        leaf: L,
    ) -> LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>;
    fn insert_many_leafs(
        &mut self,
        indexes: &[[u8; INDEX_BYTES]],
        leafs: Vec<L>,
    ) -> Vec<LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>> {
        assert_eq!(indexes.len(), leafs.len());
        let mut result = Vec::with_capacity(indexes.len());
        for (idx, leaf) in indexes.iter().zip(leafs.into_iter()) {
            let query = self.insert_leaf(idx, leaf);
            result.push(query);
        }

        result
    }
    // fn filter_renumerate(&self, indexes: &[[u8; INDEX_BYTES]], leafs: &[L]) -> (u64, Vec<L>, Vec<L>);
    fn filter_renumerate<'a>(
        &self,
        indexes: impl Iterator<Item = &'a [u8; INDEX_BYTES]>,
        leafs: impl Iterator<Item = L>,
    ) -> (u64, Vec<([u8; INDEX_BYTES], L)>, Vec<L>);
    fn verify_inclusion(
        root: &[u8; 32],
        query: &LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>,
    ) -> bool;
    fn verify_inclusion_proxy(
        &self,
        root: &[u8; 32],
        query: &LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>,
    ) -> bool {
        Self::verify_inclusion(root, query)
    }
}

pub type ZKSyncTestingTree = InMemoryStorageTree<256, 32, 8, Blake2s256, ZkSyncStorageLeaf>;

use std::collections::HashMap;

pub struct InMemoryStorageTree<
    const DEPTH: usize,
    const INDEX_BYTES: usize,
    const LEAF_METADATA_WIDTH: usize,
    H: BinaryHasher<32>,
    L: EnumeratedBinaryLeaf<32>,
> {
    pub hasher: H,
    // pub empty_leaf_hash: [u8; 32],
    pub next_enumeration_index: u64,
    pub empty_hashes: Box<[[u8; 32]; DEPTH]>,
    pub root: [u8; 32],
    pub layers: [HashMap<[u8; INDEX_BYTES], [u8; 32]>; DEPTH],
    pub leafs: HashMap<[u8; INDEX_BYTES], L>,
}

fn create_neighbour_index<const N: usize>(index: &[u8; N], depth: usize) -> [u8; N] {
    debug_assert!(depth < N * 8);
    let byte_idx = depth / 8;
    let bit_idx = depth % 8;

    let mut result = *index;
    result[byte_idx] = result[byte_idx] ^ (1u8 << bit_idx);

    result
}

fn is_right_side_node<const N: usize>(index: &[u8; N], depth: usize) -> bool {
    debug_assert!(depth < N * 8);
    let byte_idx = depth / 8;
    let bit_idx = depth % 8;

    let is_right_side = index[byte_idx] & (1u8 << bit_idx) != 0;

    is_right_side
}

impl<
        const DEPTH: usize,
        const INDEX_BYTES: usize,
        const LEAF_METADATA_WIDTH: usize,
        H: BinaryHasher<32>,
        L: EnumeratedBinaryLeaf<32>,
    > InMemoryStorageTree<DEPTH, INDEX_BYTES, LEAF_METADATA_WIDTH, H, L>
{
    pub fn new() -> Self {
        assert!(INDEX_BYTES * 8 == DEPTH);
        assert!(DEPTH > 0);
        let mut empty_leaf = vec![0u8; LEAF_METADATA_WIDTH + 32];
        empty_leaf[LEAF_METADATA_WIDTH..].copy_from_slice(L::empty().value());

        let empty_leaf_hash = H::leaf_hash(&empty_leaf);
        // now form empty hasher for every level
        // we count levels from the bottom, and level 0 is empty leaf hashes

        let mut empty_hashes = Box::<[[u8; 32]; DEPTH]>::new([[0u8; 32]; DEPTH]);
        empty_hashes[0] = empty_leaf_hash;

        let mut root = [0u8; 32];

        let mut current_hash = empty_leaf_hash;
        for level in 1..=DEPTH {
            let empty_node_hash = H::node_hash(level, &current_hash, &current_hash);

            if level < DEPTH {
                empty_hashes[level] = empty_node_hash;
                current_hash = empty_node_hash;
            } else {
                root = empty_node_hash;
            }
        }

        let layers = vec![HashMap::new(); DEPTH].try_into().unwrap();

        Self {
            hasher: H::new(),
            // pub empty_leaf_hash: [u8; 32],
            next_enumeration_index: 1u64,
            empty_hashes,
            root,
            layers: layers,
            leafs: HashMap::new(),
        }
    }

    fn insert_path_element(&mut self, level: usize, index: [u8; INDEX_BYTES], value: [u8; 32]) {
        // the only important thing is to cleanup the lowest bits for consistency
        let mut index = index;
        for bit in 0..level {
            let word_idx = bit / 8;
            let bit_idx = bit % 8;
            index[word_idx] = index[word_idx] & (!(1 << bit_idx));
        }

        self.layers[level].insert(index, value);
    }

    fn get_path_element(&self, level: usize, index: [u8; INDEX_BYTES]) -> &[u8; 32] {
        // the only important thing is to cleanup the lowest bits for consistency
        let mut index = index;
        for bit in 0..level {
            let word_idx = bit / 8;
            let bit_idx = bit % 8;
            index[word_idx] = index[word_idx] & (!(1 << bit_idx));
        }

        if let Some(node_hash) = self.layers[level].get(&index) {
            node_hash
        } else {
            &self.empty_hashes[level]
        }
    }

    fn get_leaf(&self, index: &[u8; INDEX_BYTES]) -> LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L> {
        let leaf = if let Some(leaf) = self.leafs.get(index) {
            leaf.clone()
        } else {
            L::empty()
        };

        let mut path: Box<[[u8; 32]; DEPTH]> = Box::new([[0u8; 32]; DEPTH]);
        for level in 0..DEPTH {
            let pair_idx = create_neighbour_index(index, level);
            let pair_node_hash = self.get_path_element(level, pair_idx);
            path[level] = *pair_node_hash;
        }

        LeafQuery {
            leaf,
            first_write: false,
            index: *index,
            merkle_path: path,
        }
    }

    fn verify_inclusion(root: &[u8; 32], query: &LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L>) -> bool {
        let mut leaf_bytes = vec![0u8; LEAF_METADATA_WIDTH + 32]; // can make a scratch space somewhere later on
        leaf_bytes[LEAF_METADATA_WIDTH..].copy_from_slice(query.leaf.value());

        let leaf_index_bytes = query.leaf.current_index().to_be_bytes();
        leaf_bytes[(LEAF_METADATA_WIDTH - 8)..LEAF_METADATA_WIDTH]
            .copy_from_slice(&leaf_index_bytes);

        let leaf_hash = H::leaf_hash(&leaf_bytes);

        let mut current_hash = leaf_hash;
        for level in 0..DEPTH {
            let (l, r) = if is_right_side_node(&query.index, level) {
                (&query.merkle_path[level], &current_hash)
            } else {
                (&current_hash, &query.merkle_path[level])
            };

            let this_level_hash = H::node_hash(level, l, r);

            current_hash = this_level_hash;
        }

        root == &current_hash
    }

    // fn filter_renumerate(&self, indexes: &[[u8; INDEX_BYTES]], leafs: &[L]) -> (u64, Vec<L>, Vec<L>) {
    fn filter_renumerate<'a>(
        &self,
        mut indexes: impl Iterator<Item = &'a [u8; INDEX_BYTES]>,
        mut leafs: impl Iterator<Item = L>,
    ) -> (u64, Vec<([u8; INDEX_BYTES], L)>, Vec<L>) {
        // we assume that we want to write leafs and quickly get which of those will be unique writes, and which will be updates
        let mut first_writes = vec![];
        let mut updates = vec![];
        let mut next_index = self.next_enumeration_index;
        for (idx, leaf) in (&mut indexes).zip(&mut leafs) {
            let mut leaf = leaf;
            if let Some(existing) = self.leafs.get(idx) {
                leaf.set_index(existing.current_index());
                updates.push(leaf);
            } else {
                leaf.set_index(next_index);
                next_index += 1;
                first_writes.push((*idx, leaf));
            }
        }

        assert!(indexes.next().is_none());
        assert!(leafs.next().is_none());

        (next_index, first_writes, updates)
    }

    fn insert_leaf(
        &mut self,
        index: &[u8; INDEX_BYTES],
        leaf: L,
    ) -> LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L> {
        // first decide if we enumerate

        let mut first_write = false;

        if let Some(existing_leaf) = self.leafs.get_mut(index) {
            existing_leaf.set_value(leaf.value());
        } else {
            // enumerate
            let mut leaf = leaf;
            first_write = true;
            leaf.set_index(self.next_enumeration_index);
            self.leafs.insert(*index, leaf);
            self.next_enumeration_index += 1;
        }

        // now recompute the path
        let leaf = self.leafs.get(index).cloned().unwrap();
        let mut leaf_bytes = vec![0u8; LEAF_METADATA_WIDTH + 32]; // can make a scratch space somewhere later on
        leaf_bytes[LEAF_METADATA_WIDTH..].copy_from_slice(leaf.value());

        let leaf_index_bytes = leaf.current_index().to_be_bytes();
        leaf_bytes[(LEAF_METADATA_WIDTH - 8)..LEAF_METADATA_WIDTH]
            .copy_from_slice(&leaf_index_bytes);

        let leaf_hash = H::leaf_hash(&leaf_bytes);

        let mut current_hash = leaf_hash;
        let mut path: Box<[[u8; 32]; DEPTH]> = Box::new([[0u8; 32]; DEPTH]);
        for level in 0..DEPTH {
            self.insert_path_element(level, *index, current_hash);
            let pair_idx = create_neighbour_index(index, level);
            let pair_node_hash = self.get_path_element(level, pair_idx);

            path[level] = *pair_node_hash;

            let (l, r) = if is_right_side_node(index, level) {
                (pair_node_hash, &current_hash)
            } else {
                (&current_hash, pair_node_hash)
            };

            let parent_node_hash = H::node_hash(level, l, r);
            current_hash = parent_node_hash;
        }

        self.root = current_hash;

        LeafQuery {
            leaf: leaf,
            first_write,
            index: *index,
            merkle_path: path,
        }
    }
}

impl<
        const DEPTH: usize,
        const INDEX_BYTES: usize,
        const LEAF_METADATA_WIDTH: usize,
        H: BinaryHasher<32>,
        L: EnumeratedBinaryLeaf<32>,
    > BinarySparseStorageTree<DEPTH, INDEX_BYTES, 32, LEAF_METADATA_WIDTH, 32, H, L>
    for InMemoryStorageTree<DEPTH, INDEX_BYTES, LEAF_METADATA_WIDTH, H, L>
{
    fn empty() -> Self {
        Self::new()
    }
    fn next_enumeration_index(&self) -> u64 {
        self.next_enumeration_index
    }
    fn set_next_enumeration_index(&mut self, value: u64) {
        self.next_enumeration_index = value;
    }
    fn root(&self) -> [u8; 32] {
        self.root
    }
    fn get_leaf(&mut self, index: &[u8; INDEX_BYTES]) -> LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L> {
        Self::get_leaf(self, index)
    }
    fn insert_leaf(
        &mut self,
        index: &[u8; INDEX_BYTES],
        leaf: L,
    ) -> LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L> {
        Self::insert_leaf(self, index, leaf)
    }
    // fn filter_renumerate(&self, indexes: &[[u8; INDEX_BYTES]], leafs: &[L]) -> (u64, Vec<L>, Vec<L>) {
    fn filter_renumerate<'a>(
        &self,
        indexes: impl Iterator<Item = &'a [u8; INDEX_BYTES]>,
        leafs: impl Iterator<Item = L>,
    ) -> (u64, Vec<([u8; INDEX_BYTES], L)>, Vec<L>) {
        Self::filter_renumerate(&self, indexes, leafs)
    }
    fn verify_inclusion(root: &[u8; 32], query: &LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L>) -> bool {
        Self::verify_inclusion(root, query)
    }
}

use crate::blake2::{Blake2s256, Digest};

impl BinaryHasher<32> for Blake2s256 {
    fn new() -> Self {
        Digest::new()
    }
    fn node_hash(_depth: usize, left_node: &[u8; 32], right_node: &[u8; 32]) -> [u8; 32] {
        let mut hasher = <Self as Digest>::new();
        hasher.update(left_node);
        hasher.update(right_node);
        let mut result = [0u8; 32];
        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
    fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
        let mut hasher = <Self as Digest>::new();
        hasher.update(leaf);
        let mut result = [0u8; 32];
        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
}

use crate::sha3::Keccak256;

impl BinaryHasher<32> for Keccak256 {
    fn new() -> Self {
        Digest::new()
    }
    fn node_hash(_depth: usize, left_node: &[u8; 32], right_node: &[u8; 32]) -> [u8; 32] {
        let mut hasher = <Self as Digest>::new();
        hasher.update(left_node);
        hasher.update(right_node);
        let mut result = [0u8; 32];
        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
    fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
        let mut hasher = <Self as Digest>::new();
        hasher.update(leaf);
        let mut result = [0u8; 32];
        result.copy_from_slice(hasher.finalize().as_slice());

        result
    }
}

use derivative::Derivative;

#[derive(Derivative)]
#[derivative(Clone, Copy, Hash, Debug)]
pub struct ZkSyncStorageLeaf {
    pub index: u64,
    pub value: [u8; 32],
}

impl EnumeratedBinaryLeaf<32> for ZkSyncStorageLeaf {
    fn empty() -> Self {
        Self {
            index: 0,
            value: [0u8; 32],
        }
    }
    fn from_value(value: [u8; 32]) -> Self {
        Self { index: 0, value }
    }
    fn current_index(&self) -> u64 {
        self.index
    }
    fn set_index(&mut self, value: u64) {
        self.index = value;
    }
    fn value(&self) -> &[u8; 32] {
        &self.value
    }
    fn set_value(&mut self, value: &[u8; 32]) {
        self.value.copy_from_slice(value);
    }
    fn value_ref_mut(&mut self) -> &mut [u8; 32] {
        &mut self.value
    }
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, collections::HashSet};

    use sync_vm::{
        franklin_crypto::bellman::plonk::better_better_cs::cs::Circuit,
        glue::storage_application::input::StorageApplicationCircuitInstanceWitness,
        testing::create_test_artifacts_with_optimized_gate,
    };
    use zk_evm::{zkevm_opcode_defs::system_params::STORAGE_AUX_BYTE, ethereum_types::{Address, U256}, aux_structures::LogQuery};

    use crate::witness::postprocessing::USE_BLAKE2S_EXTRA_TABLES;

    use super::*;

    #[test]
    fn trivial() {
        const DEPTH: usize = 256;
        const INDEX_BYTES: usize = 32;
        // const DEPTH: usize = 8;
        // const INDEX_BYTES: usize = 1;

        let mut tree =
            InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

        let tree2 =
            InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

        assert_eq!(tree.root(), tree2.root());

        let dummy_leaf = ZkSyncStorageLeaf::from_value([1u8; 32]);
        let index = [2u8; INDEX_BYTES];

        let query = tree.insert_leaf(&index, dummy_leaf);
        let root = tree.root();
        assert!(query.leaf.current_index() == 1);
        assert!(tree.next_enumeration_index() == 2);

        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root, &query);
        assert!(included);

        let mut index = [255u8; INDEX_BYTES];
        index[31] = 0;
        let query = tree.get_leaf(&index);
        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root, &query);
        assert!(included);

        let dummy_leaf_1 = ZkSyncStorageLeaf::from_value([3u8; 32]);
        let index_1 = [4u8; INDEX_BYTES];

        let query_1 = tree.insert_leaf(&index_1, dummy_leaf_1);
        let root_1 = tree.root();
        assert!(query_1.leaf.current_index() == 2);
        assert!(tree.next_enumeration_index() == 3);

        assert!(root != root_1);

        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root_1, &query_1);
        assert!(included);

        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root_1, &query);
        assert!(!included);
    }

    #[test]
    fn reference_params() {
        const DEPTH: usize = 256;
        const INDEX_BYTES: usize = 32;
        // const DEPTH: usize = 8;
        // const INDEX_BYTES: usize = 1;

        let mut tree =
            InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

        println!("Empty root = {}", hex::encode(&tree.root()));
        println!(
            "Next enumeration index for empty tree = {}",
            tree.next_enumeration_index()
        );

        // let's create a leaf

        let dummy_leaf = ZkSyncStorageLeaf::from_value([1u8; 32]);
        use crate::ethereum_types::{Address, U256};
        use zk_evm::aux_structures::LogQuery;
        let address = Address::from_low_u64_be(0x8002);
        let key = U256::zero();
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        println!(
            "Equivalence of query with address = {:?} and key = {}",
            address, key
        );
        println!(
            "Will insert a leaf with value {} at index (hashed index) {}",
            hex::encode(&dummy_leaf.value()),
            hex::encode(&index)
        );

        let query = tree.insert_leaf(&index, dummy_leaf);

        println!("New root = {}", hex::encode(&tree.root()));

        let root = tree.root();
        assert!(query.leaf.current_index() == 1);
        assert!(tree.next_enumeration_index() == 2);

        println!(
            "New tree has next enumeration index = {}, and leaf got enumeration index = {}",
            tree.next_enumeration_index(),
            query.leaf.current_index()
        );

        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root, &query);
        assert!(included);

        println!("Merkle proof path elements starting from the leafs:");
        for (level, el) in query.merkle_path.iter().take(4).enumerate() {
            println!("{}", hex::encode(el));
            if is_right_side_node(&query.index, level) {
                println!("Merkle path element is on the LEFT side");
            } else {
                println!("Merkle path element is on the RIGHT side");
            }
        }
    }

    #[test]
    fn reference_params_extended() {
        const DEPTH: usize = 256;
        const INDEX_BYTES: usize = 32;
        // const DEPTH: usize = 8;
        // const INDEX_BYTES: usize = 1;
        use crate::ethereum_types::{Address, U256};
        use zk_evm::aux_structures::LogQuery;

        let mut tree =
            InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

        println!("Empty root = {}", hex::encode(&tree.root()));
        println!(
            "Next enumeration index for empty tree = {}",
            tree.next_enumeration_index()
        );

        // let's create a leaf

        let dummy_leaf = ZkSyncStorageLeaf::from_value([1u8; 32]);
        let address = Address::from_low_u64_be(0x8002);
        let key = U256::zero();
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        println!(
            "Equivalence of query with address = {:?} and key = {}",
            address, key
        );
        println!(
            "Will insert a leaf with value {} at index (hashed index) {}",
            hex::encode(&dummy_leaf.value()),
            hex::encode(&index)
        );

        let query = tree.insert_leaf(&index, dummy_leaf);
        let root = tree.root();
        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root, &query);
        assert!(included);

        // and few more

        for i in 1..=5 {
            let mut value = U256::max_value();
            value -= U256::from(i as u64);
            let mut buffer = [0u8; 32];
            value.to_big_endian(&mut buffer[..]);
            let dummy_leaf = ZkSyncStorageLeaf::from_value(buffer);
            let address = Address::from_low_u64_be(u64::MAX / 2 + (i as u64));
            let key = U256::from_big_endian(&[255 - i; 32]);
            let index = LogQuery::derive_final_address_for_params(&address, &key);

            println!(
                "Equivalence of query with address = {:?} and key = {}",
                address, key
            );
            println!(
                "Will insert a leaf with value {} at index (hashed index) {}",
                hex::encode(&dummy_leaf.value()),
                hex::encode(&index)
            );

            let query = tree.insert_leaf(&index, dummy_leaf);
            let root = tree.root();
            let included = InMemoryStorageTree::<
                DEPTH,
                INDEX_BYTES,
                8,
                Blake2s256,
                ZkSyncStorageLeaf,
            >::verify_inclusion(&root, &query);
            assert!(included);

            println!("New root = {}", hex::encode(&tree.root()));
            assert_eq!(query.leaf.current_index(), 1 + (i as u64));
        }

        assert_eq!(tree.next_enumeration_index(), 7);

        // check 2 leafs: non-empty and empty

        let i = 2;
        let mut value = U256::max_value();
        value -= U256::from(i as u64);
        let mut buffer = [0u8; 32];
        value.to_big_endian(&mut buffer[..]);
        let address = Address::from_low_u64_be(u64::MAX / 2 + (i as u64));
        let key = U256::from_big_endian(&[255 - i; 32]);
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        let query = tree.get_leaf(&index);
        let root = tree.root();
        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root, &query);
        assert!(included);
        assert_eq!(&buffer, query.leaf.value());

        // and empty one

        let address = Address::from_low_u64_be(u64::MAX);
        let key = U256::from_big_endian(&[128; 32]);
        let index = LogQuery::derive_final_address_for_params(&address, &key);

        println!(
            "Equivalence of query with address = {:?} and key = {}",
            address, key
        );
        println!(
            "Will get a leaf at index (hashed index) {}",
            hex::encode(&index)
        );

        let query = tree.get_leaf(&index);
        let root = tree.root();
        let included = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::verify_inclusion(&root, &query);
        assert!(included);
        assert_eq!(query.leaf.value(), &[0u8; 32]);

        println!("Merkle proof path elements starting from the leafs:");
        for (level, el) in query.merkle_path.iter().take(4).enumerate() {
            println!("{}", hex::encode(el));
            if is_right_side_node(&query.index, level) {
                println!("Merkle path element is on the LEFT side");
            } else {
                println!("Merkle path element is on the RIGHT side");
            }
        }
    }

    #[test]
    fn test_via_circuit() {
        use crate::bytes_to_u128_le;
        use crate::encodings::initial_storage_write::*;
        use crate::encodings::repeated_storage_write::*;
        use crate::encodings::*;
        use sync_vm::testing::Bn256;
        use sync_vm::traits::CSWitnessable;

        const DEPTH: usize = 256;
        const INDEX_BYTES: usize = 32;
        // const DEPTH: usize = 8;
        // const INDEX_BYTES: usize = 1;

        let mut tree =
            InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

        let initial_root = tree.root();
        let initial_enumeration_counter = tree.next_enumeration_index();

        // let's create a leaf

        let dummy_leaf = ZkSyncStorageLeaf::from_value([1u8; 32]);
        use crate::ethereum_types::{Address, U256};
        use zk_evm::aux_structures::LogQuery;

        let address = Address::from_low_u64_be(0xffffff);
        let key = U256::from(1234u64);
        let index = LogQuery::derive_final_address_for_params(&address, &key);
        let read_query = tree.get_leaf(&index);

        let address = Address::from_low_u64_be(0x8002);
        let key = U256::zero();
        let index = LogQuery::derive_final_address_for_params(&address, &key);
        let write_query = tree.insert_leaf(&index, dummy_leaf);

        let new_root = tree.root();
        let new_enumeration_idnex = tree.next_enumeration_index();

        // form a witness

        let (mut cs, round_function, _) = create_test_artifacts_with_optimized_gate();

        let mut deduplicated_rollup_storage_queue_simulator = LogQueueSimulator::empty();

        // manually form a log

        use zk_evm::aux_structures::*;

        let log_query = LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: 0,
            aux_byte: STORAGE_AUX_BYTE,
            shard_id: 0,
            address,
            key,
            read_value: U256::zero(),
            written_value: U256::zero(),
            rw_flag: false,
            rollback: false,
            is_service: false,
        };

        deduplicated_rollup_storage_queue_simulator
            .push_and_output_intermediate_data(log_query, &round_function);

        let log_query = LogQuery {
            timestamp: Timestamp(0),
            tx_number_in_block: 0,
            aux_byte: STORAGE_AUX_BYTE,
            shard_id: 0,
            address,
            key,
            read_value: U256::zero(),
            written_value: U256::from_big_endian(dummy_leaf.value()),
            rw_flag: true,
            rollback: false,
            is_service: false,
        };

        deduplicated_rollup_storage_queue_simulator
            .push_and_output_intermediate_data(log_query, &round_function);

        use sync_vm::glue::storage_application::input::*;
        use sync_vm::scheduler::queues::FixedWidthEncodingGenericQueueWitness;

        let initial_fsm_state = StorageApplicationFSM::<Bn256>::placeholder_witness();

        let mut passthrough_input = StorageApplicationInputData::placeholder_witness();
        passthrough_input.initial_next_enumeration_counter = initial_enumeration_counter;
        let root_as_u128 = bytes_to_u128_le(&initial_root);
        passthrough_input.initial_root = root_as_u128;
        passthrough_input.storage_application_log_state =
            take_queue_state_from_simulator(&deduplicated_rollup_storage_queue_simulator);

        let mut final_fsm_state = StorageApplicationFSM::placeholder_witness();
        let first_writes_simulator = InitialStorageWritesSimulator::empty();
        let repeated_writes_simulator = RepeatedStorageWritesSimulator::empty();

        let root_as_u128 = bytes_to_u128_le(&new_root);
        final_fsm_state.root_hash = root_as_u128;
        final_fsm_state.next_enumeration_counter = new_enumeration_idnex;
        final_fsm_state.current_storage_application_log_state =
            take_queue_state_from_simulator(&deduplicated_rollup_storage_queue_simulator);
        final_fsm_state.repeated_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&repeated_writes_simulator);
        final_fsm_state.initial_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&first_writes_simulator);

        let mut passthrough_output = StorageApplicationOutputData::placeholder_witness();
        passthrough_output.final_next_enumeration_counter = new_enumeration_idnex;
        let root_as_u128 = bytes_to_u128_le(&new_root);
        passthrough_output.final_root = root_as_u128;
        passthrough_output.repeated_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&repeated_writes_simulator);
        passthrough_output.initial_writes_pubdata_queue_state =
            take_queue_state_from_simulator(&first_writes_simulator);

        let wit =
            transform_queue_witness(deduplicated_rollup_storage_queue_simulator.witness.iter());

        // transform merkle path

        use crate::bytes_to_u32_le;
        let path_read = (*read_query.merkle_path)
            .into_iter()
            .map(|el| bytes_to_u32_le(&el))
            .collect::<Vec<_>>();
        let path_write = (*write_query.merkle_path)
            .into_iter()
            .map(|el| bytes_to_u32_le(&el))
            .collect::<Vec<_>>();

        let wit = StorageApplicationCircuitInstanceWitness {
            closed_form_input: StorageApplicationCycleInputOutputWitness {
                start_flag: true,
                completion_flag: true,
                observable_input: passthrough_input,
                observable_output: passthrough_output,
                hidden_fsm_input: initial_fsm_state.clone(),
                hidden_fsm_output: final_fsm_state.clone(),
                _marker_e: (),
                _marker: std::marker::PhantomData,
            },
            storage_queue_witness: wit,
            leaf_indexes_for_reads: vec![0, 0],
            merkle_paths: vec![path_read, path_write],
        };

        use crate::abstract_zksync_circuit::concrete_circuits::StorageApplicationCircuit;

        let circuit = StorageApplicationCircuit::new(
            Some(wit),
            (4, USE_BLAKE2S_EXTRA_TABLES),
            round_function.clone(),
            None,
        );

        circuit.synthesize(&mut cs).unwrap();
    }

    #[test]
    fn reconstruct_state() {
        let mut tree = ZKSyncTestingTree::empty();

        println!("Initial root {}", hex::encode(&tree.root()));
        println!("Initial enumeration counter = {}", tree.next_enumeration_index());

        use std::io::BufRead;

        let mut minibatch_to_block = HashMap::new();
        
        let source = std::fs::File::open("zksync_public_miniblocks.csv").unwrap();
        let mut lines = std::io::BufReader::new(source).lines().map(|el| el.unwrap());
        lines.next().unwrap(); // skip 1st one
        for line in lines {
            let mut separated = line.split(",");
            let miniblock_number = separated.next().unwrap().parse::<u32>().unwrap();
            let batch_number = separated.next().unwrap().parse::<i32>().unwrap();
            assert!(separated.next().is_none());
            minibatch_to_block.insert(miniblock_number, batch_number);
        }

        let mut tmp = vec![];
        let mut block_batched_accesses = vec![];
        let source = std::fs::File::open("zksync_public_storage_logs.csv").unwrap();
        let mut previous_block = -1i32;
        let mut lines = std::io::BufReader::new(source).lines().map(|el| el.unwrap());
        lines.next().unwrap(); // skip 1st one

        for line in lines {
            let mut separated = line.split(",");
            let _ = separated.next().unwrap();
            let address = separated.next().unwrap();
            let key = separated.next().unwrap();
            let value = separated.next().unwrap();
            let op_number = separated.next().unwrap().parse::<u32>().unwrap();
            let _ = separated.next().unwrap();
            let miniblock_number = separated.next().unwrap().parse::<u32>().unwrap();
            let block_number = minibatch_to_block[&miniblock_number];
            let address = Address::from_str(address.strip_prefix("0x").unwrap()).unwrap();
            let key = U256::from_str_radix(&key.strip_prefix("0x").unwrap(), 16).unwrap();
            let value = U256::from_str_radix(&value.strip_prefix("0x").unwrap(), 16).unwrap();

            let record = (
                address,
                key,
                value,
                miniblock_number,
                op_number
            );

            if block_number != previous_block {
                previous_block = block_number;
                if tmp.len() != 0 {
                    let taken = std::mem::replace(&mut tmp, vec![]);
                    block_batched_accesses.push(taken);
                }
            }
            // always push
            tmp.push(record);
        }

        // take last one
        if tmp.len() != 0 {
            let taken = std::mem::replace(&mut tmp, vec![]);
            block_batched_accesses.push(taken);
        }

        // sort in each block

        for block_data in block_batched_accesses.iter_mut() {
            block_data.sort_by(|a, b| {
                // let a_address = U256::from_big_endian(&a.0.0);
                // let b_address = U256::from_big_endian(&b.0.0);

                match a.0.cmp(&b.0) {
                    std::cmp::Ordering::Equal => {
                        match a.1.cmp(&b.1) {
                            std::cmp::Ordering::Equal => {
                                match a.3.cmp(&b.3) {
                                    std::cmp::Ordering::Equal => {
                                        match a.4.cmp(&b.4) {
                                            std::cmp::Ordering::Equal => {
                                                panic!("must be unique")
                                            },
                                            a @ _ => a,
                                        }
                                    },
                                    a @ _ => a,
                                }
                            },
                            a @ _ => a,
                        }
                    },
                    a @ _ => a,
                }
            })
        }

        let mut key_set = HashSet::new();

        let mut extra_batched = vec![];
        // batch
        for (_block_number, block) in block_batched_accesses.into_iter().enumerate() {
            for el in block.iter() {
                let derived_key = LogQuery::derive_final_address_for_params(&el.0, &el.1);
                key_set.insert(derived_key);
            }

            let mut batched = vec![];
            let mut it = block.into_iter();
            let mut previous = it.next().unwrap();
            for el in it {
                if el.0 != previous.0 || el.1 != previous.1 {
                    batched.push((previous.0, previous.1, previous.2));
                }

                previous = el;
            }

            // finalize
            batched.push((previous.0, previous.1, previous.2));

            extra_batched.push(batched);
        }

        println!("Have {} unique keys in the tree", key_set.len());

        // we should merge now
        for (block_number, block) in extra_batched.into_iter().enumerate() {
            for (address, key, value) in block.into_iter() {
                let derived_key = LogQuery::derive_final_address_for_params(&address, &key);
                let existing_leaf = tree.get_leaf(&derived_key);
                let existing_value = U256::from_big_endian(existing_leaf.leaf.value());
                if existing_value == value {
                    // we downgrade to read
                    // println!("Downgrading to read")
                } else {
                    // we write
                    let mut tmp = [0u8; 32];
                    value.to_big_endian(&mut tmp);
                    let leaf = ZkSyncStorageLeaf::from_value(tmp);
                    if block_number == 6 {
                        let addr = Address::from_low_u64_be(0x8002);
                        let k = U256::zero();
                        if address == addr && key == k {
                            let root_before_inserting = tree.root();
                            println!("root before inserting = {}", hex::encode(&root_before_inserting));
                        }
                    }
                    let query = tree.insert_leaf(&derived_key, leaf);
                    assert!(tree.verify_inclusion_proxy(&tree.root(), &query));

                    if block_number == 6 {
                        let addr = Address::from_low_u64_be(0x8002);
                        let k = U256::zero();
                        if address == addr && key == k {
                            let root_after_inserting = tree.root();
                            println!("root after inserting = {}", hex::encode(&root_after_inserting));

                            // use crate::bytes_to_u32_le;
                            // let path: Vec<[u32; 8]> = (*query.merkle_path)
                            //     .into_iter()
                            //     .map(|el| bytes_to_u32_le(&el))
                            //     .collect::<Vec<_>>();

                            // dbg!(&path);
                        }

                    }
                }
            }

            println!("Final root at block number {} is {}", block_number, hex::encode(&tree.root()));
            println!("Tree contains {} elements", tree.leafs.len());
            println!("Next enumeration index is {}", tree.next_enumeration_index());

            if block_number == 5 || block_number == 6 {
                let address = Address::from_low_u64_be(0x8002);
                let derived_key = LogQuery::derive_final_address_for_params(&address, &U256::zero());
                let leaf = tree.get_leaf(&derived_key);
                let value = U256::from_big_endian(leaf.leaf.value());
                println!("At block {} address {:?}, key 0 has value 0x{:064x} and enumeration index {}", block_number, address, value, leaf.leaf.index);
            }

            if block_number == 5 {
                let address = Address::from_str("0x0000000000000000000000000000000000008006".strip_prefix("0x").unwrap()).unwrap();
                let key = U256::from_dec_str("10296424936580223820182946083978523599072867450410225418412986085349035080739").unwrap();
                let derived_key = LogQuery::derive_final_address_for_params(&address, &U256::zero());
                let leaf = tree.get_leaf(&derived_key);
                let value = U256::from_big_endian(leaf.leaf.value());
                println!("At block {} address {:?}, key {} has value 0x{:064x} and enumeration index {}", block_number, address, key, value, leaf.leaf.index);
            }
        }
    }
}

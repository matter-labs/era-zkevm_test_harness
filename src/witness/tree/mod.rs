
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
    fn node_hash(depth: usize, left_node: &[u8; HASH_OUTPUT_WIDTH], right_node: &[u8; HASH_OUTPUT_WIDTH]) -> [u8; HASH_OUTPUT_WIDTH];
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
> {
    fn empty() -> Self;
    fn next_enumeration_index(&self) -> u64;
    fn set_next_enumeration_index(&mut self, value: u64);
    fn root(&self) -> [u8; HASH_OUTPUT_WIDTH];
    fn get_leaf(&mut self, index: &[u8; INDEX_BYTES]) -> LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>;
    fn insert_leaf(&mut self, index: &[u8; INDEX_BYTES], leaf: L) -> LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>;
    fn insert_many_leafs(&mut self, indexes: &[[u8; INDEX_BYTES]], leafs: Vec<L>) -> Vec<LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>> {
        assert_eq!(indexes.len(), leafs.len());
        // let mut uniqueness_checker = std::collections::HashSet::new();
        let mut result = Vec::with_capacity(indexes.len());
        for (idx, leaf) in indexes.iter().zip(leafs.into_iter()) {
            // let is_unique = uniqueness_checker.insert(*idx);
            // assert!(is_unique);
            let query = self.insert_leaf(idx, leaf);
            result.push(query);
        }

        result
    }
    // fn filter_renumerate(&self, indexes: &[[u8; INDEX_BYTES]], leafs: &[L]) -> (u64, Vec<L>, Vec<L>);
    fn filter_renumerate<'a>(&self, indexes: impl Iterator<Item=&'a [u8; INDEX_BYTES]>, leafs: impl Iterator<Item=L>) -> (u64, Vec<([u8; INDEX_BYTES], L)>, Vec<L>);
    fn verify_inclusion(root: &[u8; 32], query: &LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>) -> bool;
    fn verify_inclusion_proxy(&self, root: &[u8; 32], query: &LeafQuery<DEPTH, INDEX_BYTES, LEAF_DATA_WIDTH, HASH_OUTPUT_WIDTH, L>) -> bool {
        Self::verify_inclusion(root, query)
    }
}

use std::{collections::HashMap};

pub struct InMemoryStorageTree<
    const DEPTH: usize, 
    const INDEX_BYTES: usize,
    const LEAF_METADATA_WIDTH: usize,     
    H: BinaryHasher<32>,
    L: EnumeratedBinaryLeaf<32>
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
    L: EnumeratedBinaryLeaf<32>
> InMemoryStorageTree<DEPTH, INDEX_BYTES, LEAF_METADATA_WIDTH, H, L> {
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

        let mut path: Box::<[[u8; 32]; DEPTH]> = Box::new([[0u8; 32]; DEPTH]);
        for level in 0..DEPTH {
            let pair_idx = create_neighbour_index(index, level);
            let pair_node_hash = self.get_path_element(level, pair_idx);
            path[level] = *pair_node_hash;
        }

        LeafQuery {
            leaf,
            first_write: false,
            index: *index,
            merkle_path: path
        }
    }

    fn verify_inclusion(root: &[u8; 32], query: &LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L>) -> bool {
        let mut leaf_bytes = vec![0u8; LEAF_METADATA_WIDTH + 32]; // can make a scratch space somewhere later on
        leaf_bytes[LEAF_METADATA_WIDTH..].copy_from_slice(query.leaf.value());

        let leaf_index_bytes = query.leaf.current_index().to_be_bytes();
        leaf_bytes[(LEAF_METADATA_WIDTH - 8)..LEAF_METADATA_WIDTH].copy_from_slice(&leaf_index_bytes);

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
    fn filter_renumerate<'a>(&self, mut indexes: impl Iterator<Item = &'a [u8; INDEX_BYTES]>, mut leafs: impl Iterator<Item = L>) -> (u64, Vec<([u8; INDEX_BYTES], L)>, Vec<L>) { 
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

    fn insert_leaf(&mut self, index: &[u8; INDEX_BYTES], leaf: L) -> LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L> {
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
        leaf_bytes[(LEAF_METADATA_WIDTH - 8)..LEAF_METADATA_WIDTH].copy_from_slice(&leaf_index_bytes);

        let leaf_hash = H::leaf_hash(&leaf_bytes);

        let mut current_hash = leaf_hash;
        let mut path: Box::<[[u8; 32]; DEPTH]> = Box::new([[0u8; 32]; DEPTH]);
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
            merkle_path: path
        }
    }
}

impl<
    const DEPTH: usize, 
    const INDEX_BYTES: usize,
    const LEAF_METADATA_WIDTH: usize,
    H: BinaryHasher<32>,
    L: EnumeratedBinaryLeaf<32>,
> BinarySparseStorageTree<
    DEPTH,
    INDEX_BYTES,
    32,
    LEAF_METADATA_WIDTH,
    32,
    H,
    L,
> for InMemoryStorageTree<DEPTH, INDEX_BYTES, LEAF_METADATA_WIDTH, H, L> {
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
    fn insert_leaf(&mut self, index: &[u8; INDEX_BYTES], leaf: L) -> LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L> {
        Self::insert_leaf(self, index, leaf)
    }
    // fn filter_renumerate(&self, indexes: &[[u8; INDEX_BYTES]], leafs: &[L]) -> (u64, Vec<L>, Vec<L>) {
    fn filter_renumerate<'a>(&self, indexes: impl Iterator<Item = &'a [u8; INDEX_BYTES]>, leafs: impl Iterator<Item = L>) -> (u64, Vec<([u8; INDEX_BYTES], L)>, Vec<L>) {
        Self::filter_renumerate(&self, indexes, leafs)
    }
    fn verify_inclusion(root: &[u8; 32], query: &LeafQuery<DEPTH, INDEX_BYTES, 32, 32, L>) -> bool {
        Self::verify_inclusion(root, query)
    }
}

use blake2::{Blake2s256, Digest};

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


use sha3::Keccak256;

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
    pub value: [u8; 32]
}

impl EnumeratedBinaryLeaf<32> for ZkSyncStorageLeaf {
    fn empty() -> Self {
        Self {
            index: 0,
            value: [0u8; 32]
        }
    }
    fn from_value(value: [u8; 32]) -> Self {
        Self {
            index: 0,
            value
        }
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
    use super::*;

    #[test]
    fn trivial() {
        const DEPTH: usize = 256;
        const INDEX_BYTES: usize = 32;
        // const DEPTH: usize = 8;
        // const INDEX_BYTES: usize = 1;

        let mut tree = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

        let tree2 = InMemoryStorageTree::<DEPTH, INDEX_BYTES, 8, Blake2s256, ZkSyncStorageLeaf>::empty();

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

}

pub type ZKSyncTestingTree = InMemoryStorageTree::<256, 32, 8, Blake2s256, ZkSyncStorageLeaf>;
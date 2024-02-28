# Circuits definitions crate

This crate contains the 'outer layer' for multiple circuits. The concrete circuits code is in `era-zkevm_circuits`
repository.

## Code structure

We have 13 different 'base layer' circuits (for example MainVM, Decomitter), and 3 recursive circuits (Leaf, Node and
Scheduler).

Base layer circuits are located in `src/base_layer`, Recursive circuits are in `src/recursion_layer`.

We also have 'AUX' circuits: compressors and wrapper, that are run on top of the final Scheduler proof, and they are
located in `src/aux_layer`.

![circuits](https://user-images.githubusercontent.com/128217157/275817097-0a543476-52e5-437b-a7d3-10603d5833fa.png)

`src/encodings` directory contain some helper structs that are used by the test harness (and should match the ones used
in circuits themselves).

## Circuit types

We have 12 different circuit types (in witness, you might notice 13, as one circuit (events_dedup_and_sort) is used for
both L1 messages and events).

| Circuit name             | Location                     | Description                                                                                                                                                          |
| ------------------------ | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Main VM                  | vm_main.rs                   | Executes OpCodes from the VM                                                                                                                                         |
| CodeDecommittmentsSorter | sort_code_decommit.rs        | Verifies the order of requests for code decommitment (fetching bytecode based on hash).                                                                              |
| CodeDecommiter           | code_decommiter.rs           | Unpacks the bytecode matching a given hash into memory.                                                                                                              |
| LogDemuxer               | log_demux.rs                 | Splits the queue into 6 output ones (like keccak, sha, storage).                                                                                                     |
| KeccakRoundFunction      | keccak256_round_functions.rs | Round of the keccak hash                                                                                                                                             |
| Sha256RoundFunction      | sha256_round_function.rs     | Round of sha256 hash                                                                                                                                                 |
| ECRecover                | ecrecover.rs                 | Verifies ECRecover                                                                                                                                                   |
| RAMPermutation           | ram_permutation.rs           | Verifies the correctness of the RAM accesses - looking at the access queue, and checking that correct bytes values were read                                         |
| StorageSorter            | storage_sort_dedup.rs        | Similar to RAM permutation, but for storage - checking that correct bytes were stored / read.                                                                        |
| StorageApplication       | storage_apply.rs             | Verifies the final merkle root and storage diffs based on the data that was written during computation.                                                              |
| EventsSorter             | events_sort_dedup.rs         | Verifies that a given 'unsorted' queue is matching the sorted one, without any repetitions. In this case, used for System Events.                                    |
| L1MessagesSorter         | events_sort_dedup.rs         | It reuses the circuit above, but this time to sort user generated events (L2 -> L1 messages).                                                                        |
| L1MessageHasher          | linear_hasher.rs             | Verifies that linear hash of L1 messages matches the content of the queue.                                                                                           |

3 recursive circuits:

| Circuit name | Location      | Description                                               |
| ------------ | ------------- | --------------------------------------------------------- |
| Leaf         | leaf_layer.rs | Aggregates 32 basic circuits of the same type             |
| Node         | node_layer.rs | Aggregates 32 leaf (or node) circruits of the same type   |
| Scheduler    | scheduler.rs  | Aggregates 13 nodes (1 from each type) into a final proof |

And  'wrapper'/AUX circuits on top:

| Circuit name | Location       | Description                                                                              |
| ------------ | -------------- | ---------------------------------------------------------------------------------------- |
| Compression  | compression.rs | Compresses the final scheduler proof                                                     |
| Wrapper      | wrapper.rs     | Wraps the compressed proof into a SNARK to be verifierd on L1. (This is a SNARK circuit) |

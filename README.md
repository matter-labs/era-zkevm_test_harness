# How to use

This repo contains a mixture of witness generation harness (that runs block's code and produces circuit-specific witness parts) and basic examples of full block proof workflow execution, that is:
- create a necessary number of circuits of each unique basic type (so called scheduling)
- aggreagte proofs over them
- run the final state "scheduler" circuit that verifies logical validity of scheduling (feeding outputs to inputs) and attest that aggregation is a result of recursive verification of the scheduled sequence

It's easy to run

Get some modern Rust version (at least that supports Rust 2021 and const generics, but usually latest nightly is also a good option) and run

```
cargo test basic_test  --release -- --nocapture
```

It may be a little verbose, but it's a full end to end test that:
- sets up basic environment - empty state tree with added "system" level contracts 
- creates some dummy information about previous state of the chain (only state root is necessary)
- runs a contract from [https://github.com/vladbochok/test-contract](https://github.com/vladbochok/test-contract) as from address 0x8001 that is a contract call without a calldata and particular meaning, but touches the most interesting parts of the system: external calls, reverts, precompiles, storage access, events, L2 to L1 messages
- produces witness
- makes as many circuits as needed given some (arbitrary) set of capacity parameters of the form "principal operations per circuit of type T"
- generated verification keys for both basic circuits, recursive aggregation circuits, and "scheduler"
- makes proofs of every stage - basic circuits -> aggregation (leafs and nodes) -> scheduler
- each proof is verified against the corresponding verification key on creation

One can see a lot of `.json` files in the `setup` and `test_proofs` folders. Those are all the intermediate proofs, and if proof exists then example script will skip it's recomputation (whether it's a proof or verification key). So to run the full workflow one can remove all of those, or some of those.

### Running regeneration of setup files
Will regenerate setup parameters (geometry, verification keys, finalization hints and padding proofs)
```shell
cargo test --release run_capacity_estimation
cargo test --release test_run_create_base_layer_vks_and_proofs
cargo test --release test_run_create_recursion_layer_vks_and_proofs
```
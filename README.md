# zkSync Era: A ZK Rollup For Scaling Ethereum

[![Logo](eraLogo.png)](https://zksync.io/)

zkSync Era is a layer 2 rollup that uses zero-knowledge proofs to scale Ethereum without compromising on security or
decentralization. Since it's EVM compatible (Solidity/Vyper), 99% of Ethereum projects can redeploy without refactoring
or re-auditing a single line of code. zkSync Era also uses an LLVM-based compiler that will eventually let developers
write smart contracts in C++, Rust and other popular languages.

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
cargo run --release --bin geometry_config_generator
cargo test --release test_run_create_base_layer_vks_and_proofs
cargo test --release test_run_create_recursion_layer_vks_and_proofs
```

## License

zkSync Era is distributed under the terms of either

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Official Links

- [Website](https://zksync.io/)
- [GitHub](https://github.com/matter-labs)
- [Twitter](https://twitter.com/zksync)
- [Twitter for Devs](https://twitter.com/zkSyncDevs)
- [Discord](https://join.zksync.dev)

## Disclaimer

zkSync Era has been through lots of testing and audits. Although it is live, it is still in alpha state and will go
through more audits and bug bounties programs. We would love to hear our community's thoughts and suggestions about it!
It is important to state that forking it now can potentially lead to missing important security updates, critical
features, and performance improvements.

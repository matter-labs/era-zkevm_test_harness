# Proof wrapping

This directory is responsible for wrapping the final FRI proof into a SNARK.

The main entry point is the `wrap_proof` method in mod.rs, that accepts the scheduler circuit proof.

This method is handling both compression and wrapping.

## Testing
End-to-end tests for proof compression are in proof_compression_tests.rs

By default, they test multiple levels of compression based on the files located in testdata/proof_compression.

If you need to update the files, please re-run the test with `UPDATE_TESTDATA` environment variable set:


```
UPDATE_TESTDATA=true RUST_BACKTRACE=1 cargo test --release perform_step_4_compression  --  --nocapture
```
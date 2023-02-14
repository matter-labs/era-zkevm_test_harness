use super::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{fs, path::PathBuf};
use zk_evm::ethereum_types::Address;

const TEST_ARTIFACTS_DIR: &'static str = "./src/tests/complex_tests/test_artifacts/";

#[derive(Debug, Serialize, Deserialize)]
pub struct TestArtifact {
    pub entry_point_address: Address,
    #[serde(deserialize_with = "deserialize_bytecode")]
    pub entry_point_code: Vec<[u8; 32]>,
    #[serde(deserialize_with = "deserialize_bytecode")]
    pub default_account_code: Vec<[u8; 32]>,
    #[serde(deserialize_with = "deserialize_bytecodes_with_addresses")]
    pub predeployed_contracts: HashMap<Address, Vec<[u8; 32]>>,
}

pub fn read_test_artifact(test_name: &str) -> TestArtifact {
    let mut path = PathBuf::from(TEST_ARTIFACTS_DIR);

    path.push(test_name);
    path.set_extension("json");

    if !path.exists() {
        panic!(
            "The test artifacts directory {:?} does not exist",
            path.as_path()
        );
    }

    let text = fs::read_to_string(path.as_path())
        .unwrap_or_else(|_| panic!("Failed to read the test artifact"));
    serde_json::from_str(text.as_str()).unwrap()

    // serde_json::from_str(text.as_str()).unwrap_or_else(|_| panic!("Failed to deserialize the test artifact"))
}

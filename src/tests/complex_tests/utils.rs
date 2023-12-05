use crate::helper::artifact_utils::TestArtifact;
use crate::helper::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use std::{
    fs,
    path::{Path, PathBuf},
};

const TEST_CONTRACT_REPO: &str = "https://github.com/matter-labs/test-contract";
const VERSION: &str = "v1.4.1";
const BASIC_TEST_JSON_LOCATION: &str = "test_artifacts/basic_test.json";
const BASIC_TEST_COMMIT_HASH_LOCATION: &str = "test_artifacts/basic_test_commit_hash";

pub fn read_basic_test_artifact() -> TestArtifact {
    let no_hash = !Path::new(BASIC_TEST_COMMIT_HASH_LOCATION).exists();
    if no_hash {
        let hash = get_latest_commit_hash(VERSION);
        fs::write(BASIC_TEST_COMMIT_HASH_LOCATION, hash)
            .expect("should be able to write commit hash");
    }

    let commit_hash_bytes =
        fs::read(BASIC_TEST_COMMIT_HASH_LOCATION).expect("should be able to read commit hash");
    let commit_hash =
        std::str::from_utf8(&commit_hash_bytes).expect("commit hash should be utf8 encoded string");
    if !Path::new(BASIC_TEST_JSON_LOCATION).exists()
        || get_latest_commit_hash(VERSION) != commit_hash
        || no_hash
    {
        let url = TEST_CONTRACT_REPO.to_owned() + "/blob/" + VERSION + "/contracts";
        let contract_json = compile_latest_test_contract(&url);
        fs::write(BASIC_TEST_JSON_LOCATION, contract_json)
            .expect("should be able to write contract json");
    }

    let basic_test_bytes = fs::read(BASIC_TEST_JSON_LOCATION).expect("failed reading file");
    let text = std::str::from_utf8(&basic_test_bytes)
        .expect("basic test json should be utf8 encoded string");
    serde_json::from_str(text).unwrap()
}

fn get_latest_commit_hash(version: &str) -> String {
    let client = reqwest::blocking::Client::builder()
        .user_agent("a")
        .build()
        .expect("should be able to build client");
    let body = client
        .get("https://api.github.com/repos/matter-labs/test-contract/commits/".to_owned() + VERSION)
        .send()
        .expect("should be able to fetch commit hash")
        .text()
        .expect("should be able to extract text from get request");

    // The response is a huge JSON object but the commit hash is right at the start so we just cut
    // it out of the body.
    body[8..47].to_owned()
}

// TODO
fn compile_latest_test_contract(url: &str) -> String {
    return "".to_owned();
}

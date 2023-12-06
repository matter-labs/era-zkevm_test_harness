use crate::helper::artifact_utils::TestArtifact;
use crate::helper::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use compiler_solidity::SolcCompiler as Compiler;
use compiler_solidity::SolcPipeline as Pipeline;
use compiler_solidity::SolcStandardJsonInput as Input;
use compiler_solidity::SolcStandardJsonInputLanguage as Language;
use compiler_solidity::SolcStandardJsonInputSettings as Settings;
use compiler_solidity::SolcStandardJsonInputSettingsOptimizer as Optimizer;
use compiler_solidity::SolcStandardJsonInputSource as Source;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

const TEST_CONTRACT_REPO: &str = "https://github.com/matter-labs/test-contract";
const VERSION: &str = "v1.4.1";
const BASIC_TEST_JSON_LOCATION: &str = "test_artifacts/basic_test.json";
const BASIC_TEST_COMMIT_HASH_LOCATION: &str = "test_artifacts/basic_test_commit_hash";

const SOLC_VERSION: &str = "0.8.8"; // as used in test-contract

#[derive(Debug)]
enum ArtifactError {
    ContractDownloadFailed,
    SolcDownloadFailed,
    ContractsDeletionFailed,
    SolcDeletionFailed,
    UnsupportedArch,
    UnsupportedOS,
}

pub fn read_basic_test_artifact() -> TestArtifact {
    let no_hash = !Path::new(BASIC_TEST_COMMIT_HASH_LOCATION).exists();
    let latest_hash = get_latest_commit_hash();
    let hash = if no_hash {
        latest_hash.clone()
    } else {
        let bytes =
            fs::read(BASIC_TEST_COMMIT_HASH_LOCATION).expect("should be able to read commit hash");
        std::str::from_utf8(&bytes)
            .expect("commit hash should be utf8-encoded")
            .to_owned()
    };

    if !Path::new(BASIC_TEST_JSON_LOCATION).exists() || latest_hash != hash || no_hash {
        let contract_json =
            compile_latest_test_contract().expect("should be able to compile contract");

        fs::write(BASIC_TEST_JSON_LOCATION, contract_json)
            .expect("should be able to write contract json");
        fs::write(BASIC_TEST_COMMIT_HASH_LOCATION, latest_hash)
            .expect("should be able to write new commit hash");
    }

    let basic_test_bytes = fs::read(BASIC_TEST_JSON_LOCATION).expect("failed reading file");
    let text = std::str::from_utf8(&basic_test_bytes)
        .expect("basic test json should be utf8 encoded string");
    serde_json::from_str(text).unwrap()
}

fn get_latest_commit_hash() -> String {
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

fn compile_latest_test_contract() -> Result<String, ArtifactError> {
    let binary_name = get_solc_binary_name()?;
    download_solc_binary(&binary_name)?;
    let mut solc = Compiler::new(binary_name.clone());

    download_contracts()?;
    let sources = construct_sources_map();

    let output = solc
        .standard_json(
            Input {
                language: Language::Solidity,
                sources,
                settings: Settings {
                    libraries: None,
                    remappings: None,
                    output_selection: None,
                    via_ir: None,
                    optimizer: Optimizer {
                        enabled: true,
                        mode: Some(200 as char),
                        details: Default::default(),
                    },
                    metadata: None,
                },
                suppressed_warnings: None,
            },
            Pipeline::Yul,
            None,
            vec![],
            None,
        )
        .expect("should be able to compile contracts");
    println!("{:?}", output);
    delete_solc_binary(&binary_name)?;
    delete_contracts_folder()?;
    panic!("DEAD");
    // should return bytecode here
    Ok("".to_owned())
}

fn download_contracts() -> Result<(), ArtifactError> {
    let url = TEST_CONTRACT_REPO.to_owned() + "/blob/" + VERSION + "/contracts";
    Err(ArtifactError::ContractDownloadFailed)
}

fn delete_contracts_folder() -> Result<(), ArtifactError> {
    fs::remove_dir_all("contracts").map_err(|_| ArtifactError::ContractsDeletionFailed)
}

fn download_solc_binary(binary_name: &str) -> Result<(), ArtifactError> {
    Err(ArtifactError::SolcDownloadFailed)
}

fn delete_solc_binary(binary_name: &str) -> Result<(), ArtifactError> {
    fs::remove_file(binary_name).map_err(|_| ArtifactError::SolcDeletionFailed)
}

fn get_solc_binary_name() -> Result<String, ArtifactError> {
    // as far as i know, no arm pre-compiles for solc
    if std::env::consts::ARCH != "x86_64" {
        return Err(ArtifactError::UnsupportedArch);
    }

    match std::env::consts::OS {
        "linux" => Ok("solc-static-linux".to_owned()),
        "macos" => Ok("solc-macos".to_owned()),
        "windows" => Ok("solc-windows.exe".to_owned()),
        _ => Err(ArtifactError::UnsupportedOS),
    }
}

fn construct_sources_map() -> BTreeMap<String, Source> {
    let mut sources = BTreeMap::new();
    sources.insert(
        "contracts/HeapLibrary.sol".to_owned(),
        Source::try_from(Path::new("./contracts/HeapLibrary.sol"))
            .expect("should be able to grab source from contract"),
    );
    sources.insert(
        "contracts/Helper.sol".to_owned(),
        Source::try_from(Path::new("contracts/Helper.sol"))
            .expect("should be able to grab source from contract"),
    );
    sources.insert(
        "contracts/Main.sol".to_owned(),
        Source::try_from(Path::new("contracts/Main.sol"))
            .expect("should be able to grab source from contract"),
    );
    sources.insert(
        "contracts/ReentrancyGuard.sol".to_owned(),
        Source::try_from(Path::new("contracts/ReentrancyGuard.sol"))
            .expect("should be able to grab source from contract"),
    );

    sources
}

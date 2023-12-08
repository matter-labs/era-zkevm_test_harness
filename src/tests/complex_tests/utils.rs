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
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

const TEST_CONTRACT_REPO: &str = "https://github.com/matter-labs/test-contract";
const BRANCH: &str = "v1.4.1";
const BASIC_TEST_JSON_LOCATION: &str = "src/tests/complex_tests/test_artifacts/basic_test.json";
const BASIC_TEST_COMMIT_HASH_LOCATION: &str =
    "src/tests/complex_tests/test_artifacts/basic_test_commit_hash";

const SOLC_VERSION: &str = "v0.8.17";
const FILE_NAMES: [&str; 4] = [
    "ReentrancyGuard.sol",
    "Helper.sol",
    "HeapLibrary.sol",
    "Main.sol",
];

#[derive(Debug)]
enum ArtifactError {
    DownloadFailed(String),
    CompilationFailed(String),
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
        let binary_name =
            get_solc_binary_name().expect("should be able to figure out a solc binary");

        // delay unwrapping so we always clean up after ourselves even in case of failure
        let contract_json = compile_latest_test_contract(&binary_name);
        delete_solc_binary(&binary_name);
        delete_contracts_folder();
        let contract_json = match contract_json {
            Ok(c) => c,
            Err(e) => panic!("{:?}", e),
        };

        // TODO: we need to also fetch precompiles and correctly put everything together in the
        // JSON, raw contract data won't do
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
        .get("https://api.github.com/repos/matter-labs/test-contract/commits/".to_owned() + BRANCH)
        .send()
        .expect("should be able to fetch commit hash")
        .text()
        .expect("should be able to extract text from get request");

    // The response is a huge JSON object but the commit hash is right at the start so we just cut
    // it out of the body.
    body[8..47].to_owned()
}

fn compile_latest_test_contract(solc_binary_name: &str) -> Result<String, ArtifactError> {
    download_solc_binary(solc_binary_name)?;
    let mut full_path = std::env::current_dir().unwrap();
    full_path.push(solc_binary_name);
    // XXX windows?
    fs::set_permissions(full_path.clone(), fs::Permissions::from_mode(0o777)).unwrap();
    let mut solc = Compiler::new(full_path.to_str().unwrap().to_owned());

    download_contracts()?;

    let file_names = FILE_NAMES
        .iter()
        .map(|name| {
            let mut path = std::env::current_dir().unwrap();
            path.push("contracts");
            path.push(name);
            path
        })
        .collect::<Vec<PathBuf>>();
    let mut output = compiler_solidity::standard_output(
        &file_names,
        vec![],
        &mut solc,
        true,
        compiler_llvm_context::OptimizerSettings::cycles(),
        false,
        true,
        false,
        None,
        vec![],
        None,
        None,
        None,
        None,
    )
    .map_err(|e| ArtifactError::CompilationFailed(e.to_string()))?;

    println!("{:?}", output);

    panic!();
    // should return bytecode here
    Ok("".to_owned())
}

fn download_contracts() -> Result<(), ArtifactError> {
    fs::create_dir("contracts").map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;

    for file_name in FILE_NAMES {
        let url = "https://raw.githubusercontent.com/matter-labs/test-contract/".to_owned()
            + BRANCH
            + "/contracts/basic_test/"
            + file_name;
        download_to_disk(&url, &("contracts/".to_owned() + file_name))?;
    }

    Ok(())
}

fn delete_contracts_folder() {
    let _ = fs::remove_dir_all("contracts");
}

fn download_solc_binary(binary_name: &str) -> Result<(), ArtifactError> {
    let url = "https://github.com/ethereum/solidity/releases/download/".to_owned()
        + SOLC_VERSION
        + "/"
        + binary_name;
    download_to_disk(&url, binary_name)
}

fn delete_solc_binary(binary_name: &str) {
    let _ = fs::remove_file(binary_name);
}

fn download_to_disk(url: &str, write_location: &str) -> Result<(), ArtifactError> {
    use curl::easy::Easy;

    let mut file_data = vec![];
    let mut easy = Easy::new();
    easy.url(&url)
        .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
    easy.follow_location(true)
        .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
    {
        let mut transfer = easy.transfer();
        transfer
            .write_function(|data| {
                file_data.extend_from_slice(data);
                Ok(data.len())
            })
            .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
        transfer
            .perform()
            .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
    }

    fs::write(write_location, file_data).map_err(|e| ArtifactError::DownloadFailed(e.to_string()))
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
    for file_name in FILE_NAMES {
        sources.insert(
            "contracts/".to_owned() + file_name,
            Source::try_from(Path::new(&("./contracts/".to_owned() + file_name)))
                .expect("should be able to grab source from contract"),
        );
    }

    sources
}

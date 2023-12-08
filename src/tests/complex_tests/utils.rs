use super::consts::*;
use crate::helper::artifact_utils::TestArtifact;
use crate::helper::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use crate::zk_evm::ethereum_types::Address;
use compiler_solidity::SolcCompiler as Compiler;
use compiler_solidity::SolcPipeline as Pipeline;
use compiler_solidity::SolcStandardJsonInput as Input;
use compiler_solidity::SolcStandardJsonInputLanguage as Language;
use compiler_solidity::SolcStandardJsonInputSettings as Settings;
use compiler_solidity::SolcStandardJsonInputSettingsOptimizer as Optimizer;
use compiler_solidity::SolcStandardJsonInputSource as Source;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

const TEST_CONTRACT_REPO: &str = "https://github.com/matter-labs/test-contract";
const BRANCH: &str = "v1.4.1";
const BASIC_TEST_JSON_LOCATION: &str = "src/tests/complex_tests/test_artifacts/basic_test.json";
const BASIC_TEST_COMMIT_HASH_LOCATION: &str =
    "src/tests/complex_tests/test_artifacts/basic_test_commit_hash";
const SOLC_VERSION: &str = "v0.8.17";
const ZKSOLC_VERSION: &str = "v1.3.18";
const FILE_NAMES: [&str; 4] = [
    "ReentrancyGuard.sol",
    "Helper.sol",
    "HeapLibrary.sol",
    "Main.sol",
];

const ENTRY_POINT_ADDRESS: &str = "0xc54E30ABB6a3eeD1b9DC0494D90c9C22D76FbA7e";

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
        println!("test json is outdated, updating...");
        let solc_binary_name =
            get_solc_binary_name().expect("should be able to figure out a solc binary");
        let zksolc_binary_name =
            get_zksolc_binary_name().expect("should be able to figure out a zksolc binary");

        // delay checking result so that we clean up in all cases
        let result = compile_latest_test_contract(&solc_binary_name, &zksolc_binary_name);
        delete_binary(&solc_binary_name);
        delete_binary(&zksolc_binary_name);
        delete_contracts_folder();
        match result {
            Ok(bytecode) => {
                let artifact = create_artifact(bytecode);
                let artifact_string = serde_json::to_string(&artifact)
                    .expect("should be able to stringify test artifact");
                fs::write(BASIC_TEST_JSON_LOCATION, artifact_string)
                    .expect("should be able to write contract json");
                fs::write(BASIC_TEST_COMMIT_HASH_LOCATION, latest_hash)
                    .expect("should be able to write new commit hash");
            }
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }

    let basic_test_bytes = fs::read(BASIC_TEST_JSON_LOCATION).expect("failed reading file");
    let text = std::str::from_utf8(&basic_test_bytes)
        .expect("basic test json should be utf8 encoded string");
    serde_json::from_str(text).unwrap()
}

fn create_artifact(bytecode: Vec<u8>) -> TestArtifact {
    let segment_byte_vector = |bytes: Vec<u8>| -> Vec<[u8; 32]> {
        bytes
            .chunks(32)
            .map(|chunk| {
                let mut arr = [0u8; 32];
                arr[..chunk.len()].copy_from_slice(chunk);
                arr
            })
            .collect()
    };

    let entry_point_code = segment_byte_vector(bytecode);
    let default_account_code =
        segment_byte_vector(hex::decode(DEFAULT_ACCOUNT_CODE[2..].to_owned()).unwrap());
    let predeployed = PREDEPLOYED_CONTRACTS
        .iter()
        .map(|(address, code)| {
            let address = Address::from_str(address).unwrap();
            let code = segment_byte_vector(hex::decode(code[2..].to_owned()).unwrap());
            (address, code)
        })
        .collect::<Vec<(Address, Vec<[u8; 32]>)>>();
    TestArtifact {
        entry_point_address: Address::from_str(ENTRY_POINT_ADDRESS)
            .expect("should be able to decode from constant entry point address"),
        entry_point_code,
        default_account_code,
        predeployed_contracts: HashMap::from_iter(predeployed),
    }
}

fn get_latest_commit_hash() -> String {
    let client = reqwest::blocking::Client::builder()
        .user_agent("a") // this call needs a user agent but it doesn't matter what it is really
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

fn set_binary_perms(binary_name: &str) -> Result<PathBuf, ArtifactError> {
    let mut full_path =
        std::env::current_dir().map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
    full_path.push(binary_name);
    match std::env::consts::OS {
        "linux" | "macos" => {
            fs::set_permissions(full_path.clone(), fs::Permissions::from_mode(0o777))
                .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
        }
        // XXX windows?
        _ => {}
    }

    Ok(full_path)
}

fn compile_latest_test_contract(
    solc_binary_name: &str,
    zksolc_binary_name: &str,
) -> Result<Vec<u8>, ArtifactError> {
    download_solc_binary(solc_binary_name)?;
    let solc_compiler_path = set_binary_perms(solc_binary_name)?;
    let mut solc = Compiler::new(
        solc_compiler_path
            .to_str()
            .ok_or(ArtifactError::CompilationFailed(
                "could not convert solc compiler path to string".to_owned(),
            ))?
            .to_owned(),
    );
    download_contracts()?;

    // set zksolc as executable for compiler
    download_zksolc_binary(zksolc_binary_name)?;
    let zksolc_compiler_path = set_binary_perms(zksolc_binary_name)?;
    compiler_solidity::EXECUTABLE
        .set(zksolc_compiler_path)
        .map_err(|_| {
            ArtifactError::CompilationFailed("couldn't set zksolc as executable".to_owned())
        })?;

    // create full filepaths for all contracts
    // NOTE: the constant should be updated if we add more contracts
    let mut file_names = vec![];
    for name in FILE_NAMES {
        let mut path =
            std::env::current_dir().map_err(|e| ArtifactError::CompilationFailed(e.to_string()))?;
        path.push("contracts");
        path.push(name);
        file_names.push(path);
    }

    Ok(compiler_solidity::standard_output(
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
    .map_err(|e| ArtifactError::CompilationFailed(e.to_string()))?
    .contracts[&(file_names[3]
        .to_str()
        .ok_or(ArtifactError::CompilationFailed(
            "could not convert main contract path to string".to_owned(),
        ))?
        .to_owned()
        + ":Main")]
        .build
        .bytecode
        .clone())
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

fn download_zksolc_binary(binary_name: &str) -> Result<(), ArtifactError> {
    let url = "https://github.com/matter-labs/zksolc-bin/releases/download/".to_owned()
        + ZKSOLC_VERSION
        + "/"
        + binary_name;
    download_to_disk(&url, binary_name)
}

fn delete_binary(binary_name: &str) {
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
    match std::env::consts::OS {
        "linux" => {
            if std::env::consts::ARCH == "x86_64" {
                Ok("solc-static-linux".to_owned())
            } else {
                Err(ArtifactError::UnsupportedArch)
            }
        }
        "macos" => {
            if std::env::consts::ARCH == "arm" {
                Ok("solc-macos".to_owned())
            } else {
                Err(ArtifactError::UnsupportedArch)
            }
        }
        "windows" => Ok("solc-windows.exe".to_owned()),
        _ => Err(ArtifactError::UnsupportedOS),
    }
}

fn get_zksolc_binary_name() -> Result<String, ArtifactError> {
    match std::env::consts::OS {
        "linux" => {
            if std::env::consts::ARCH == "x86_64" {
                Ok("zksolc-linux-amd64-musl-".to_owned() + ZKSOLC_VERSION)
            } else {
                // there is no precompiled arm build for linux solc so we can't proceed if we arent
                // on an amd64 platform
                Err(ArtifactError::UnsupportedArch)
            }
        }
        "macos" => {
            if std::env::consts::ARCH == "arm" {
                Ok("zksolc-macosx-arm64-".to_owned() + ZKSOLC_VERSION)
            } else {
                Err(ArtifactError::UnsupportedArch)
            }
        }
        "windows" => {
            if std::env::consts::ARCH == "x86_64" {
                Ok("zksolc-windows-amd64-gnu-".to_owned() + ZKSOLC_VERSION + ".exe")
            } else {
                Err(ArtifactError::UnsupportedArch)
            }
        }
        _ => Err(ArtifactError::UnsupportedOS),
    }
}

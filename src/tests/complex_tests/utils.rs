use crate::helper::artifact_utils::TestArtifact;
use crate::helper::serialize_utils::{deserialize_bytecode, deserialize_bytecodes_with_addresses};
use crate::zk_evm::ethereum_types::Address;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};
use walkdir::WalkDir;

const TEST_CONTRACT_COMMITS_URL: &str =
    "https://api.github.com/repos/matter-labs/test-contract/commits/";
const BRANCH: &str = "v1.4.1";
const BASIC_TEST_JSON_LOCATION: &str = "src/tests/complex_tests/test_artifacts/basic_test.json";
const BASIC_TEST_COMMIT_HASH_LOCATION: &str =
    "src/tests/complex_tests/test_artifacts/basic_test_commit_hash";
const SOLC_VERSION: &str = "v0.8.20";
const ZKSOLC_VERSION: &str = "v1.3.18";
const TEST_CONTRACT_FILE_NAMES: [&str; 4] = [
    "ReentrancyGuard.sol",
    "Helper.sol",
    "HeapLibrary.sol",
    "Main.sol",
];
const SYSTEM_CONTRACTS_BRANCH: &str = "v1-4-1-integration";
const SYSTEM_CONTRACTS_URL: &str = "https://github.com/matter-labs/era-system-contracts/";
const SYSTEM_CONTRACTS_COMMITS_URL: &str =
    "https://api.github.com/repos/matter-labs/era-system-contracts/commits/";
const SYSTEM_CONTRACTS_COMMIT_HASH_LOCATION: &str =
    "src/tests/complex_tests/test_artifacts/system_contracts_commit_hash";
const SYSTEM_CONTRACTS_PATH: &str = "./era-system-contracts/contracts";
const COMPILER_METADATA_LOCATION: &str = "src/tests/complex_tests/test_artifacts/compiler_metadata";

const PREDEPLOYED_CONTRACTS_SOL: [(&str, &str); 12] = [
    (
        "AccountCodeStorage",
        "0x0000000000000000000000000000000000008002",
    ),
    ("NonceHolder", "0x0000000000000000000000000000000000008003"),
    (
        "KnownCodesStorage",
        "0x0000000000000000000000000000000000008004",
    ),
    (
        "ImmutableSimulator",
        "0x0000000000000000000000000000000000008005",
    ),
    (
        "ContractDeployer",
        "0x0000000000000000000000000000000000008006",
    ),
    ("L1Messenger", "0x0000000000000000000000000000000000008008"),
    (
        "MsgValueSimulator",
        "0x0000000000000000000000000000000000008009",
    ),
    ("L2EthToken", "0x000000000000000000000000000000000000800a"),
    (
        "SystemContext",
        "0x000000000000000000000000000000000000800b",
    ),
    (
        "BootloaderUtilities",
        "0x000000000000000000000000000000000000800c",
    ),
    ("Compressor", "0x000000000000000000000000000000000000800e"),
    (
        "ComplexUpgrader",
        "0x000000000000000000000000000000000000800f",
    ),
];
const PREDEPLOYED_CONTRACTS_YUL: [(&str, &str); 6] = [
    ("Ecrecover", "0x0000000000000000000000000000000000000001"),
    ("SHA256", "0x0000000000000000000000000000000000000002"),
    ("EcAdd", "0x0000000000000000000000000000000000000006"),
    ("EcMul", "0x0000000000000000000000000000000000000007"),
    ("EventWriter", "0x000000000000000000000000000000000000800d"),
    ("Keccak256", "0x0000000000000000000000000000000000008010"),
];

const ENTRY_POINT_ADDRESS: &str = "0xc54E30ABB6a3eeD1b9DC0494D90c9C22D76FbA7e";

#[derive(Debug)]
enum ArtifactError {
    DownloadFailed(String),
    CompilationFailed(String),
    UnsupportedArch,
    UnsupportedOS,
}

#[derive(Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CompilerMetadata {
    solc_compiler_version: String,
    zksolc_compiler_version: String,
}

pub fn read_basic_test_artifact() -> TestArtifact {
    let current_compiler_metadata = CompilerMetadata {
        solc_compiler_version: SOLC_VERSION.to_owned(),
        zksolc_compiler_version: ZKSOLC_VERSION.to_owned(),
    };
    let last_compiler_metadata =
        serde_json::from_slice(&fs::read(COMPILER_METADATA_LOCATION).unwrap_or_default())
            .unwrap_or_default();

    let (basic_test_hash, latest_basic_test_hash) = retrieve_latest_commit_hash(
        &(TEST_CONTRACT_COMMITS_URL.to_owned() + BRANCH),
        BASIC_TEST_COMMIT_HASH_LOCATION,
    );
    let (system_contract_hash, latest_system_contract_hash) = retrieve_latest_commit_hash(
        &(SYSTEM_CONTRACTS_COMMITS_URL.to_owned() + SYSTEM_CONTRACTS_BRANCH),
        SYSTEM_CONTRACTS_COMMIT_HASH_LOCATION,
    );

    if !Path::new(BASIC_TEST_JSON_LOCATION).exists()
        || !Path::new(SYSTEM_CONTRACTS_COMMIT_HASH_LOCATION).exists()
        || latest_basic_test_hash != basic_test_hash
        || latest_system_contract_hash != system_contract_hash
        || current_compiler_metadata != last_compiler_metadata
    {
        println!("test artifacts are outdated, updating...");
        let solc_binary_name = get_solc_binary_name().expect("should be able to get binary name");
        let zksolc_binary_name =
            get_zksolc_binary_name().expect("should be able to get binary name");

        // delay checking result so that we clean up in all cases
        let result = compile_latest_artifacts(&solc_binary_name, &zksolc_binary_name);
        let _ = fs::remove_file(&solc_binary_name);
        let _ = fs::remove_file(&zksolc_binary_name);
        let _ = fs::remove_dir_all("contracts");
        let _ = fs::remove_dir_all("era-system-contracts");
        match result {
            Ok((bytecode, default_account_code, predeployed_contracts)) => {
                let artifact =
                    create_artifact(bytecode, default_account_code, predeployed_contracts);
                let artifact_string = serde_json::to_string(&artifact)
                    .expect("should be able to stringify test artifact");
                fs::write(BASIC_TEST_JSON_LOCATION, artifact_string)
                    .expect("should be able to write contract json");
                fs::write(BASIC_TEST_COMMIT_HASH_LOCATION, latest_basic_test_hash)
                    .expect("should be able to write new commit hash");
                fs::write(
                    SYSTEM_CONTRACTS_COMMIT_HASH_LOCATION,
                    latest_system_contract_hash,
                )
                .expect("should be able to write new commit hash");
                let compiler_metadata_string = serde_json::to_string(&current_compiler_metadata)
                    .expect("should be able to stringify compiler metadata");
                fs::write(COMPILER_METADATA_LOCATION, compiler_metadata_string)
                    .expect("should be able to write compiler metadata");
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

fn create_artifact(
    bytecode: Vec<u8>,
    default_account_code: Vec<u8>,
    predeployed_contracts: Vec<(String, Vec<u8>)>,
) -> TestArtifact {
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
    let default_account_code = segment_byte_vector(default_account_code);
    let predeployed_contracts = HashMap::from_iter(
        predeployed_contracts
            .iter()
            .map(|(address, code)| {
                let address = Address::from_str(address).unwrap();
                let code = segment_byte_vector(code.clone());
                (address, code)
            })
            .collect::<Vec<(Address, Vec<[u8; 32]>)>>(),
    );

    TestArtifact {
        entry_point_address: Address::from_str(ENTRY_POINT_ADDRESS)
            .expect("should be able to decode from constant entry point address"),
        entry_point_code,
        default_account_code,
        predeployed_contracts,
    }
}

fn retrieve_latest_commit_hash(url: &str, hash_location: &str) -> (String, String) {
    let latest_hash = get_latest_commit_hash(url);
    match fs::read(hash_location) {
        Ok(bytes) => (
            std::str::from_utf8(&bytes)
                .expect("commit hash should be utf8-encoded")
                .to_owned(),
            latest_hash,
        ),
        Err(_) => (String::new(), latest_hash),
    }
}

fn get_latest_commit_hash(url: &str) -> String {
    let client = reqwest::blocking::Client::builder()
        .user_agent("a") // this call needs a user agent but it doesn't matter what it is really
        .build()
        .expect("should be able to build client");
    let body = client
        .get(url)
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

fn compile_latest_artifacts(
    solc_binary_name: &str,
    zksolc_binary_name: &str,
) -> Result<(Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>), ArtifactError> {
    download_solc_binary(solc_binary_name)?;
    let solc_compiler_path = set_binary_perms(solc_binary_name)?;

    download_zksolc_binary(zksolc_binary_name)?;
    let zksolc_compiler_path = set_binary_perms(zksolc_binary_name)?;

    download_contracts()?;
    clone_system_contracts()?;
    Ok((
        compile_latest_test_contract(&solc_compiler_path, &zksolc_compiler_path)?,
        compile_default_account_code(&solc_compiler_path, &zksolc_compiler_path)?,
        compile_predeployed_contracts(&solc_compiler_path, &zksolc_compiler_path)?,
    ))
}

fn compile_latest_test_contract(
    solc_compiler_path: &PathBuf,
    zksolc_compiler_path: &PathBuf,
) -> Result<Vec<u8>, ArtifactError> {
    // create full filepaths for all contracts
    // NOTE: the constant should be updated if we add more contracts
    let mut file_names = vec![];
    for name in TEST_CONTRACT_FILE_NAMES {
        let mut path =
            std::env::current_dir().map_err(|e| ArtifactError::CompilationFailed(e.to_string()))?;
        path.push("contracts");
        path.push(name);
        file_names.push(path);
    }

    compile_solidity_for_contract(solc_compiler_path, zksolc_compiler_path, file_names, "Main")
}

// The default account code compilation is kept separate as it isn't deployed and needs to be
// extracted from all the other predeployed contracts.
fn compile_default_account_code(
    solc_compiler_path: &PathBuf,
    zksolc_compiler_path: &PathBuf,
) -> Result<Vec<u8>, ArtifactError> {
    let mut file_names: Vec<PathBuf> = vec![];
    // we just naively grab all sol files to ensure we satisfy imports with minimal hassle
    for entry in WalkDir::new(SYSTEM_CONTRACTS_PATH)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_name().to_string_lossy().ends_with(".sol") {
            file_names.push(entry.into_path());
        }
    }

    // we can then only extract the default account code
    compile_solidity_for_contract(
        solc_compiler_path,
        zksolc_compiler_path,
        file_names,
        "DefaultAccount",
    )
}

fn compile_predeployed_contracts(
    solc_compiler_path: &PathBuf,
    zksolc_compiler_path: &PathBuf,
) -> Result<Vec<(String, Vec<u8>)>, ArtifactError> {
    let mut file_names: Vec<PathBuf> = vec![];
    for entry in WalkDir::new(SYSTEM_CONTRACTS_PATH)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let name = entry.file_name().to_string_lossy();
        if name.ends_with(".sol") || name.ends_with(".yul") {
            file_names.push(entry.into_path());
        }
    }

    // sol and yul files need a different compilation strategy so we separate the vector into two
    let (sol_file_names, yul_file_names): (Vec<PathBuf>, Vec<PathBuf>) = file_names
        .into_iter()
        .partition(|path| path.extension().unwrap() == "sol");

    let sol_stdout = compile_solidity(solc_compiler_path, zksolc_compiler_path, sol_file_names)?;

    let mut yul_stdout = vec![];
    for file_name in yul_file_names.into_iter() {
        yul_stdout.push(compile_yul(
            solc_compiler_path,
            zksolc_compiler_path,
            file_name,
        )?);
    }

    // generic output extraction closure
    let extract_results = |contracts: &[(&str, &str)],
                           extension: &str,
                           outputs: Vec<String>,
                           results: &mut Vec<(String, Vec<u8>)>|
     -> Result<(), ArtifactError> {
        for (contract_name, address) in contracts {
            results.push((
                (*address).to_owned(),
                grab_bytecode(
                    outputs
                        .iter()
                        .find(|output| output.contains(&((*contract_name).to_owned() + extension)))
                        .ok_or(ArtifactError::CompilationFailed(
                            "couldn't find contract bytecode".to_owned() + contract_name,
                        ))?,
                ),
            ));
        }

        Ok(())
    };

    let mut results = vec![];
    extract_results(
        &PREDEPLOYED_CONTRACTS_SOL,
        ".sol",
        String::from_utf8_lossy(&sol_stdout)
            .to_string()
            .lines()
            .map(|s| s.to_owned())
            .collect(),
        &mut results,
    )?;
    extract_results(&PREDEPLOYED_CONTRACTS_YUL, ".yul", yul_stdout, &mut results)?;
    Ok(results)
}

fn compile_solidity(
    solc_compiler_path: &PathBuf,
    zksolc_compiler_path: &PathBuf,
    file_names: Vec<PathBuf>,
) -> Result<Vec<u8>, ArtifactError> {
    let mut command = Command::new(zksolc_compiler_path);
    command.args([
        "--solc",
        solc_compiler_path
            .to_str()
            .ok_or(ArtifactError::CompilationFailed(
                "couldn't convert string".to_owned(),
            ))?,
    ]);
    command.arg("--system-mode");
    command.arg("--bin");
    for name in file_names {
        command.arg(name);
    }

    Ok(run_process(command)?)
}

fn compile_solidity_for_contract(
    solc_compiler_path: &PathBuf,
    zksolc_compiler_path: &PathBuf,
    file_names: Vec<PathBuf>,
    contract_name: &str,
) -> Result<Vec<u8>, ArtifactError> {
    Ok(grab_bytecode(
        String::from_utf8_lossy(&compile_solidity(
            solc_compiler_path,
            zksolc_compiler_path,
            file_names,
        )?)
        .to_string()
        .lines()
        .find(|line| line.contains(&(contract_name.to_owned() + ".sol")))
        .ok_or(ArtifactError::CompilationFailed(
            "couldn't find compiled contract".to_owned(),
        ))?,
    ))
}

fn compile_yul(
    solc_compiler_path: &PathBuf,
    zksolc_compiler_path: &PathBuf,
    file_name: PathBuf,
) -> Result<String, ArtifactError> {
    let mut command = Command::new(zksolc_compiler_path);
    command.args([
        "--solc",
        solc_compiler_path
            .to_str()
            .ok_or(ArtifactError::CompilationFailed(
                "couldn't convert string".to_owned(),
            ))?,
    ]);
    command.arg("--system-mode");
    command.arg("--bin");
    command.arg("--yul");
    command.arg(file_name);

    Ok(String::from_utf8_lossy(&run_process(command)?).to_string())
}

fn run_process(mut command: Command) -> Result<Vec<u8>, ArtifactError> {
    let _ = command
        .spawn()
        .map_err(|e| ArtifactError::CompilationFailed(e.to_string()))?;
    let output = command
        .output()
        .map_err(|e| ArtifactError::CompilationFailed(e.to_string()))?;

    if !output.status.success() {
        Err(ArtifactError::CompilationFailed(
            String::from_utf8_lossy(output.stderr.as_slice()).to_string(),
        ))
    } else {
        Ok(output.stdout)
    }
}

fn grab_bytecode(output: &str) -> Vec<u8> {
    hex::decode(
        output
            .split(' ')
            .last()
            .unwrap()
            .trim()
            .strip_prefix("0x")
            .expect("should have 0x prefix"),
    )
    .expect("bytecode should be hex encoded")
}

fn download_contracts() -> Result<(), ArtifactError> {
    fs::create_dir("contracts").map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;

    for file_name in TEST_CONTRACT_FILE_NAMES {
        let url = "https://raw.githubusercontent.com/matter-labs/test-contract/".to_owned()
            + BRANCH
            + "/contracts/basic_test/"
            + file_name;
        download_to_disk(&url, &("contracts/".to_owned() + file_name))?;
    }

    Ok(())
}

fn clone_system_contracts() -> Result<(), ArtifactError> {
    let _ = Command::new("git")
        .args(["clone", "-b", SYSTEM_CONTRACTS_BRANCH, SYSTEM_CONTRACTS_URL])
        .output()
        .map_err(|e| ArtifactError::DownloadFailed(e.to_string()))?;
    Ok(())
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
            if std::env::consts::ARCH == "x86_64" {
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
            // For some reason, the M1/M2 macs will return `x86_64` from this check, even though
            // they are running ARM.
            if std::env::consts::ARCH == "x86_64" {
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

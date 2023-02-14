use serde::{de, Deserialize, Deserializer};
use std::{collections::HashMap, str::FromStr};
use zk_evm::ethereum_types::Address;

fn hex_string_to_bytecode<'de, D>(deserialized_string: &str) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let result = if let Some(deserialized_string) = deserialized_string.strip_prefix("0x") {
        hex::decode(&deserialized_string).map_err(de::Error::custom)
    } else {
        Err(de::Error::custom(
            format!("string value missing prefix 0x",),
        ))
    }?
    .chunks(32)
    .map(|chunk| {
        let mut res = [0u8; 32];
        res.copy_from_slice(chunk);

        res
    })
    .collect();

    Ok(result)
}

pub fn deserialize_bytecode<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let deserialized_string = String::deserialize(deserializer)?;

    hex_string_to_bytecode::<D>(&deserialized_string)
}

pub fn deserialize_bytecodes_with_addresses<'de, D>(
    deserializer: D,
) -> Result<HashMap<Address, Vec<[u8; 32]>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let deserialized_strings: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    let result: Result<HashMap<_, Vec<[u8; 32]>>, _> = deserialized_strings
        .iter()
        .map(|(key, value)| {
            Ok((
                Address::from_str(key).unwrap(),
                hex_string_to_bytecode::<D>(value)?,
            ))
        })
        .collect();

    result
}

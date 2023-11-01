use hasher::HasherKeccak;
use hex;
use serde::Serializer;
use std::{fmt, sync::Arc};

use cita_trie::{MemoryDB, PatriciaTrie, Trie};

pub fn verify_proof(root: &[u8], key: &mut [u8], proof: Vec<Vec<u8>>) -> Vec<u8> {
    let memdb = Arc::new(MemoryDB::new(true));
    let hasher = Arc::new(HasherKeccak::new());

    let trie = PatriciaTrie::new(Arc::clone(&memdb), Arc::clone(&hasher));
    let value_option = trie.verify_proof(root, key, proof).unwrap();

    value_option.unwrap_or_else(|| vec![0])
}

pub fn from_hex_string<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> serde::de::Visitor<'de> for HexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing hex bytes")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            hex::decode(value.trim_start_matches("0x"))
                .map_err(|err| E::custom(format!("failed to decode hex: {}", err)))
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

pub fn from_hex_array<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct HexArrayVisitor;

    impl<'de> serde::de::Visitor<'de> for HexArrayVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an array of strings representing hex bytes")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(hex_str) = seq.next_element::<String>()? {
                // Adjusted to expect owned String values
                let bytes = hex::decode(hex_str.trim_start_matches("0x")).map_err(|err| {
                    serde::de::Error::custom(format!("failed to decode hex: {}", err))
                })?;
                vec.push(bytes);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_seq(HexArrayVisitor)
}

pub fn to_hex_array<S>(bytes_array: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(bytes_array.len()))?;

    for bytes in bytes_array {
        let hex_str = hex::encode(bytes);
        seq.serialize_element(&hex_str)?;
    }

    // End the sequence and return the result.
    seq.end()
}

pub fn to_hex_string<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_str = hex::encode(bytes);
    serializer.serialize_str(&hex_str)
}

#[cfg(test)]
pub mod test_helpers {
    use std::fs::File;

    use crate::types::VerificationRequest;

    pub fn get_receipt_verification_request() -> VerificationRequest {
        let path = format!("testdata/receipt_proof.json");
        let file = File::open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }
}

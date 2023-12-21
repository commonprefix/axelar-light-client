use core::{
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};
use serde::{self};
use ssz_rs::prelude::*;

#[derive(Default, Clone, Eq, SimpleSerialize)]
pub struct ByteVector<const N: usize>(
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::as_hex"))] Vector<u8, N>,
);

impl<const N: usize> TryFrom<&[u8]> for ByteVector<N> {
    type Error = ssz_rs::DeserializeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ByteVector::<N>::deserialize(bytes)
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for ByteVector<N> {
    type Error = ssz_rs::DeserializeError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        ByteVector::<N>::deserialize(&bytes)
    }
}

// impl here to satisfy clippy
impl<const N: usize> PartialEq for ByteVector<N> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<const N: usize> Hash for ByteVector<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl<const N: usize> AsRef<[u8]> for ByteVector<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for ByteVector<N> {
    type Target = Vector<u8, N>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for ByteVector<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/**
 * U64: a 64-bit unsigned integer.
 */

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct U64 {
    inner: u64,
}

impl U64 {
    pub fn as_u64(&self) -> u64 {
        self.inner
    }
}

impl From<U64> for u64 {
    fn from(value: U64) -> Self {
        value.inner
    }
}

impl From<u64> for U64 {
    fn from(value: u64) -> Self {
        Self { inner: value }
    }
}

impl ssz_rs::Merkleized for U64 {
    fn hash_tree_root(&mut self) -> std::result::Result<Node, MerkleizationError> {
        self.inner.hash_tree_root()
    }
}

// impl ssz_rs::Sized for U64 {
//     fn size_hint() -> usize {
//         0
//     }

//     fn is_variable_size() -> bool {
//         false
//     }
// }

impl ssz_rs::Serialize for U64 {
    fn serialize(&self, buffer: &mut Vec<u8>) -> std::result::Result<usize, SerializeError> {
        self.inner.serialize(buffer)
    }
}

impl ssz_rs::Deserialize for U64 {
    fn deserialize(encoding: &[u8]) -> std::result::Result<Self, DeserializeError>
    where
        Self: std::marker::Sized,
    {
        Ok(Self {
            inner: u64::deserialize(encoding)?,
        })
    }
}

// impl ssz_rs::SimpleSerialize for U64 {}

impl serde::Serialize for U64 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for U64 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let val: String = serde::Deserialize::deserialize(deserializer)?;
        Ok(Self {
            inner: val.parse().unwrap(),
        })
    }
}

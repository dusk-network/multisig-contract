//! Types used to interact with the `multisig-contract`.

#![no_std]
#![deny(missing_docs)]

use core::cmp::Ordering;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

pub use execution_core::signatures::bls;

#[doc(hidden)]
#[derive(Debug, Clone, Copy, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct WrappedPublicKey(pub bls::PublicKey);

impl PartialEq for WrappedPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_raw_bytes().eq(&other.0.to_raw_bytes())
    }
}

impl Eq for WrappedPublicKey {}

impl PartialOrd for WrappedPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WrappedPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_raw_bytes().cmp(&other.0.to_raw_bytes())
    }
}

/// The data about a given account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct AccountData {
    /// The balance the account holds.
    pub balance: u64,
    /// The current nonce of the account.
    pub nonce: u64,
}

impl AccountData {
    /// An account that has never been used.
    pub const EMPTY: Self = AccountData {
        balance: 0,
        nonce: 0,
    };
}

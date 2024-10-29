//! Types used to interact with the `multisig-contract`.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

pub use execution_core::signatures::bls;

/// Used to transfer funds from an account to a Moonlight account.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct Transfer {
    /// The ID of the account to transfer from.
    pub from_id: u64,
    /// The keys and signatures used to sign the transfer.
    pub from_kas: Vec<bls::PublicKeyAndSignature>,
    /// The Moonlight account to transfer the amount to.
    pub to: bls::PublicKey,
    /// The amount to transfer.
    pub amount: u64,
    /// The nonce used for the transfer.
    pub nonce: u64,
}

impl Transfer {
    /// Returns the message that should be signed to have a valid transfer.
    // NOTE: We purposefully don't include the keys used in the message to
    //       allow for the owner of each key to sign the message independently,
    //       without communicating with the other signers.
    //       If we did include the keys, the signers would have to agree on the
    //       set of keys to be used prior to signing.
    pub fn signature_msg(&self) -> Vec<u8> {
        let mut msg = vec![0; 8 + 193 + 8 + 8];
        msg[..8].copy_from_slice(&self.from_id.to_le_bytes());
        msg[8..201].copy_from_slice(&self.to.to_raw_bytes());
        msg[201..209].copy_from_slice(&self.amount.to_le_bytes());
        msg[209..217].copy_from_slice(&self.nonce.to_le_bytes());
        msg
    }
}

/// The data about a given account.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize,
)]
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

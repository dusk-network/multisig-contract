//! Types used to interact with the `multisig-contract`.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

pub use execution_core::signatures::bls;

/// Used to create multisig accounts.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct CreateAccount {
    /// Keys to be owned by the account.
    pub keys: Vec<bls::PublicKey>,
    /// Number of keys that need to sign to effect an operation.
    pub threshold: u32,
}

/// Used to deposit to a multisig account.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct Deposit {
    /// The account to deposit to.
    pub account_id: u64,
    /// The amount to deposit.
    pub amount: u64,
    /// Memo to include the in the deposit.
    pub memo: String,
}

/// Used to transfer funds from an account to a Moonlight account.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct Transfer {
    /// The ID of the account to transfer from.
    pub account_id: u64,
    /// The keys used to sign the transfer.
    pub keys: Vec<bls::PublicKey>,
    /// The signature of the transfer.
    pub signature: bls::MultisigSignature,
    /// The Moonlight account to transfer the amount to.
    pub receiver: bls::PublicKey,
    /// The amount to transfer.
    pub amount: u64,
    /// The nonce used for the transfer.
    pub nonce: u64,
    /// Memo to include with the transfer.
    pub memo: String,
}

impl Transfer {
    /// Returns the message that should be signed to have a valid transfer.
    // NOTE: We purposefully don't include the keys used in the message to
    //       allow for the owner of each key to sign the message independently,
    //       without communicating with the other signers.
    //       If we did include the keys, the signers would have to agree on the
    //       set of keys to be used prior to signing.
    pub fn signature_msg(&self) -> Vec<u8> {
        let mut msg = vec![0; 8 + 193 + 8 + 8 + self.memo.len()];
        msg[..8].copy_from_slice(&self.account_id.to_le_bytes());
        msg[8..201].copy_from_slice(&self.receiver.to_raw_bytes());
        msg[201..209].copy_from_slice(&self.amount.to_le_bytes());
        msg[209..217].copy_from_slice(&self.nonce.to_le_bytes());
        msg[217..].copy_from_slice(&self.memo.as_bytes());
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
    /// Number of keys that need to sign to effect an operation.
    pub threshold: u32,
    /// The current nonce of the account.
    pub nonce: u64,
}

impl AccountData {
    /// An account that has never been used.
    pub const EMPTY: Self = AccountData {
        balance: 0,
        threshold: 0,
        nonce: 0,
    };
}

/// Event emitted upon a successful account creation.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct CreateAccountEvent {
    /// The ID of the account created.
    pub account_id: u64,
    /// Keys used by the account.
    pub keys: Vec<bls::PublicKey>,
    /// Number of keys that need to sign to effect an operation.
    pub threshold: u32,
}

/// Event emitted upon a successful deposit.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct DepositEvent {
    /// The account deposited to.
    pub account_id: u64,
    /// Amount deposited.
    pub amount: u64,
    /// Memo included with the deposit.
    pub memo: String,
}

/// Event emitted upon a successful transfer.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct TransferEvent {
    /// The account that transferred.
    pub account_id: u64,
    /// Keys used to sign the transfer.
    pub keys: Vec<bls::PublicKey>,
    /// The receiver of the funds.
    pub receiver: bls::PublicKey,
    /// Amount transferred.
    pub amount: u64,
    /// Memo included with the transfer.
    pub memo: String,
}

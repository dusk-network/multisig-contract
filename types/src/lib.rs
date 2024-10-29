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

/// The kind of of change to be made to an account.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
#[allow(missing_docs)]
pub enum AccountChange {
    /// Add a key to the account.
    AddKey { key: bls::PublicKey },
    /// Remove a key from an account.
    RemoveKey { key: bls::PublicKey },
    /// Set number of keys needed to effect an operation.
    SetThreshold { threshold: u32 },
}

/// Used to perform changes to an account.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct ChangeAccount {
    /// The account to change.
    pub account_id: u64,
    /// Keys used to sign the change.
    pub keys: Vec<bls::PublicKey>,
    /// The signature of the change.
    pub signature: bls::MultisigSignature,
    /// List of changes to apply to the account.
    pub changes: Vec<AccountChange>,
    /// The nonce used for the change.
    pub nonce: u64,
}

impl ChangeAccount {
    const ADD_KEY_TAG: u8 = 0;
    const REMOVE_KEY_TAG: u8 = 1;
    const SET_THRESHOLD_TAG: u8 = 2;

    /// Returns the message that should be signed to have a valid change.
    // NOTE: We purposefully don't include the keys used in the message to
    //       allow for the owner of each key to sign the message independently,
    //       without communicating with the other signers.
    //       If we did include the keys, the signers would have to agree on the
    //       set of keys to be used prior to signing.
    pub fn signature_msg(&self) -> Vec<u8> {
        let mut msg = vec![
            0;
            8 + self
                .changes
                .iter()
                .map(|change| {
                    1 + match change {
                        AccountChange::AddKey { .. } => 193,
                        AccountChange::RemoveKey { .. } => 193,
                        AccountChange::SetThreshold { .. } => 4,
                    }
                })
                .sum::<usize>()
                + 8
        ];

        let mut offset = 0;
        msg[offset..offset + 8].copy_from_slice(&self.account_id.to_le_bytes());
        offset += 8;

        for change in &self.changes {
            match change {
                AccountChange::AddKey { key } => {
                    msg[offset] = Self::ADD_KEY_TAG;
                    offset += 1;

                    msg[offset..offset + 193]
                        .copy_from_slice(&key.to_raw_bytes());
                    offset += 193;
                }
                AccountChange::RemoveKey { key } => {
                    msg[offset] = Self::REMOVE_KEY_TAG;
                    offset += 1;

                    msg[offset..offset + 193]
                        .copy_from_slice(&key.to_raw_bytes());
                    offset += 193;
                }
                AccountChange::SetThreshold { threshold } => {
                    msg[offset] = Self::SET_THRESHOLD_TAG;
                    offset += 1;

                    msg[offset..offset + 4]
                        .copy_from_slice(&threshold.to_le_bytes());
                    offset += 4;
                }
            }
        }

        msg[offset..offset + 8].copy_from_slice(&self.nonce.to_le_bytes());
        // offset += 8;

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

/// Event emitted upon a successful account change.
#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
#[archive_attr(derive(CheckBytes))]
pub struct ChangeAccountEvent {
    /// The account that changed.
    pub account_id: u64,
    /// Keys added during the change.
    pub added_keys: Vec<bls::PublicKey>,
    /// Keys removed during the change.
    pub removed_keys: Vec<bls::PublicKey>,
    /// Threshold after the change.
    pub threshold: u32,
}

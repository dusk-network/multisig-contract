#![no_std]

extern crate alloc;

use core::cmp::Ordering;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use execution_core::transfer::{ContractToAccount, TRANSFER_CONTRACT};

use bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};

use multisig_contract_types::*;

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

/// The state consists of the balance and nonce of each account, together with
/// each account's keys. It also holds an index of the accounts to which each
/// key belongs to.
struct ContractState {
    accounts: BTreeMap<u64, AccountData>,
    account_keys: BTreeMap<u64, BTreeSet<WrappedPublicKey>>,
    key_accounts: BTreeMap<WrappedPublicKey, BTreeSet<u64>>,
}

/// The state starts out all empty.
static mut STATE: ContractState = ContractState {
    accounts: BTreeMap::new(),
    account_keys: BTreeMap::new(),
    key_accounts: BTreeMap::new(),
};

impl ContractState {
    /// Creates an account with the given public keys, returning the new
    /// account's ID.
    fn create_account(&mut self, keys: Vec<bls::PublicKey>) -> u64 {
        let account_id = self
            .accounts
            .last_key_value()
            .map(|(k, _)| k)
            .cloned()
            .unwrap_or(0);
        let account_id = account_id + 1;

        let mut account_keys = BTreeSet::new();
        for key in keys {
            if !account_keys.insert(WrappedPublicKey(key)) {
                panic!("Cannot use duplicate keys to create an account");
            }

            self.key_accounts
                .entry(WrappedPublicKey(key))
                .or_insert(BTreeSet::new())
                .insert(account_id);
        }
        self.account_keys.insert(account_id, account_keys);
        self.accounts.insert(account_id, AccountData::EMPTY);

        account_id
    }

    /// Handles depositing an amount to the account with the given ID.
    ///
    /// NOTE: here we always accept a deposit to an existing account, however,
    ///       nothing stops us from including more complex logic, such as an
    ///       identity check.
    fn deposit(&mut self, amount: u64, id: u64) {
        let account = self
            .accounts
            .get_mut(&id)
            .expect("The account must exist when depositing funds");

        rusk_abi::call::<_, ()>(TRANSFER_CONTRACT, "deposit", &amount)
            .expect("Retrieving deposit should succeed");

        account.balance += amount;
    }

    /// Transfers an amount from an account to the given Moonlight account.
    ///
    /// Signatures must be included of at least half (rounded-up) of at least
    /// half of the account's keys.
    fn transfer(&mut self, transfer: Transfer) {
        let account = self
            .accounts
            .get_mut(&transfer.from_id)
            .expect("The account must exist when transferring from it");

        if transfer.amount > account.balance {
            panic!("The account doesn't have enough balance to transfer");
        }
        if transfer.nonce != account.nonce + 1 {
            panic!("The nonce must be the previous value incremented");
        }

        let account_keys = self.account_keys.get(&transfer.from_id).unwrap();
        if transfer.from_kas.len() < account_keys.len().div_ceil(2) {
            panic!("At least half of the keys must sign a transfer");
        }

        // this set is here for the express purpose of checking for unique keys
        // in the kas
        let mut uniqueness_set = BTreeSet::new();

        for kas in &transfer.from_kas {
            if !uniqueness_set.insert(WrappedPublicKey(kas.public_key)) {
                panic!("Cannot use duplicate keys to transfer");
            }

            // NOTE: we might want to use a map for keys instead of a vector to
            //       speed up these lookups if they become expensive. For now,
            //       since we don't expect hundreds of keys for each account,
            //       this is fine.
            let mut contains = false;

            for k in account_keys {
                if k.0 == kas.public_key {
                    contains = true;
                    break;
                }
            }

            if !contains {
                panic!("The keys used to sign the transfer should be used by the account");
            }
        }

        let msg = transfer.signature_msg();
        if !rusk_abi::verify_bls_multisig(msg, transfer.from_kas) {
            panic!("The signature should be valid to effect the transfer");
        }

        // NOTE: Here we simply immediately give the amount to the specified
        //       Moonlight account, however, it would also be possible - in a
        //       different type of contract - to keep the funds until a
        //       withdrawal is made.
        //       In such a case, it would be possible to withdraw the funds to
        //       either Moonlight *or* Phoenix.
        rusk_abi::call::<_, ()>(
            TRANSFER_CONTRACT,
            "contract_to_account",
            &ContractToAccount {
                account: transfer.to,
                value: transfer.amount,
            },
        )
        .expect("Transferring to the given account should succeed");
    }

    /// Returns the balance and nonce of the account with the given ID.
    fn account(&self, id: u64) -> AccountData {
        self.accounts
            .get(&id)
            .unwrap_or(&AccountData::EMPTY)
            .clone()
    }

    /// Feeds the public keys used by the account with the given ID.
    fn account_keys(&self, id: u64) {
        for key in self
            .account_keys
            .get(&id)
            .cloned()
            .unwrap_or(BTreeSet::new())
        {
            rusk_abi::feed(key);
        }
    }

    /// Feeds the account IDs by which the given public key is used.
    fn key_accounts(&self, key: bls::PublicKey) {
        for id in self
            .key_accounts
            .get(&WrappedPublicKey(key))
            .cloned()
            .unwrap_or(BTreeSet::new())
        {
            rusk_abi::feed(id)
        }
    }
}

// Mutations

#[no_mangle]
unsafe fn create_account(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.create_account(arg))
}

#[no_mangle]
unsafe fn deposit(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |(amount, id)| STATE.deposit(amount, id))
}

#[no_mangle]
unsafe fn transfer(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.transfer(arg))
}

// Queries

#[no_mangle]
unsafe fn account(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.account(arg))
}

// Feeder queries

#[no_mangle]
unsafe fn account_keys(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.account_keys(arg))
}

#[no_mangle]
unsafe fn key_accounts(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.key_accounts(arg))
}

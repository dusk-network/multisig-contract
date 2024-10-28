#![no_std]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use multisig_contract_types::*;

/// The state consists of the balance and nonce of each account, together with
/// each account's keys. It also holds an index of the accounts to which each
/// key belongs to.
struct ContractState {
    accounts: BTreeMap<u128, AccountData>,
    account_keys: BTreeMap<u128, Vec<WrappedPublicKey>>,
    key_accounts: BTreeMap<WrappedPublicKey, Vec<u128>>,
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
    fn create_account(&mut self, keys: Vec<WrappedPublicKey>) -> u128 {
        let account_id = self
            .accounts
            .last_key_value()
            .map(|(k, _)| k)
            .cloned()
            .unwrap_or(0);
        let account_id = account_id + 1;

        for key in &keys {
            self.key_accounts
                .entry(*key)
                .or_insert(Vec::new())
                .push(account_id);
        }

        self.account_keys.insert(account_id, keys);
        self.accounts.insert(account_id, AccountData::EMPTY);

        account_id
    }

    /// Returns the balance and nonce of the account with the given ID.
    fn account(&self, id: u128) -> AccountData {
        self.accounts
            .get(&id)
            .unwrap_or(&AccountData::EMPTY)
            .clone()
    }

    /// Feeds the public keys used by the account with the given ID.
    fn account_keys(&self, id: u128) {
        for key in self.account_keys.get(&id).cloned().unwrap_or(Vec::new()) {
            rusk_abi::feed(key);
        }
    }

    /// Feeds the account IDs by which the given public key is used.
    fn key_accounts(&self, key: WrappedPublicKey) {
        for id in self.key_accounts.get(&key).cloned().unwrap_or(Vec::new()) {
            rusk_abi::feed(id)
        }
    }
}

// Mutations

#[no_mangle]
unsafe fn create_account(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.create_account(arg))
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

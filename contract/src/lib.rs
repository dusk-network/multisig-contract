#![no_std]

extern crate alloc;

use core::cmp::Ordering;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
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
    fn create_account(&mut self, ca: CreateAccount) -> u64 {
        if ca.keys.len() < 1 {
            panic!("There must be at least one key to create an account");
        }
        if ca.threshold < 1 {
            panic!("Thresold must be at least 1");
        }
        if ca.threshold as usize > ca.keys.len() {
            panic!("Cannot use a threshold larger than the number of keys");
        }

        let account_id = self
            .accounts
            .last_key_value()
            .map(|(k, _)| k)
            .cloned()
            .unwrap_or(0);
        let account_id = account_id + 1;

        let mut account_keys = BTreeSet::new();
        for key in &ca.keys {
            if !account_keys.insert(WrappedPublicKey(*key)) {
                panic!("Cannot use duplicate keys to create an account");
            }

            self.key_accounts
                .entry(WrappedPublicKey(*key))
                .or_insert(BTreeSet::new())
                .insert(account_id);
        }
        self.account_keys.insert(account_id, account_keys);
        self.accounts.insert(
            account_id,
            AccountData {
                balance: 0,
                threshold: ca.threshold,
                nonce: 0,
                description: ca.description.clone(),
            },
        );

        rusk_abi::emit(
            "create_account",
            CreateAccountEvent {
                account_id,
                keys: ca.keys,
                threshold: ca.threshold,
                description: ca.description,
            },
        );

        account_id
    }

    /// Handles depositing an amount to the account with the given ID.
    ///
    /// NOTE: here we always accept a deposit to an existing account, however,
    ///       nothing stops us from including more complex logic, such as an
    ///       identity check.
    fn deposit(&mut self, d: Deposit) {
        let account = self
            .accounts
            .get_mut(&d.account_id)
            .expect("The account must exist when depositing funds");

        rusk_abi::call::<_, ()>(TRANSFER_CONTRACT, "deposit", &d.amount)
            .expect("Retrieving deposit should succeed");

        account.balance += d.amount;

        rusk_abi::emit(
            "deposit",
            DepositEvent {
                account_id: d.account_id,
                amount: d.amount,
                memo: d.memo,
            },
        );
    }

    /// Transfers an amount from an account to the given Moonlight account.
    fn transfer(&mut self, t: Transfer) {
        let account = self
            .accounts
            .get_mut(&t.account_id)
            .expect("The account must exist when transferring from it");

        if t.amount > account.balance {
            panic!("The account doesn't have enough balance to transfer");
        }
        if t.nonce != account.nonce + 1 {
            panic!("The nonce must be the current value incremented");
        }

        let mut key_set = BTreeSet::new();
        let account_keys = self.account_keys.get(&t.account_id).unwrap();

        for key in &t.keys {
            let key = WrappedPublicKey(*key);

            if !key_set.insert(key) {
                panic!("Cannot use duplicate keys to transfer");
            }

            if !account_keys.contains(&key) {
                panic!("Signing key must be used by account");
            }
        }

        if t.keys.len() < account.threshold as usize {
            panic!("Threshold number of keys not met");
        }

        let msg = t.signature_msg();
        if !rusk_abi::verify_bls_multisig(msg, t.keys, t.signature) {
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
                account: t.receiver,
                value: t.amount,
            },
        )
        .expect("Transferring to the given account should succeed");

        account.balance -= t.amount;
        account.nonce += 1;

        rusk_abi::emit(
            "transfer",
            TransferEvent {
                account_id: t.account_id,
                keys: key_set.into_iter().map(|k| k.0).collect(),
                receiver: t.receiver,
                amount: t.amount,
                memo: t.memo,
            },
        );
    }

    fn change_account(&mut self, c: ChangeAccount) {
        let account = self
            .accounts
            .get_mut(&c.account_id)
            .expect("The account must exist when changing it");

        if c.nonce != account.nonce + 1 {
            panic!("The nonce must be the current value incremented");
        }

        let mut key_set = BTreeSet::new();
        let account_keys = self.account_keys.get_mut(&c.account_id).unwrap();

        for key in &c.keys {
            let key = WrappedPublicKey(*key);

            if !key_set.insert(key) {
                panic!("Cannot use duplicate keys to transfer");
            }

            if !account_keys.contains(&key) {
                panic!("Signing key must be used by account");
            }
        }

        if c.keys.len() < account.threshold as usize {
            panic!("Threshold number of keys not met");
        }

        let msg = c.signature_msg();
        if !rusk_abi::verify_bls_multisig(msg, c.keys, c.signature) {
            panic!("The signature should be valid to effect the change");
        }

        let mut added_keys = Vec::new();
        let mut removed_keys = Vec::new();

        for change in c.changes {
            match change {
                AccountChange::AddKey { key } => {
                    let key = WrappedPublicKey(key);

                    if !account_keys.insert(key) {
                        panic!("Key to add already used by account");
                    }

                    let key_accounts =
                        self.key_accounts.entry(key).or_insert(BTreeSet::new());

                    key_accounts.insert(c.account_id);
                    added_keys.push(key.0);
                }
                AccountChange::RemoveKey { key } => {
                    if account.threshold as usize > account_keys.len() {
                        panic!("Removing key from account leaves key number below threshold");
                    }
                    if account_keys.len() == 1 {
                        panic!("Removing key from account leaves no keys left");
                    }

                    let key = WrappedPublicKey(key);

                    if !account_keys.remove(&key) {
                        panic!("Key to remove not used by account");
                    }

                    let key_accounts = self.key_accounts.get_mut(&key).unwrap();

                    key_accounts.remove(&c.account_id);
                    removed_keys.push(key.0);
                }
                AccountChange::SetThreshold { threshold } => {
                    if threshold < 1 {
                        panic!("Threshold must be at least 1");
                    }
                    if threshold as usize > account_keys.len() {
                        panic!(
                            "Threshold too large for number of keys in account"
                        );
                    }

                    account.threshold = threshold;
                }
                AccountChange::SetDescription { description } => {
                    account.description = description;
                }
            }
        }

        account.nonce += 1;

        rusk_abi::emit(
            "change_account",
            ChangeAccountEvent {
                account_id: c.account_id,
                added_keys,
                removed_keys,
                threshold: account.threshold,
                description: account.description.clone(),
            },
        );
    }

    /// Returns the balance and nonce of the account with the given ID.
    fn account(&self, id: u64) -> AccountData {
        self.accounts
            .get(&id)
            .unwrap_or(&AccountData {
                balance: 0,
                threshold: 0,
                description: String::new(),
                nonce: 0,
            })
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
    rusk_abi::wrap_call(arg_len, |arg| STATE.deposit(arg))
}

#[no_mangle]
unsafe fn transfer(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.transfer(arg))
}

#[no_mangle]
unsafe fn change_account(arg_len: u32) -> u32 {
    rusk_abi::wrap_call(arg_len, |arg| STATE.change_account(arg))
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

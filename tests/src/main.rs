use std::sync::mpsc;

use execution_core::{
    transfer::{
        data::ContractCall, moonlight::AccountData as MoonlightAccountData,
        Transaction, TRANSFER_CONTRACT,
    },
    ContractError, ContractId, StandardBufSerializer,
};
use rusk_abi::{CallReceipt, ContractData, PiecrustError, Session};
use rusk_recovery_tools::state;
use tempfile::TempDir;

use bytecheck::CheckBytes;
use rkyv::de::deserializers::SharedDeserializeMap;
use rkyv::validation::validators::DefaultValidator;
use rkyv::{Archive, Deserialize, Infallible, Serialize};

use rand::rngs::StdRng;
use rand::{CryptoRng, RngCore, SeedableRng};

use bls::{MultisigSignature, PublicKey, SecretKey};
use multisig_contract_types::*;

const CONTRACT_BYTECODE: &[u8] =
    include_bytes!("../../build/multisig_contract.wasm");
const CONTRACT_ID: ContractId = ContractId::from_bytes([1; 32]);
const CONTRACT_OWNER: [u8; 64] = [0u8; 64];

const CHAIN_ID: u8 = 0xFE;
const BLOCK_HEIGHT: u64 = 1;
const SNAPSHOT: &str = include_str!("../state.toml");

const NUM_KEYS: usize = 16;
const THRESHOLD: u32 = NUM_KEYS as u32 / 2;
const DESCRIPTION: &str = "test-description";
const MEMO: &str = "test-memo";
const RNG_SEED: u64 = 0xBEEF;
const INITIAL_BALANCE: u64 = 10_000_000_000;

type Result<T, Error = PiecrustError> = std::result::Result<T, Error>;

struct ContractSession {
    session: Session,
    sks: Vec<SecretKey>,
    pks: Vec<PublicKey>,
    account_id: Option<u64>,
    _state_dir: TempDir,
}

#[allow(dead_code)]
impl ContractSession {
    fn new<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        let state_dir = TempDir::new()
            .expect("Creating temporary directory should succeed");
        let snapshot = toml::from_str(SNAPSHOT)
            .expect("Deserializing snapshot should succeed");

        let (vm, root) = state::deploy(&state_dir, &snapshot, |_| {})
            .expect("Deploying snapshot should succeed");
        let mut session =
            rusk_abi::new_session(&vm, root, CHAIN_ID, BLOCK_HEIGHT)
                .expect("Starting a new session should succeed");

        let mut sks = Vec::with_capacity(NUM_KEYS);
        let mut pks = Vec::with_capacity(NUM_KEYS);

        for _ in 0..NUM_KEYS {
            let sk = SecretKey::random(rng);
            let pk = PublicKey::from(&sk);
            sks.push(sk);
            pks.push(pk);
        }

        session
            .deploy(
                CONTRACT_BYTECODE,
                ContractData::builder()
                    .owner(CONTRACT_OWNER)
                    .contract_id(CONTRACT_ID),
                u64::MAX,
            )
            .expect("Deploying the multisig contract should succeed");

        Self {
            session,
            sks,
            pks,
            account_id: None,
            _state_dir: state_dir,
        }
    }

    fn call<A, R>(
        &mut self,
        contract: ContractId,
        fn_name: &str,
        fn_arg: &A,
    ) -> Result<CallReceipt<R>>
    where
        A: for<'b> Serialize<StandardBufSerializer<'b>>,
        A::Archived: for<'b> CheckBytes<DefaultValidator<'b>>,
        R: Archive,
        R::Archived: Deserialize<R, Infallible>
            + for<'b> CheckBytes<DefaultValidator<'b>>,
    {
        self.session.call(contract, fn_name, fn_arg, u64::MAX)
    }

    fn feeder_query<A, R>(
        &mut self,
        fn_name: &str,
        fn_arg: &A,
    ) -> Result<Vec<R>>
    where
        A: for<'b> Serialize<StandardBufSerializer<'b>>,
        A::Archived: for<'b> CheckBytes<DefaultValidator<'b>>,
        R: Archive,
        R::Archived: Deserialize<R, SharedDeserializeMap>
            + Deserialize<R, Infallible>
            + for<'b> CheckBytes<DefaultValidator<'b>>,
    {
        let mut results = Vec::new();
        let (sender, receiver) = mpsc::channel();
        self.session.feeder_call::<_, ()>(
            CONTRACT_ID,
            fn_name,
            fn_arg,
            u64::MAX,
            sender,
        )?;

        for bytes in receiver.into_iter() {
            results.push(
                rkyv::from_bytes(&bytes)
                    .map_err(|_| PiecrustError::MissingFeed)?,
            );
        }

        Ok(results)
    }

    fn create_account(&mut self) -> u64 {
        let keys = self.pks.clone();

        let create_account = CreateAccount {
            keys,
            threshold: THRESHOLD,
            description: String::from(DESCRIPTION),
        };

        let id = self
            .call(CONTRACT_ID, "create_account", &create_account)
            .expect("Creating an account should succeed")
            .data;
        self.account_id = Some(id);
        id
    }

    fn deposit(&mut self, index: usize, amount: u64) {
        let account_id = self
            .account_id
            .expect("must call `create_account` before `account`");
        let sk = self.sks[index].clone();

        const GAS_LIMIT: u64 = 1_000_000;
        const GAS_PRICE: u64 = 1;
        const NONCE: u64 = 1;

        let deposit = Deposit {
            account_id,
            amount,
            memo: String::from(MEMO),
        };

        let fn_args = rkyv::to_bytes::<_, 128>(&deposit)
            .expect("Serializing argument should succeed")
            .to_vec();

        let tx = Transaction::moonlight(
            &sk,
            None,
            0,
            amount,
            GAS_LIMIT,
            GAS_PRICE,
            NONCE,
            CHAIN_ID,
            Some(ContractCall {
                contract: CONTRACT_ID,
                fn_name: String::from("deposit"),
                fn_args,
            }),
        )
        .unwrap();

        let receipt = self
            .session
            .call::<_, Result<Vec<u8>, ContractError>>(
                TRANSFER_CONTRACT,
                "spend_and_execute",
                &tx,
                GAS_LIMIT,
            )
            .expect("Executing transaction should succeed");

        println!("{:?}", receipt.data);

        let _refund_receipt = self
            .session
            .call::<_, ()>(
                TRANSFER_CONTRACT,
                "refund",
                &receipt.gas_spent,
                u64::MAX,
            )
            .expect("Refunding must succeed");
    }

    fn transfer(&mut self, index: usize, receiver_index: usize, amount: u64) {
        let account_id = self
            .account_id
            .expect("must call `create_account` before `transfer`");
        let sk = self.sks[index].clone();

        const GAS_LIMIT: u64 = 2_000_000;
        const GAS_PRICE: u64 = 1;
        const NONCE: u64 = 1;

        let mut transfer = Transfer {
            account_id,
            keys: Vec::with_capacity(NUM_KEYS),
            signature: MultisigSignature::default(),
            receiver: self.pks[receiver_index],
            amount,
            nonce: 1, // if its the first interaction, 2 if second, etc...
            memo: String::from(MEMO),
        };

        let msg = transfer.signature_msg();

        // NOTE: Here we sign with all the keys of the account. This is
        //       technically unnecessary, since we could use only some of the
        //       keys, but as a test it is ok.
        let public_key = self.pks[0];

        transfer.keys.push(public_key);
        transfer.signature = self.sks[0].sign_multisig(&public_key, &msg);

        for i in 1..NUM_KEYS {
            let public_key = self.pks[i];
            transfer.keys.push(public_key);

            let s = self.sks[i].sign_multisig(&public_key, &msg);
            transfer.signature = transfer.signature.aggregate(&[s]);
        }

        let fn_args = rkyv::to_bytes::<_, 128>(&transfer)
            .expect("Serializing argument should succeed")
            .to_vec();

        let tx = Transaction::moonlight(
            &sk,
            None,
            0,
            0,
            GAS_LIMIT,
            GAS_PRICE,
            NONCE,
            CHAIN_ID,
            Some(ContractCall {
                contract: CONTRACT_ID,
                fn_name: String::from("transfer"),
                fn_args,
            }),
        )
        .unwrap();

        let receipt = self
            .session
            .call::<_, Result<Vec<u8>, ContractError>>(
                TRANSFER_CONTRACT,
                "spend_and_execute",
                &tx,
                GAS_LIMIT,
            )
            .expect("Executing transaction should succeed");

        println!("{:?}", receipt.data);

        let _refund_receipt = self
            .session
            .call::<_, ()>(
                TRANSFER_CONTRACT,
                "refund",
                &receipt.gas_spent,
                u64::MAX,
            )
            .expect("Refunding must succeed");
    }

    fn change_account(&mut self, index: usize, changes: Vec<AccountChange>) {
        let account_id = self
            .account_id
            .expect("must call `create_account` before `change_account`");
        let sk = self.sks[index].clone();

        const GAS_LIMIT: u64 = 2_000_000;
        const GAS_PRICE: u64 = 1;
        const NONCE: u64 = 1;

        let mut change_account = ChangeAccount {
            account_id,
            keys: Vec::with_capacity(NUM_KEYS),
            signature: MultisigSignature::default(),
            changes,
            nonce: 1, // if its the first interaction, 2 if second, etc...
        };

        let msg = change_account.signature_msg();

        // NOTE: Here we sign with all the keys of the account. This is
        //       technically unnecessary, since we could use only some of the
        //       keys, but as a test it is ok.
        let public_key = self.pks[0];

        change_account.keys.push(public_key);
        change_account.signature = self.sks[0].sign_multisig(&public_key, &msg);

        for i in 1..NUM_KEYS {
            let public_key = self.pks[i];
            change_account.keys.push(public_key);

            let s = self.sks[i].sign_multisig(&public_key, &msg);
            change_account.signature = change_account.signature.aggregate(&[s]);
        }

        let fn_args = rkyv::to_bytes::<_, 128>(&change_account)
            .expect("Serializing argument should succeed")
            .to_vec();

        let tx = Transaction::moonlight(
            &sk,
            None,
            0,
            0,
            GAS_LIMIT,
            GAS_PRICE,
            NONCE,
            CHAIN_ID,
            Some(ContractCall {
                contract: CONTRACT_ID,
                fn_name: String::from("change_account"),
                fn_args,
            }),
        )
        .unwrap();

        let receipt = self
            .session
            .call::<_, Result<Vec<u8>, ContractError>>(
                TRANSFER_CONTRACT,
                "spend_and_execute",
                &tx,
                GAS_LIMIT,
            )
            .expect("Executing transaction should succeed");

        println!("{:?}", receipt.data);

        let _refund_receipt = self
            .session
            .call::<_, ()>(
                TRANSFER_CONTRACT,
                "refund",
                &receipt.gas_spent,
                u64::MAX,
            )
            .expect("Refunding must succeed");
    }

    fn account(&mut self) -> AccountData {
        let account_id = self
            .account_id
            .expect("must call `create_account` before `account`");
        self.call(CONTRACT_ID, "account", &account_id)
            .expect("Querying an account should succeed")
            .data
    }

    fn balance(&mut self, key: PublicKey) -> u64 {
        self.call::<_, MoonlightAccountData>(TRANSFER_CONTRACT, "account", &key)
            .expect("Querying an account should succeed")
            .data
            .balance
    }

    fn account_keys(&mut self) -> Vec<PublicKey> {
        let account_id = self
            .account_id
            .expect("must call `create_account` before `account_keys`");

        self.feeder_query("account_keys", &account_id)
            .expect("Feeding account keys should succeed")
    }

    fn key_accounts(&mut self, key: PublicKey) -> Vec<u64> {
        self.feeder_query("key_accounts", &key)
            .expect("Feeding key accounts should succeed")
    }
}

#[test]
fn create_account() {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut session = ContractSession::new(&mut rng);

    session.create_account();

    let account = session.account();
    let account_keys = session.account_keys();

    assert_eq!(
        account_keys.len(),
        session.pks.len(),
        "Equal number of keys should be inserted"
    );

    for account_key in account_keys {
        let mut contains = false;
        for pk in &session.pks {
            if account_key == *pk {
                contains = true;
                break;
            }
        }
        assert!(
            contains,
            "Account keys should be the ones used in creating it"
        );
    }

    let account_id = session.account_id.unwrap();

    for key in session.pks.clone() {
        let ids = session.key_accounts(key);
        assert_eq!(
            ids.len(),
            1,
            "The public key should only be used by one account"
        );
        assert_eq!(
            ids[0], account_id,
            "The ID should be of the created account"
        );
    }

    assert_eq!(account.balance, 0, "Balance should be zero");
    assert_eq!(account.threshold, THRESHOLD, "Threshold should be as set");
    assert_eq!(
        account.description, DESCRIPTION,
        "Description should be as set"
    );
}

#[test]
fn deposit() {
    const DEPOSITOR_INDEX: usize = 1;
    const DEPOSIT_AMOUNT: u64 = 1_000;

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut session = ContractSession::new(&mut rng);

    session.create_account();
    let account = session.account();

    assert_eq!(
        account.balance, 0,
        "Account should have zero initial balance"
    );

    session.deposit(DEPOSITOR_INDEX, DEPOSIT_AMOUNT);
    let account = session.account();

    assert_eq!(
        account.balance, DEPOSIT_AMOUNT,
        "Account should have the amount deposited"
    );
}

#[test]
fn transfer() {
    const DEPOSITOR_INDEX: usize = 1;
    const DEPOSIT_AMOUNT: u64 = 1_000;
    const TRANSFERRER_INDEX: usize = 3;
    const RECEIVER_INDEX: usize = 2;
    const TRANSFER_AMOUNT: u64 = DEPOSIT_AMOUNT / 2;

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut session = ContractSession::new(&mut rng);

    session.create_account();
    session.deposit(DEPOSITOR_INDEX, DEPOSIT_AMOUNT);

    let account = session.account();
    let balance = session.balance(session.pks[RECEIVER_INDEX]);
    assert_eq!(
        account.balance, DEPOSIT_AMOUNT,
        "Account should have the amount deposited",
    );
    assert_eq!(
        balance, INITIAL_BALANCE,
        "The receiver account should, at first, just have its initial balance"
    );

    session.transfer(TRANSFERRER_INDEX, RECEIVER_INDEX, TRANSFER_AMOUNT);

    let account = session.account();
    let balance = session.balance(session.pks[RECEIVER_INDEX]);
    assert_eq!(
        account.balance,
        DEPOSIT_AMOUNT - TRANSFER_AMOUNT,
        "Account should have the amount deposited minus the transferred amount"
    );
    assert_eq!(
        balance,
        INITIAL_BALANCE + TRANSFER_AMOUNT,
        "The receiver account should, after the transfer, have its initial balance plus the transferred amount"
    );
}

#[test]
fn change_account() {
    const CHANGER_INDEX: usize = 1;
    const REMOVE_INDEX: usize = 4;
    const NEW_THRESHOLD: u32 = THRESHOLD + 1;
    const NEW_DESCRIPTION: &str = "new-description";

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut session = ContractSession::new(&mut rng);

    let new_sk = SecretKey::random(&mut rng);
    let new_pk = PublicKey::from(&new_sk);

    session.create_account();

    let account = session.account();
    assert_eq!(account.balance, 0, "Balance should be zero");
    assert_eq!(account.threshold, THRESHOLD, "Threshold should be as set");
    assert_eq!(
        account.description, DESCRIPTION,
        "Description should be as set"
    );

    let mut pks = session.pks.clone();
    let account_keys = session.account_keys();

    assert_eq!(
        account_keys.len(),
        pks.len(),
        "Equal number of keys should be inserted"
    );

    for account_key in account_keys {
        let mut contains = false;
        for pk in &pks {
            if account_key == *pk {
                contains = true;
                break;
            }
        }
        assert!(
            contains,
            "Account keys should be the ones used in creating it"
        );
    }

    let account_id = session.account_id.unwrap();

    for key in pks.clone() {
        let ids = session.key_accounts(key);
        assert_eq!(
            ids.len(),
            1,
            "The public key should only be used by one account"
        );
        assert_eq!(
            ids[0], account_id,
            "The ID should be of the created account"
        );
    }

    session.change_account(
        CHANGER_INDEX,
        vec![
            AccountChange::SetThreshold {
                threshold: NEW_THRESHOLD,
            },
            AccountChange::RemoveKey {
                key: session.pks[REMOVE_INDEX],
            },
            AccountChange::AddKey { key: new_pk },
            AccountChange::SetDescription {
                description: String::from(NEW_DESCRIPTION),
            },
        ],
    );

    let account = session.account();
    assert_eq!(account.balance, 0, "Balance should be zero");
    assert_eq!(
        account.threshold, NEW_THRESHOLD,
        "Threshold should be as set"
    );
    assert_eq!(
        account.description, NEW_DESCRIPTION,
        "Description should be as set"
    );

    let removed_pk = pks.remove(REMOVE_INDEX);
    pks.push(new_pk);
    let account_keys = session.account_keys();

    assert_eq!(
        account_keys.len(),
        pks.len(),
        "There should be the same number of keys after change"
    );

    for account_key in account_keys {
        let mut contains = false;
        for pk in &pks {
            if account_key == *pk {
                contains = true;
                break;
            }
        }
        assert!(
            contains,
            "Account keys should be the ones used in creating it"
        );
    }

    let account_id = session.account_id.unwrap();

    for key in pks.clone() {
        let ids = session.key_accounts(key);
        assert_eq!(
            ids.len(),
            1,
            "The public key should only be used by one account"
        );
        assert_eq!(
            ids[0], account_id,
            "The ID should be of the created account"
        );
    }

    assert_eq!(
        session.key_accounts(removed_pk).len(),
        0,
        "The removed key should have no accounts"
    );
}

// #[test]
// fn print() {
//     use dusk_bytes::Serializable;
//
//     let mut rng = StdRng::seed_from_u64(RNG_SEED);
//
//     for _ in 0..NUM_KEYS {
//         let sk = SecretKey::random(&mut rng);
//         let pk = PublicKey::from(&sk);
//         println!("{}", bs58::encode(pk.to_bytes()).into_string());
//     }
// }

fn main() {
    unreachable!("`main` should never run for this crate");
}

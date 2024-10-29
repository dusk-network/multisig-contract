use std::sync::mpsc;

use execution_core::{
    transfer::{data::ContractCall, Transaction, TRANSFER_CONTRACT},
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

use bls::{PublicKey, SecretKey};
use multisig_contract_types::*;

const CONTRACT_BYTECODE: &[u8] = include_bytes!("../../build/multisig_contract.wasm");
const CONTRACT_ID: ContractId = ContractId::from_bytes([1; 32]);
const CONTRACT_OWNER: [u8; 64] = [0u8; 64];

const CHAIN_ID: u8 = 0xFE;
const BLOCK_HEIGHT: u64 = 1;
const SNAPSHOT: &str = include_str!("../state.toml");

const NUM_KEYS: usize = 16;
const RNG_SEED: u64 = 0xBEEF;

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
        let state_dir = TempDir::new().expect("Creating temporary directory should succeed");
        let snapshot = toml::from_str(SNAPSHOT).expect("Deserializing snapshot should succeed");

        let (vm, root) = state::deploy(&state_dir, &snapshot, |_| {})
            .expect("Deploying snapshot should succeed");
        let mut session = rusk_abi::new_session(&vm, root, CHAIN_ID, BLOCK_HEIGHT)
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

    fn call<A, R>(&mut self, fn_name: &str, fn_arg: &A) -> Result<CallReceipt<R>>
    where
        A: for<'b> Serialize<StandardBufSerializer<'b>>,
        A::Archived: for<'b> CheckBytes<DefaultValidator<'b>>,
        R: Archive,
        R::Archived: Deserialize<R, Infallible> + for<'b> CheckBytes<DefaultValidator<'b>>,
    {
        self.session.call(CONTRACT_ID, fn_name, fn_arg, u64::MAX)
    }

    fn feeder_query<A, R>(&mut self, fn_name: &str, fn_arg: &A) -> Result<Vec<R>>
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
        self.session
            .feeder_call::<_, ()>(CONTRACT_ID, fn_name, fn_arg, u64::MAX, sender)?;

        for bytes in receiver.into_iter() {
            results.push(rkyv::from_bytes(&bytes).map_err(|_| PiecrustError::MissingFeed)?);
        }

        Ok(results)
    }

    fn create_account(&mut self) -> u64 {
        let pks = self.pks.clone();
        let id = self
            .call("create_account", &pks)
            .expect("Creating an account should succeed")
            .data;
        self.account_id = Some(id);
        id
    }

    fn deposit(&mut self, index: usize, amount: u64) {
        let id = self
            .account_id
            .expect("must call `create_account` before `account`");
        let sk = self.sks[index].clone();

        const GAS_LIMIT: u64 = 1_000_000;
        const GAS_PRICE: u64 = 1;
        const NONCE: u64 = 1;

        let fn_args = rkyv::to_bytes::<_, 128>(&(amount, id))
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
            .call::<_, ()>(TRANSFER_CONTRACT, "refund", &receipt.gas_spent, u64::MAX)
            .expect("Refunding must succeed");
    }

    fn account(&mut self) -> AccountData {
        let id = self
            .account_id
            .expect("must call `create_account` before `account`");
        self.call("account", &id)
            .expect("Creating an account should succeed")
            .data
    }

    fn account_keys(&mut self) -> Vec<PublicKey> {
        let id = self
            .account_id
            .expect("must call `create_account` before `account_keys`");

        self.feeder_query("account_keys", &id)
            .expect("Feeding account keys should succeed")
    }

    fn key_accounts(&mut self, index: usize) -> Vec<u64> {
        let key = self.pks[index].clone();
        self.feeder_query("key_accounts", &key)
            .expect("Feeding key accounts should succeed")
    }
}

#[test]
fn create_account() {
    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut session = ContractSession::new(&mut rng);

    session.create_account();

    assert_eq!(
        session.account_keys(),
        session.pks,
        "Account keys should be the ones used in creating it"
    );

    let id = session.account_id.unwrap();

    for (i, _) in session.pks.clone().into_iter().enumerate() {
        let ids = session.key_accounts(i);
        assert_eq!(
            ids.len(),
            1,
            "The public key should only be used by one account"
        );
        assert_eq!(ids[0], id, "The ID should be of the created account");
    }
}

#[test]
fn deposit() {
    const DEPOSIT_AMOUNT: u64 = 100;

    let mut rng = StdRng::seed_from_u64(RNG_SEED);
    let mut session = ContractSession::new(&mut rng);

    session.create_account();
    let account = session.account();

    assert_eq!(
        account.balance, 0,
        "Account should have zero initial balance"
    );

    session.deposit(1, DEPOSIT_AMOUNT);
    let account = session.account();

    assert_eq!(
        account.balance, DEPOSIT_AMOUNT,
        "Account should have the amount deposited"
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

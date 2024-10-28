use std::sync::mpsc;

use execution_core::{ContractId, StandardBufSerializer};
use rusk_abi::{CallReceipt, ContractData, PiecrustError, Session};

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

const CHAIN_ID: u8 = 0xFE;
const OWNER: [u8; 64] = [0u8; 64];

type Result<T, Error = PiecrustError> = std::result::Result<T, Error>;

struct ContractSession {
    session: Session,
    sks: Vec<SecretKey>,
    pks: Vec<PublicKey>,
    account_id: Option<u128>,
}

#[allow(dead_code)]
impl ContractSession {
    fn new<Rng: RngCore + CryptoRng>(rng: &mut Rng, num_keys: usize) -> Self {
        let vm = rusk_abi::new_ephemeral_vm().expect("Creating VM should succeed");
        let mut session = rusk_abi::new_genesis_session(&vm, CHAIN_ID);

        let mut sks = Vec::with_capacity(num_keys);
        let mut pks = Vec::with_capacity(num_keys);

        for _ in 0..num_keys {
            let sk = SecretKey::random(rng);
            let pk = PublicKey::from(&sk);
            sks.push(sk);
            pks.push(pk);
        }

        session
            .deploy(
                CONTRACT_BYTECODE,
                ContractData::builder()
                    .owner(OWNER)
                    .contract_id(CONTRACT_ID),
                u64::MAX,
            )
            .expect("Deploying the multisig contract should succeed");

        Self {
            session,
            sks,
            pks,
            account_id: None,
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

    fn create_account(&mut self) -> u128 {
        let pks = self.pks.clone();
        let id = self
            .call("create_account", &pks)
            .expect("Creating an account should succeed")
            .data;
        self.account_id = Some(id);
        id
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

    fn key_accounts(&mut self, index: usize) -> Vec<u128> {
        let key = self.pks[index].clone();
        self.feeder_query("key_accounts", &key)
            .expect("Feeding key accounts should succeed")
    }
}

#[test]
fn create_account() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let mut session = ContractSession::new(&mut rng, 32);

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

fn main() {
    unreachable!("`main` should never run for this crate");
}

# Dusk - Multisig Contract

This repository contains an example of how to do multi-signature transfers, where only N out of M
keys must sign a message to transfer Dusk to another account.

## Introduction

Dusk's chain supports cheaply verifying BLS multisig signatures passed to a contract. This contract
leverages this capability to offer multisig accounts. Users get to create accounts owned by multiple
different BLS keys, where any important action must be signed (agreed upon) by some configurable
portion of those keys.

This contract works directly with Dusk - receives deposits of Dusk and transfers to Dusk accounts -
but it can be imagined that it would also work for [transparent tokens], given slight modifications
of its code.

[transparent tokens]: https://github.com/dusk-network/transparent-token

## Build

Have [`rust`] and [`make`] installed and a built instance of [`rusk`] located in the same parent
directory as this repository and run:

```sh
make
make test # optional
```

[`rust`]: https://www.rust-lang.org/tools/install
[`make`]: https://www.gnu.org/software/make
[`rusk`]: https://github.com/dusk-network/rusk

## Features

This contract allows a caller to:

- Create multisig accounts
- Deposit Dusk to multisig accounts
- Transfer Dusk from multisig accounts to Moonlight accounts
- Modify multisig accounts

### Data Structures

The data structures that a user will use to interact with the functions of this contract are defined
in the [`types` crate] in this repository. This contract makes use of [`rkyv`] serialization. The
keys used by this contract are BLS12_381 keys.

[`types` crate]: ./types
[`rkyv`]: https://github.com/rkyv/rkyv

### Functions

The following functions will be defined by a contract implementing this specification. `&self` and
`&mut self` are used to denote whether a function mutates the state handled by the contract, and
closely matches its use in the implementation.

```rust
fn create_account(&mut self, _: CreateAccount) -> u64;
fn deposit(&mut self, _: Deposit);
fn transfer(&mut self, _: Transfer); 
fn change_account(&mut self, _: ChangeAccount); 
fn account(&self, _: u64) -> AccountData; 
fn account_keys(&self, _: u64) -> Vec<PublicKey>; // feeder query 
fn key_accounts(&self, _: PublicKey) -> Vec<u64>; // feeder query 
```

### Events

On a `create_account`, `deposit`, `transfer`, and `change_account` functions all emit events related
to the action performed. The data emitted is also defined in the [`types` crate].

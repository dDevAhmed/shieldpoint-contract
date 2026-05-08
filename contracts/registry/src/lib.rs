#![no_std]

use soroban_sdk::{contract, contractevent, contractimpl, contracttype, Address, BytesN, Env, Map, Vec, panic_with_error};

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    /// Map<u64, ProofDetails> — keyed by proof ID
    Proofs,
    /// Map<Address, Vec<u64>> — list of proof IDs per user
    UserProofs,
    /// Next proof ID counter
    NextProofId,
    /// Authorized verifier contract address
    VerifierContract,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ProofDetails {
    pub user: Address,
    pub proof_type: u32,
    pub commitment_hash: BytesN<32>,
    pub timestamp: u64,
    pub valid: bool,
}

#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum RegistryError {
    NotInitialised = 1,
    AlreadyInitialised = 2,
    NotFound = 3,
    Unauthorised = 4,
}

impl soroban_sdk::TryFromVal<Env, soroban_sdk::Val> for RegistryError {
    type Error = soroban_sdk::ConversionError;
    fn try_from_val(env: &Env, v: &soroban_sdk::Val) -> Result<Self, Self::Error> {
        let n = u32::try_from_val(env, v)?;
        match n {
            1 => Ok(RegistryError::NotInitialised),
            2 => Ok(RegistryError::AlreadyInitialised),
            3 => Ok(RegistryError::NotFound),
            4 => Ok(RegistryError::Unauthorised),
            _ => Err(soroban_sdk::ConversionError),
        }
    }
}

impl soroban_sdk::IntoVal<Env, soroban_sdk::Val> for RegistryError {
    fn into_val(&self, env: &Env) -> soroban_sdk::Val {
        (*self as u32).into_val(env)
    }
}

#[contractevent]
pub enum ProofRegistryEvent {
    ProofStored(u64, Address, u32, BytesN<32>, bool),
}

#[contract]
pub struct Registry;

#[contractimpl]
impl Registry {
    pub fn initialize(env: Env, verifier_contract: Address) {
        let storage = env.storage().instance();
        if storage.get::<DataKey, Address>(&DataKey::VerifierContract).is_some() {
            panic_with_error!(&env, RegistryError::AlreadyInitialised);
        }
        storage.set(&DataKey::VerifierContract, &verifier_contract);
        storage.set(&DataKey::NextProofId, &1u64);
    }

    pub fn store_proof(
        env: Env,
        user: Address,
        proof_type: u32,
        commitment_hash: BytesN<32>,
        proof_valid: bool,
    ) -> u64 {
        let verifier_contract = env
            .storage()
            .instance()
            .get(&DataKey::VerifierContract)
            .unwrap_or_else(|| panic_with_error!(&env, RegistryError::NotInitialised));

        if env.invoker() != verifier_contract {
            panic_with_error!(&env, RegistryError::Unauthorised);
        }

        let proof_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextProofId)
            .unwrap_or_else(|| 1u64);

        let mut proofs: Map<u64, ProofDetails> = env
            .storage()
            .instance()
            .get(&DataKey::Proofs)
            .unwrap_or_else(|| Map::new(&env));

        proofs.set(
            proof_id,
            ProofDetails {
                user: user.clone(),
                proof_type,
                commitment_hash: commitment_hash.clone(),
                timestamp: env.ledger().timestamp(),
                valid: proof_valid,
            },
        );
        env.storage().instance().set(&DataKey::Proofs, &proofs);

        let mut user_proofs: Map<Address, Vec<u64>> = env
            .storage()
            .instance()
            .get(&DataKey::UserProofs)
            .unwrap_or_else(|| Map::new(&env));

        let mut ids: Vec<u64> = user_proofs
            .get(user.clone())
            .unwrap_or_else(|| Vec::new(&env));
        ids.push_back(proof_id);
        user_proofs.set(user.clone(), ids);
        env.storage().instance().set(&DataKey::UserProofs, &user_proofs);

        env.storage()
            .instance()
            .set(&DataKey::NextProofId, &(proof_id + 1));

        env.events().publish(
            ProofRegistryEvent::ProofStored(
                proof_id,
                user,
                proof_type,
                commitment_hash,
                proof_valid,
            ),
        );

        proof_id
    }

    pub fn get_proof(env: Env, proof_id: u64) -> ProofDetails {
        let proofs: Map<u64, ProofDetails> = env
            .storage()
            .instance()
            .get(&DataKey::Proofs)
            .unwrap_or_else(|| Map::new(&env));

        proofs.get(proof_id).unwrap_or_else(|| {
            panic_with_error!(&env, RegistryError::NotFound)
        })
    }

    pub fn get_user_proofs(env: Env, user: Address) -> Vec<u64> {
        let user_proofs: Map<Address, Vec<u64>> = env
            .storage()
            .instance()
            .get(&DataKey::UserProofs)
            .unwrap_or_else(|| Map::new(&env));

        user_proofs.get(user).unwrap_or_else(|| Vec::new(&env))
    }

    pub fn has_proof(env: Env, proof_id: u64) -> bool {
        let proofs: Map<u64, ProofDetails> = env
            .storage()
            .instance()
            .get(&DataKey::Proofs)
            .unwrap_or_else(|| Map::new(&env));
        proofs.contains_key(proof_id)
    }
}

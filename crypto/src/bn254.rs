#![no_std]

use soroban_sdk::{Bytes, BytesN, Env, Vec};

/// Performs a multi-pairing check on BN254 (alt-bn128) curve.
///
/// Mathematically, it checks if:
///   prod_{i=0}^{n-1} e(P_i, Q_i) == 1
///
/// where P_i are G1 points and Q_i are G2 points.
///
/// # Arguments
/// * `g1_points` - A vector of 64-byte uncompressed G1 points (X || Y).
/// * `g2_points` - A vector of 128-byte uncompressed G2 points (X.c1 || X.c0 || Y.c1 || Y.c0).
///
/// # Returns
/// Returns `true` if the pairing product is 1, `false` otherwise or if input lengths mismatch.
///
/// # Gas Metering
/// Estimated cost per pairing: ~500,000 - 1,000,000 instructions.
pub fn multi_pairing_check(env: &Env, g1_points: Vec<Bytes>, g2_points: Vec<Bytes>) -> bool {
    if g1_points.len() != g2_points.len() || g1_points.is_empty() {
        return false;
    }
    env.crypto().bn254_multi_pairing_check(&g1_points, &g2_points)
}

/// Verifies a Groth16 proof for the BN254 curve using the native host function.
///
/// # Arguments
/// * `vk` - 32-byte verification key identifier or hash.
/// * `proof_a` - 64-byte G1 point.
/// * `proof_b` - 128-byte G2 point.
/// * `proof_c` - 64-byte G1 point.
/// * `public_inputs` - Vector of 32-byte scalar field elements.
///
/// # Returns
/// Returns `true` only if the host pairing check passes.
///
/// # Gas Metering
/// Estimated total cost per verification: ~2,000,000 - 3,000,000 instructions.
pub fn verify_groth16_proof(
    env: Env,
    vk: [u8; 32],
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    public_inputs: Vec<[u8; 32]>,
) -> bool {
    // 1. Prepare Verification Key
    let vk_bytes = BytesN::from_array(&env, &vk);

    // 2. Prepare Proof Bytes (A || B || C)
    let mut proof_bytes = Bytes::new(&env);
    proof_bytes.extend_from_array(&proof_a);
    proof_bytes.extend_from_array(&proof_b);
    proof_bytes.extend_from_array(&proof_c);

    // 3. Prepare Public Inputs (flattened)
    let mut inputs_bytes = Bytes::new(&env);
    for input in public_inputs.iter() {
        inputs_bytes.extend_from_array(&input);
    }

    // 4. Call Host Function
    env.crypto().groth16_bn254_verify(&vk_bytes, &proof_bytes, &inputs_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{Env, Vec, Bytes};

    #[test]
    fn test_verify_groth16_proof_mock() {
        let env = Env::default();
        
        // Mock values (actual verification will fail/return false in test utils 
        // unless host is fully mocked, but we check signature and flow).
        let vk = [0u8; 32];
        let proof_a = [0u8; 64];
        let proof_b = [0u8; 128];
        let proof_c = [0u8; 64];
        let mut public_inputs = Vec::new(&env);
        public_inputs.push_back([0u8; 32]);

        // In test environment without a full mock, this might return false 
        // or whatever the default test implementation provides.
        // We ensure it doesn't panic.
        let _result = verify_groth16_proof(
            env,
            vk,
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
        );
    }

    #[test]
    fn test_multi_pairing_check_length_mismatch() {
        let env = Env::default();
        let mut g1 = Vec::new(&env);
        g1.push_back(Bytes::from_slice(&env, &[0u8; 64]));
        
        let g2 = Vec::new(&env); // empty g2

        let result = multi_pairing_check(&env, g1, g2);
        assert!(!result);
    }

    #[test]
    fn test_multi_pairing_check_empty() {
        let env = Env::default();
        let g1 = Vec::new(&env);
        let g2 = Vec::new(&env);

        let result = multi_pairing_check(&env, g1, g2);
        assert!(!result);
    }
}

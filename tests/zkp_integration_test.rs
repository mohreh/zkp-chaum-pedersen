use num_bigint::BigUint;
use zkp_chaum_pedersen::{ChaumPedersenParameters, generate_random_nonce};

/// Helper function to initialize standard RFC 3526 1024-bit MODP parameters (Group 2).
fn setup_1024_bit_params() -> ChaumPedersenParameters {
    let p_hex = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF";
    let prime_modulus = BigUint::parse_bytes(p_hex, 16).unwrap();

    // In Safe Primes (p = 2q + 1), the subgroup order 'q' is exactly (p - 1) / 2
    let subgroup_order = (&prime_modulus - BigUint::from(1u32)) / BigUint::from(2u32);

    // Generator 2 is mathematically guaranteed to generate the prime-order subgroup
    let generator_1 = BigUint::from(2u32);
    let generator_2 = generator_1.modpow(&BigUint::from(2u32), &prime_modulus);

    ChaumPedersenParameters {
        prime_modulus,
        subgroup_order,
        generator_1,
        generator_2,
    }
}

/// Helper function to initialize standard RFC 3526 2048-bit MODP parameters (Group 14).
fn setup_2048_bit_params() -> ChaumPedersenParameters {
    let p_hex = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let prime_modulus = BigUint::parse_bytes(p_hex, 16).unwrap();

    // Dynamically calculate 'q' to avoid any hardcoded mismatches
    let subgroup_order = (&prime_modulus - BigUint::from(1u32)) / BigUint::from(2u32);

    let generator_1 = BigUint::from(2u32);
    let generator_2 = generator_1.modpow(&BigUint::from(2u32), &prime_modulus);

    ChaumPedersenParameters {
        prime_modulus,
        subgroup_order,
        generator_1,
        generator_2,
    }
}

// ============================================================================
// Happy Path Tests (Valid Proofs)
// ============================================================================

#[test]
fn test_valid_proof_1024_bit() {
    let params = setup_1024_bit_params();

    let secret_value = generate_random_nonce(&params.subgroup_order);
    let random_nonce = generate_random_nonce(&params.subgroup_order);
    let challenge = generate_random_nonce(&params.subgroup_order);

    let public_value_1 = params.exponentiate(&params.generator_1, &secret_value);
    let public_value_2 = params.exponentiate(&params.generator_2, &secret_value);

    let commitment_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let commitment_2 = params.exponentiate(&params.generator_2, &random_nonce);

    let response = params.compute_response(&random_nonce, &challenge, &secret_value);

    let is_valid = params.verify(
        &commitment_1,
        &commitment_2,
        &public_value_1,
        &public_value_2,
        &challenge,
        &response,
    );

    assert!(
        is_valid,
        "A valid 1024-bit Chaum-Pedersen proof was incorrectly rejected."
    );
}

#[test]
fn test_valid_proof_2048_bit() {
    let params = setup_2048_bit_params();

    let secret_value = generate_random_nonce(&params.subgroup_order);
    let random_nonce = generate_random_nonce(&params.subgroup_order);
    let challenge = generate_random_nonce(&params.subgroup_order);

    let public_value_1 = params.exponentiate(&params.generator_1, &secret_value);
    let public_value_2 = params.exponentiate(&params.generator_2, &secret_value);

    let commitment_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let commitment_2 = params.exponentiate(&params.generator_2, &random_nonce);

    let response = params.compute_response(&random_nonce, &challenge, &secret_value);

    let is_valid = params.verify(
        &commitment_1,
        &commitment_2,
        &public_value_1,
        &public_value_2,
        &challenge,
        &response,
    );

    assert!(
        is_valid,
        "A valid 2048-bit Chaum-Pedersen proof was incorrectly rejected."
    );
}

// ============================================================================
// Malicious Scenarios & Invalid Proofs
// ============================================================================

#[test]
fn test_invalid_proof_wrong_secret() {
    let params = setup_1024_bit_params();

    let true_secret = generate_random_nonce(&params.subgroup_order);
    let fake_secret = generate_random_nonce(&params.subgroup_order);
    let random_nonce = generate_random_nonce(&params.subgroup_order);
    let challenge = generate_random_nonce(&params.subgroup_order);

    // Public values are bound to the TRUE secret
    let public_value_1 = params.exponentiate(&params.generator_1, &true_secret);
    let public_value_2 = params.exponentiate(&params.generator_2, &true_secret);

    let commitment_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let commitment_2 = params.exponentiate(&params.generator_2, &random_nonce);

    // Malicious prover tries to generate a response using the FAKE secret
    let forged_response = params.compute_response(&random_nonce, &challenge, &fake_secret);

    let is_valid = params.verify(
        &commitment_1,
        &commitment_2,
        &public_value_1,
        &public_value_2,
        &challenge,
        &forged_response,
    );

    assert!(
        !is_valid,
        "Security Flaw: Proof with a forged/incorrect secret was accepted!"
    );
}

#[test]
fn test_invalid_proof_mismatched_discrete_logs() {
    // This tests the core premise of Chaum-Pedersen: proving equality of discrete logs.
    // If log_g1(y1) != log_g2(y2), the verification MUST fail.

    let params = setup_1024_bit_params();

    let secret_1 = generate_random_nonce(&params.subgroup_order);
    let secret_2 = generate_random_nonce(&params.subgroup_order); // Different secret!
    let random_nonce = generate_random_nonce(&params.subgroup_order);
    let challenge = generate_random_nonce(&params.subgroup_order);

    // y1 uses secret_1, but y2 uses secret_2
    let public_value_1 = params.exponentiate(&params.generator_1, &secret_1);
    let public_value_2 = params.exponentiate(&params.generator_2, &secret_2);

    let commitment_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let commitment_2 = params.exponentiate(&params.generator_2, &random_nonce);

    // Prover attempts to answer using secret_1
    let response = params.compute_response(&random_nonce, &challenge, &secret_1);

    let is_valid = params.verify(
        &commitment_1,
        &commitment_2,
        &public_value_1,
        &public_value_2,
        &challenge,
        &response,
    );

    assert!(
        !is_valid,
        "Security Flaw: Mismatched discrete logarithms were successfully verified!"
    );
}

#[test]
fn test_invalid_proof_tampered_commitment() {
    let params = setup_1024_bit_params();

    let secret_value = generate_random_nonce(&params.subgroup_order);
    let random_nonce = generate_random_nonce(&params.subgroup_order);
    let challenge = generate_random_nonce(&params.subgroup_order);

    let public_value_1 = params.exponentiate(&params.generator_1, &secret_value);
    let public_value_2 = params.exponentiate(&params.generator_2, &secret_value);

    let mut commitment_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let commitment_2 = params.exponentiate(&params.generator_2, &random_nonce);

    let response = params.compute_response(&random_nonce, &challenge, &secret_value);

    // MITM (Man-in-the-Middle) or transmission error alters commitment_1
    commitment_1 += BigUint::from(1u32);

    let is_valid = params.verify(
        &commitment_1,
        &commitment_2,
        &public_value_1,
        &public_value_2,
        &challenge,
        &response,
    );

    assert!(
        !is_valid,
        "Security Flaw: Verification succeeded despite tampered commitment data!"
    );
}

#[test]
fn test_invalid_proof_tampered_challenge() {
    let params = setup_1024_bit_params();

    let secret_value = generate_random_nonce(&params.subgroup_order);
    let random_nonce = generate_random_nonce(&params.subgroup_order);

    let original_challenge = generate_random_nonce(&params.subgroup_order);
    let forged_challenge = generate_random_nonce(&params.subgroup_order);

    let public_value_1 = params.exponentiate(&params.generator_1, &secret_value);
    let public_value_2 = params.exponentiate(&params.generator_2, &secret_value);

    let commitment_1 = params.exponentiate(&params.generator_1, &random_nonce);
    let commitment_2 = params.exponentiate(&params.generator_2, &random_nonce);

    // Response is formulated using the original challenge
    let response = params.compute_response(&random_nonce, &original_challenge, &secret_value);

    // Verifier maliciously or erroneously checks against a different challenge
    let is_valid = params.verify(
        &commitment_1,
        &commitment_2,
        &public_value_1,
        &public_value_2,
        &forged_challenge,
        &response,
    );

    assert!(
        !is_valid,
        "Security Flaw: Verification succeeded despite challenge mismatch!"
    );
}

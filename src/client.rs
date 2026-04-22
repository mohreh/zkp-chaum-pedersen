pub mod zkp_auth {
    include!(concat!(env!("OUT_DIR"), "/zkp_auth.rs"));
}

use std::{env, io::stdin};

use argon2::{Argon2, PasswordHasher};
use crypto_bigint::Odd;
use crypto_bigint::modular::FixedMontyForm;
use crypto_bigint::modular::MontyParams;
use crypto_bigint::{Encoding, U2048, Uint};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use zkp_auth::auth_service_client::AuthServiceClient;
use zkp_auth::{
    CreateAuthenticationChallengeRequest, RegisterRequest, VerifyAuthenticationRequest,
    VerifyNonInteractiveRequest,
};
use zkp_chaum_pedersen::{ChaumPedersenParameters, generate_random_nonce};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let server_port = env::var("SERVER_PORT").unwrap_or_else(|_| "50051".to_string());
    let zkp = ChaumPedersenParameters::default();

    let mut client =
        AuthServiceClient::connect(format!("http://127.0.0.1:{}", server_port)).await?;
    log::info!("Connected to the server at port {}", server_port);

    let mut buf = String::new();
    println!("Enter Username: ");
    stdin()
        .read_line(&mut buf)
        .expect("Failed to read username");
    let username = buf.trim().to_string();

    buf.clear();
    println!("Enter Password: ");
    stdin()
        .read_line(&mut buf)
        .expect("Failed to read password");
    let password = buf.trim().as_bytes();

    log::info!("Deriving a cryptographically secure secret from the password...");

    let salt_hash = Sha256::digest(username.as_bytes());
    let mut argon2_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password, &salt_hash, &mut argon2_key)
        .expect("Argon2 hashing failed");

    let hkdf = Hkdf::<Sha256>::new(None, &argon2_key);
    let mut expanded_key = [0u8; 256];
    hkdf.expand(b"zkp-chaum-pedersen-secret-x", &mut expanded_key)
        .expect("HKDF expansion failed");

    let secret_raw = Uint::from_be_slice(&expanded_key);

    let odd_q = Odd::new(zkp.subgroup_order).expect("Modulus must be odd");
    let q_params = MontyParams::new_vartime(odd_q);
    let secret_value = FixedMontyForm::<32>::new(&secret_raw, &q_params).retrieve();

    let public_value_1 = zkp.exponentiate(&zkp.generator_1, &secret_value);
    let public_value_2 = zkp.exponentiate(&zkp.generator_2, &secret_value);

    // Registeration
    log::info!("Registering user: {}", username);
    let register_request = RegisterRequest {
        user: username.clone(),
        public_value_1: public_value_1.to_be_bytes().to_vec(),
        public_value_2: public_value_2.to_be_bytes().to_vec(),
    };

    match client.register(register_request).await {
        Ok(_) => log::info!("Registration successful!"),
        Err(e) => log::warn!("Registration skipped or failed: {}", e.message()),
    }

    // Interative Login
    log::info!("--- Starting INTERACTIVE Authentication ---");
    let random_nonce = generate_random_nonce(&zkp.subgroup_order);
    let commitment_1 = zkp.exponentiate(&zkp.generator_1, &random_nonce);
    let commitment_2 = zkp.exponentiate(&zkp.generator_2, &random_nonce);

    let challenge_resp = client
        .create_authentication_challenge(CreateAuthenticationChallengeRequest {
            user: username.clone(),
            commitment_1: commitment_1.to_be_bytes().to_vec(),
            commitment_2: commitment_2.to_be_bytes().to_vec(),
        })
        .await?
        .into_inner();

    let auth_id = challenge_resp.auth_id;
    let challenge = Uint::from_be_slice(&challenge_resp.challenge);

    let response = zkp.compute_response(&random_nonce, &challenge, &secret_value);

    let auth_resp = client
        .verify_authentication(VerifyAuthenticationRequest {
            auth_id,
            response: response.to_be_bytes().to_vec(),
        })
        .await;

    match auth_resp {
        Ok(res) => log::info!(
            "Interactive Login Success! Session: {}",
            res.into_inner().session_id
        ),
        Err(e) => log::error!("Interactive Login Failed: {}", e.message()),
    }

    // Non-Interactive Login
    log::info!("--- Starting NON-INTERACTIVE Authentication (Fiat-Shamir) ---");

    let ni_random_nonce = generate_random_nonce(&zkp.subgroup_order);
    let ni_commitment_1 = zkp.exponentiate(&zkp.generator_1, &ni_random_nonce);
    let ni_commitment_2 = zkp.exponentiate(&zkp.generator_2, &ni_random_nonce);

    let ni_challenge = zkp.compute_fiat_shamir_challenge(
        &public_value_1,
        &public_value_2,
        &ni_commitment_1,
        &ni_commitment_2,
    );

    let ni_response = zkp.compute_response(&ni_random_nonce, &ni_challenge, &secret_value);

    let ni_request = VerifyNonInteractiveRequest {
        user: username.clone(),
        challenge: ni_challenge.to_be_bytes().to_vec(),
        response: ni_response.to_be_bytes().to_vec(),
    };

    let ni_auth_resp = client.verify_non_interactive(ni_request).await;

    match ni_auth_resp {
        Ok(res) => log::info!(
            "Non-Interactive Login Success! Session: {}",
            res.into_inner().session_id
        ),
        Err(e) => log::error!("Non-Interactive Login Failed: {}", e.message()),
    }

    Ok(())
}

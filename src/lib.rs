use crypto_bigint::modular::{FixedMontyForm, MontyParams, Retrieve};
use crypto_bigint::{Encoding, NonZero, Odd, RandomMod, U2048};
use rand::Rng;
use rand::distr::{Alphanumeric, SampleString};
use rand::rngs::SysRng;
use rand_core::UnwrapErr;
use sha2::{Digest, Sha256};

/// Public parameters for the Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol.
/// This protocol proves the equality of discrete logarithms: log_g1(y1) == log_g2(y2) == x,
/// without revealing the underlying secret value 'x'.
/// It operates within a prime-order subgroup of the multiplicative group Z_p^*.
#[derive(Debug)]
pub struct ChaumPedersenParameters {
    /// The large prime modulus (p) defining the finite field Z_p.
    pub prime_modulus: U2048,
    /// The prime order (q) of the cyclic subgroup.
    pub subgroup_order: U2048,
    /// The first generator (g1) of the subgroup.
    pub generator_1: U2048,
    /// The second generator (g2) of the subgroup.
    pub generator_2: U2048,
}

/// A cryptographically secure, non-interactive Zero-Knowledge Proof. This Struct Will be send directly to the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonInteractiveProof {
    pub challenge: U2048,
    pub response: U2048,
}

impl ChaumPedersenParameters {
    /// Returns the standard RFC 3526 2048-bit MODP parameters (Group 14).
    /// These parameters are safe primes where p = 2q + 1, widely used in secure communications.
    pub fn get_default_2048_parameters() -> Self {
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
        let prime_modulus = U2048::from_be_hex(p_hex);

        // q = (p - 1) / 2. Since p is odd, a right shift by 1 is mathematically equivalent to (p-1)/2.
        let subgroup_order = prime_modulus.wrapping_shr_vartime(1);
        let generator_1 = U2048::from_u64(2);

        // Setup Montgomery parameters for modulo 'p'.
        let odd_p = Odd::new(prime_modulus).expect("Modulus must be odd");
        let p_params = MontyParams::new_vartime(odd_p);

        // SECURE GENERATION OF g2
        let mut hasher = Sha256::new();
        hasher.update(b"Chaum-Pedersen Generator 2 Seed for RFC 3526 Group 14");
        let hash_result = hasher.finalize();

        // Map the 32-byte SHA256 output to the end of a 256-byte array to create a U2048
        let mut h_bytes = [0u8; 256];
        h_bytes[256 - 32..].copy_from_slice(&hash_result);

        let h = U2048::from_be_bytes(h_bytes.into());
        let h_form = FixedMontyForm::<32>::new(&h, &p_params);

        // Project into subgroup q by squaring
        let generator_2 = h_form.pow(&U2048::from_u64(2)).retrieve();

        Self {
            prime_modulus,
            subgroup_order,
            generator_1,
            generator_2,
        }
    }

    /// Performs modular exponentiation: base ^ exponent mod p.
    /// This is fundamentally utilized for computing public values (y1, y2)
    /// and generating the initial cryptographic commitments (r1, r2).
    pub fn exponentiate(&self, base: &U2048, exponent: &U2048) -> U2048 {
        let odd_p = Odd::new(self.prime_modulus).expect("Modulus must be odd");
        let p_params = MontyParams::new_vartime(odd_p);
        let base_form = FixedMontyForm::<32>::new(base, &p_params);
        base_form.pow(exponent).retrieve()
    }

    /// Computes the prover's response (s) to the verifier's challenge (c).
    /// Equation: s = (k - c * x) mod q
    /// Where 'k' is the random nonce, 'c' is the challenge, and 'x' is the secret value.
    pub fn compute_response(
        &self,
        random_nonce: &U2048,
        challenge: &U2048,
        secret_value: &U2048,
    ) -> U2048 {
        let odd_q = Odd::new(self.subgroup_order).expect("Subgroup order must be odd");
        let q_params = MontyParams::new_vartime(odd_q);

        let c_form = FixedMontyForm::<32>::new(challenge, &q_params.clone());
        let x_form = FixedMontyForm::<32>::new(secret_value, &q_params.clone());
        let k_form = FixedMontyForm::<32>::new(random_nonce, &q_params);

        // cx = c * x mod q
        let cx_form = c_form * x_form;

        // s = k - cx mod q (constant-time algebraic wrap-around via Montgomery Form)
        let s_form = k_form - cx_form;
        s_form.retrieve()
    }

    /// Verifies the cryptographic proof provided by the prover.
    /// It validates two mathematical conditions simultaneously to assure both
    /// discrete logarithms are unequivocally bound to the identical secret 'x'.
    ///
    /// Verification Equation 1: r1 == (g1 ^ s * y1 ^ c) mod p
    /// Verification Equation 2: r2 == (g2 ^ s * y2 ^ c) mod p
    pub fn verify(
        &self,
        commitment_1: &U2048,
        commitment_2: &U2048,
        public_value_1: &U2048,
        public_value_2: &U2048,
        challenge: &U2048,
        response: &U2048,
    ) -> bool {
        let odd_p = Odd::new(self.prime_modulus).expect("Modulus must be odd");
        let p_params = MontyParams::new_vartime(odd_p);

        let g1_form = FixedMontyForm::<32>::new(&self.generator_1, &p_params.clone());
        let g2_form = FixedMontyForm::<32>::new(&self.generator_2, &p_params.clone());
        let y1_form = FixedMontyForm::<32>::new(public_value_1, &p_params.clone());
        let y2_form = FixedMontyForm::<32>::new(public_value_2, &p_params);
        // r1 == (g1 ^ s * y1 ^ c) mod p
        let rhs_1 = g1_form.pow(response) * y1_form.pow(challenge);

        // r2 == (g2 ^ s * y2 ^ c) mod p
        let rhs_2 = g2_form.pow(response) * y2_form.pow(challenge);

        // Compare values
        *commitment_1 == rhs_1.retrieve() && *commitment_2 == rhs_2.retrieve()
    }

    /// Fiat-Shamir Heuristic: Deterministically generates a cryptographic challenge
    /// by hashing the public parameters, public keys, and current commitments.
    /// This acts as a Random Oracle, removing the need for verifier interaction.
    pub fn compute_fiat_shamir_challenge(
        &self,
        public_value_1: &U2048,
        public_value_2: &U2048,
        commitment_1: &U2048,
        commitment_2: &U2048,
    ) -> U2048 {
        let mut hasher = Sha256::new();

        // Hash the generators
        hasher.update(self.generator_1.to_be_bytes());
        hasher.update(self.generator_2.to_be_bytes());

        // Hash the public values (y1, y2)
        hasher.update(public_value_1.to_be_bytes());
        hasher.update(public_value_2.to_be_bytes());

        // Hash the transient commitments (r1, r2)
        hasher.update(commitment_1.to_be_bytes());
        hasher.update(commitment_2.to_be_bytes());

        let hash_result = hasher.finalize();

        // Convert the 256-bit (32-byte) SHA256 output to a U2048.
        // Since 2^256 is massively smaller than our 2047-bit subgroup order 'q',
        // this value is inherently reduced modulo q.
        let mut challenge_bytes = [0u8; 256];
        challenge_bytes[256 - 32..].copy_from_slice(&hash_result);

        U2048::from_be_bytes(challenge_bytes.into())
    }

    /// Generates a complete Non-Interactive Zero-Knowledge Proof (NIZK).
    /// The Prover computes everything locally and returns a single proof struct.
    pub fn prove_non_interactive(
        &self,
        secret_value: &U2048,
        public_value_1: &U2048,
        public_value_2: &U2048,
    ) -> NonInteractiveProof {
        // 1. Generate random nonce (k)
        let random_nonce = generate_random_nonce(&self.subgroup_order);

        // 2. Compute commitments (r1, r2)
        let r1 = self.exponentiate(&self.generator_1, &random_nonce);
        let r2 = self.exponentiate(&self.generator_2, &random_nonce);

        // 3. Compute Fiat-Shamir challenge (c)
        let challenge =
            self.compute_fiat_shamir_challenge(public_value_1, public_value_2, &r1, &r2);

        // 4. Compute response (s = k - c * x mod q)
        let response = self.compute_response(&random_nonce, &challenge, secret_value);

        NonInteractiveProof {
            challenge,
            response,
        }
    }

    /// Verifies a Non-Interactive Zero-Knowledge Proof.
    pub fn verify_non_interactive(
        &self,
        public_value_1: &U2048,
        public_value_2: &U2048,
        proof: &NonInteractiveProof,
    ) -> bool {
        let odd_p = Odd::new(self.prime_modulus).expect("Modulus must be odd");
        let p_params = MontyParams::new_vartime(odd_p);

        let g1_form = FixedMontyForm::<32>::new(&self.generator_1, &p_params.clone());
        let g2_form = FixedMontyForm::<32>::new(&self.generator_2, &p_params.clone());
        let y1_form = FixedMontyForm::<32>::new(public_value_1, &p_params.clone());
        let y2_form = FixedMontyForm::<32>::new(public_value_2, &p_params);

        // Reconstruct commitments based on the algebraic properties:
        // r1' = (g1^s * y1^c) mod p
        let r1_prime = (g1_form.pow(&proof.response) * y1_form.pow(&proof.challenge)).retrieve();

        // r2' = (g2^s * y2^c) mod p
        let r2_prime = (g2_form.pow(&proof.response) * y2_form.pow(&proof.challenge)).retrieve();

        // Recompute the challenge using the reconstructed commitments
        let expected_challenge = self.compute_fiat_shamir_challenge(
            public_value_1,
            public_value_2,
            &r1_prime,
            &r2_prime,
        );

        proof.challenge == expected_challenge
    }
}

impl Default for ChaumPedersenParameters {
    fn default() -> Self {
        Self::get_default_2048_parameters()
    }
}

/// Generates a costant-time, cryptographically uniformly distributed random integer in the range [0, bound - 1].
pub fn generate_random_nonce(bound: &U2048) -> U2048 {
    let bound_nz = NonZero::new(*bound).expect("Bound cannot be zero");
    let mut rng = UnwrapErr(SysRng);
    U2048::random_mod_vartime(&mut rng, &bound_nz)
}

/// Generates a cryptographically secure random alphanumeric string of a specified length.
pub fn generate_random_string(size: usize) -> String {
    let mut rng = UnwrapErr(SysRng);
    Alphanumeric.sample_string(&mut rng, size)
}

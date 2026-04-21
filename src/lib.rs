use num_bigint::{BigUint, RandBigInt};

/// Public parameters for the Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol.
/// This protocol proves the equality of discrete logarithms: log_g1(y1) == log_g2(y2) == x,
/// without revealing the underlying secret value 'x'.
/// It operates within a prime-order subgroup of the multiplicative group Z_p^*.
#[derive(Debug)]
pub struct ChaumPedersenParameters {
    /// The large prime modulus (p) defining the finite field Z_p.
    pub prime_modulus: BigUint,
    /// The prime order (q) of the cyclic subgroup.
    pub subgroup_order: BigUint,
    /// The first generator (g1) of the subgroup.
    pub generator_1: BigUint,
    /// The second generator (g2) of the subgroup.
    pub generator_2: BigUint,
}

impl ChaumPedersenParameters {
    /// Returns the standard RFC 3526 2048-bit MODP parameters (Group 14).
    /// These parameters are safe primes where p = 2q + 1, widely used in secure communications.
    pub fn get_default_2048_parameters() -> Self {
        let p_hex = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
        let prime_modulus = BigUint::parse_bytes(p_hex, 16).unwrap();

        let subgroup_order = (&prime_modulus - BigUint::from(1u32)) / BigUint::from(2u32);
        let generator_1 = BigUint::from(2u32);
        let generator_2 = generator_1.modpow(&BigUint::from(2u32), &prime_modulus);

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
    pub fn exponentiate(&self, base: &BigUint, exponent: &BigUint) -> BigUint {
        base.modpow(exponent, &self.prime_modulus)
    }

    /// Computes the prover's response (s) to the verifier's challenge (c).
    /// Equation: s = (k - c * x) mod q
    /// Where 'k' is the random nonce, 'c' is the challenge, and 'x' is the secret value.
    /// Note: All arithmetic operations for the response phase are performed modulo 'q' (the subgroup order).
    pub fn compute_response(
        &self,
        random_nonce: &BigUint,
        challenge: &BigUint,
        secret_value: &BigUint,
    ) -> BigUint {
        // Calculate (c * x) mod q
        let cx = (challenge * secret_value) % &self.subgroup_order;

        // Calculate k mod q to ensure the nonce strictly falls within the subgroup boundaries
        let nonce_mod = random_nonce % &self.subgroup_order;

        // Perform safe modular subtraction: (k - cx) mod q
        // If k >= cx, standard subtraction is geometrically sufficient.
        // Otherwise, we add 'q' to avoid negative numbers and ensure correct algebraic wrap-around.
        if nonce_mod >= cx {
            nonce_mod - cx
        } else {
            &self.subgroup_order + nonce_mod - cx
        }
    }

    /// Verifies the cryptographic proof provided by the prover.
    /// It validates two mathematical conditions simultaneously to assure both
    /// discrete logarithms are unequivocally bound to the identical secret 'x'.
    ///
    /// Verification Equation 1: r1 == (g1 ^ s * y1 ^ c) mod p
    /// Verification Equation 2: r2 == (g2 ^ s * y2 ^ c) mod p
    pub fn verify(
        &self,
        commitment_1: &BigUint,
        commitment_2: &BigUint,
        public_value_1: &BigUint,
        public_value_2: &BigUint,
        challenge: &BigUint,
        response: &BigUint,
    ) -> bool {
        // Evaluate the right-hand side (RHS) of the first verification equation
        let rhs_1 = (self.generator_1.modpow(response, &self.prime_modulus)
            * public_value_1.modpow(challenge, &self.prime_modulus))
            % &self.prime_modulus;

        // Evaluate the right-hand side (RHS) of the second verification equation
        let rhs_2 = (self.generator_2.modpow(response, &self.prime_modulus)
            * public_value_2.modpow(challenge, &self.prime_modulus))
            % &self.prime_modulus;

        // Both derived constraints must perfectly equate to the initial commitments
        *commitment_1 == rhs_1 && *commitment_2 == rhs_2
    }
}

impl Default for ChaumPedersenParameters {
    fn default() -> Self {
        Self::get_default_2048_parameters()
    }
}

/// Generates a cryptographically uniformly distributed random integer in the range [0, bound - 1].
/// Extensively used for generating the secret (x), the random blinding factor/nonce (k),
/// and the challenge (c) in non-interactive variants.
pub fn generate_random_nonce(bound: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint_below(bound)
}

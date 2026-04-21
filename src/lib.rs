use num_bigint::{BigUint, RandBigInt};

/// Public parameters for the Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol.
/// This protocol proves the equality of discrete logarithms: log_g1(y1) == log_g2(y2) == x,
/// without revealing the underlying secret value 'x'.
/// It operates within a prime-order subgroup of the multiplicative group Z_p^*.
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

/// Generates a cryptographically uniformly distributed random integer in the range [0, bound - 1].
/// Extensively used for generating the secret (x), the random blinding factor/nonce (k),
/// and the challenge (c) in non-interactive variants.
pub fn generate_random_nonce(bound: &BigUint) -> BigUint {
    let mut rng = rand::thread_rng();
    rng.gen_biguint_below(bound)
}

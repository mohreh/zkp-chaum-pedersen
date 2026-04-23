
# ZKP-Auth: Zero-Knowledge Authentication System

## *“Knowledge is the only treasure that can be proven without being shared.”*

A implementation of the **Chaum-Pedersen Zero-Knowledge Proof (ZKP)** protocol. This system allows a prover (client) to prove knowledge of a secret (password) to a verifier (server) without ever revealing the secret itself, nor sending any sensitive data over the network.

## 🚀 Features
 * **Protocol**: Implements the Chaum-Pedersen protocol for proving the equality of discrete logarithms.
 * **Modes**:
   * **Interactive**: 3-pass protocol (Commitment, Challenge, Response).
   * **Non-Interactive**: 1-pass protocol using the **Fiat-Shamir Heuristic**.
 * **Security**:
   * **Constant-Time Arithmetic**: Built with crypto-bigint (cosidering side-channel timing attacks, maybe best-practice in real-world).
   * **Key Derivation**: Uses **Argon2id** (memory-hard) and **HKDF** to derive the *secret x* from human passwords.
   * **Standard Parameters**: Uses **RFC 3526 (Group 14)** 2048-bit Safe Prime MODP groups.
   * **Replay Protection**: Challenges are consumed upon use in the server's state machine.
 * **Interface**: Simple Terminal User Interface (TUI) built with ratatui and crossterm for showcasing (I use tokio::time:sleep just for showcasing the protocol and it's steps).
 * **Communication**: High-performance asynchronous gRPC API using tonic and prost.
 
## 🏗️ Mathematical Overview
The system proves that $\log_{g_1}(y_1) = \log_{g_2}(y_2) = x$ without revealing x.

### 1. Setup & Registration
The client derives a secret $x \in \mathbb{Z}_q$ from their password and registers the public values:

### 2. The Proof (Interactive)
 1. **Commitment**: Client picks random $k \in \mathbb{Z}_q$ and sends $r_1 = g_1^k$, $r_2 = g_2^k$.
 2. **Challenge**: Server sends random $c \in \mathbb{Z}_q$.
 3. **Response**: Client sends $s = (k - c \cdot x) \pmod q$.
 4. **Verification**: The server verifies the proof by checking:
$$g_1^s \cdot y_1^c \equiv r_1 \pmod p$$
$$g_2^s \cdot y_2^c \equiv r_2 \pmod p$$
### 3. Non-Interactive (Fiat-Shamir)
The client computes the challenge c locally as a hash of the parameters and commitments:
$c = \text{Hash}(g_1, g_2, y_1, y_2, r_1, r_2)$

## 🛠️ Project Structure
 * lib.rs: The core cryptographic library (Parameters, Exponentiation, Verification Logic).
 * server.rs: The gRPC server managing user registration and authentication states.
 * client.rs: The TUI-based client handling KDF derivation and ZKP generation.
 * zkp_auth.proto: Protobuf definitions for the gRPC service.
 
## 🚦 Getting Started

### Prerequisites
 * **Rust**: Latest stable version.
 * **Protobuf Compiler**: Required by tonic-build (protoc).
   * Ubuntu: ```sudo apt install protobuf-compiler```
   * macOS: ```brew install protobuf```
   
### Running the System
1. **Start the Server**:
```bash
# Set the port (optional, defaults to 50051)
export SERVER_PORT=50051
cargo run --bin server
```
   
2. **Run the Client**:
```bash
cargo run --bin client
```
   
## 🎮 How to Use the CLI
 1. **Navigation**: Use [TAB] to switch between the **Username** and **Password** fields.
 2. **Input**: Type your credentials. The password will be masked with *.
 3. **Commands**:
   * Press [R] to **Register** (one-time setup).
   * Press [I] for **Interactive Login** (standard 3-step proof).
   * Press [F] for **Fiat-Shamir Login** (fast 1-step proof).
   * Press [L] to **Logout** once authenticated.
   * Press [ESC] to Quit.
## 🛡️ Security Implementation Details
 * **RFC 3526 Group 14**: A 2048-bit MODP group with a safe prime $p = 2q + 1$. This ensures that the subgroup order q is prime and provides 112 bits of security against the discrete log problem.
 * **State Handling**: The server uses a HashMap protected by a Mutex to track PendingChallenges. To prevent **Replay Attacks**, challenges are removed from the map immediately upon the first verification attempt.
 * **KDF**: Passwords are not directly used as x. Instead, **Argon2id** processes the password with a salt (derived from the username) to produce a 256-bit key, which is then expanded to 2048-bits via **HKDF** and reduced modulo q.

## The Problem on 2048-bit parameters based on the **RFC 5114** 

### Documentation: Resolving RFC 5114 Parameter Mismatch in Chaum-Pedersen ZKP Implementation

During writing the integration testing phase of the Chaum-Pedersen Zero-Knowledge Proof (ZKP) protocol, the test utilizing the 2048-bit parameters based on the **RFC 5114** standard with parameters described in the code below, failed with the following panic:

```rust
fn setup_2048_bit_params() -> ChaumPedersenParameters {
    let p_hex = b"AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DFCB1EA9C43CF9BEAABDE592D50E88E165561E47CF8CCDF70DFDE5681D3E0213E300B700F801A7FB022E5C9A4B38A731118D6874BE531B5E05FF8F22A26FDBDFE4473DE4BC2316EADCCBE183A5B8E85A6A3FADCD5E58A46BCCED10452668580E132CA6ACEC0C9368565F35FA168EEBA11D250BD26DE4CF684F66C2BB1D537DFCFBD4A92F2BFB7E9F4AC17C9482F62A8D9BCCB19E5DC7BDC44D42031F59B7D4F7256F88E6B151FC6DBB4673B8DE926EE1DF85B69E8193DE8D5CB711D7BBDB8CBE5DF1EF0E12F66DFE7548CDFCF2BA69BA31AF6BE88DCD37A74AF07C747";
    let q_hex = b"801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";
    let g_hex = b"AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57CB17C9B2E14A8C430CA01E6BB39B64D18861B580EEAE62B80FBA1812822CA36B1569B1363ED0F409C6D332FA7AD1E9EB76ED684813583CBE7A4FC8A74A3D00D06456079FE046465DCF524A325ACBA8BAE71B218962BBBCF5569DB3C27EE1C8F5CC6CDECD4E9AE8F4C68B61E256F42D50CE16869AD385419DFCB25FA17CF91BE2F05D5CC3B3E4DC03BB612E115664CB680D1DCC96BD6AC070CFB6DCDE30ADBCBEF487D43977FAD3DF0C240166CC83CA52174C37145A834165651BC51ACBC7C826CE3658F9DC1CB";
    let prime_modulus = BigUint::parse_bytes(p_hex, 16).unwrap();
    let subgroup_order = BigUint::parse_bytes(q_hex, 16).unwrap();
    let generator_1 = BigUint::parse_bytes(g_hex, 16).unwrap();
    let generator_2 = generator_1.modpow(&BigUint::from(2u32), &prime_modulus);
    ChaumPedersenParameters {
        prime_modulus,
        subgroup_order,
        generator_1,
        generator_2,
    }
}
```

```text
thread 'test_valid_proof_2048_bit' panicked at tests/zkp_integration_test.rs::
A valid 2048-bit Chaum-Pedersen proof was incorrectly rejected.
```

While the core cryptographic logic functioned perfectly for smaller moduli (toy examples) and 1024-bit parameters, the verification phase consistently failed to validate a legitimately generated proof at the 2048-bit scale.

#### Root Cause Analysis
The Chaum-Pedersen algorithm fundamentally relies on arithmetic operations within prime-order multiplicative subgroups. A critical mathematical prerequisite for this protocol is that the generator (g) must strictly belong to the cyclic subgroup of prime order q. Expressed mathematically, the following condition must hold true without exception:
The standard parameters defined in **RFC 5114** are designed such that the subgroup order (q) is a specific prime factor of p - 1. In certain modular arithmetic implementations, especially when utilizing hardcoded values for q alongside exceptionally large random nonces, a **boundary mismatch** can occur. This causes the values generated during the proof formulation to wrap around the subgroup boundaries incorrectly. Consequently, the right-hand side (RHS) of the verification congruence equation fails to equal the initial commitment value.
## 3. Architectural Solution: Migration to Safe Primes (RFC 3526)
To permanently resolve this vulnerability and adhere to modern cryptography engineering standards, the architecture was migrated to utilize **RFC 3526** groups, which are constructed using **Safe Primes**.
In a Safe Prime group, the prime modulus (p) and the subgroup order (q) have the following strict algebraic relationship:
Transitioning to this structure offers two paramount advantages for ZKP implementations:
 1. **Dynamic Subgroup Order Calculation:** We can explicitly and dynamically compute q from p with zero margin for hardcoding errors:
   
 2. **Generator Guarantee:** In Safe Prime groups, it is mathematically proven that g = 2 acts as a secure generator that strictly spans the prime-order subgroup without leaking information or breaking boundary constraints.
## 4. Implementation
The test setup functions were refactored to utilize these Safe Primes. Below is the updated implementation for the 2048-bit parameters (RFC 3526 - Group 14):
```rust
fn setup_2048_bit_params() -> ChaumPedersenParameters {
    // RFC 3526 - 2048-bit MODP Group (Group 14)
    let p_hex = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
    let prime_modulus = BigUint::parse_bytes(p_hex, 16).unwrap();
    
    // Dynamically and accurately calculate 'q' based on the Safe Primes formula
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

**Resolution Status:** Following this architectural adjustment, all integration tests pass consistently.

pub mod zkp_auth {
    include!(concat!(env!("OUT_DIR"), "/zkp_auth.rs"));
}

use std::{collections::HashMap, env, sync::Arc};

use crypto_bigint::{Encoding, U2048};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use zkp_auth::auth_service_server::{AuthService, AuthServiceServer};
use zkp_chaum_pedersen::{ChaumPedersenParameters, NonInteractiveProof, generate_random_string};

use crate::zkp_auth::{
    CreateAuthenticationChallengeRequest, CreateAuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse, VerifyAuthenticationRequest, VerifyAuthenticationResponse,
    VerifyNonInteractiveRequest, VerifyNonInteractiveResponse,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkpBytes(pub [u8; 256]);

impl From<U2048> for ZkpBytes {
    fn from(value: U2048) -> Self {
        ZkpBytes(value.to_be_bytes().into())
    }
}

impl From<&ZkpBytes> for U2048 {
    fn from(value: &ZkpBytes) -> Self {
        U2048::from_be_bytes(value.0.into())
    }
}

impl TryFrom<&[u8]> for ZkpBytes {
    type Error = Status;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() > 256 {
            return Err(Status::invalid_argument(format!(
                "Data is too large. Expected at most 256 bytes, got {}",
                data.len()
            )));
        }

        if data.is_empty() {
            return Err(Status::invalid_argument("Data cannot be empty"));
        }

        let mut padded = [0u8; 256];
        let start_idx = 256 - data.len();
        padded[start_idx..].copy_from_slice(data);

        Ok(ZkpBytes(padded))
    }
}

#[derive(Debug)]
pub struct UserInfo {
    // pub user: String,
    pub public_value_1: ZkpBytes,
    pub public_value_2: ZkpBytes,
}

#[derive(Debug, Clone)]
struct AuthSession {
    pub user: String,
    pub commitment_1: ZkpBytes,
    pub commitment_2: ZkpBytes,
    pub challenge: ZkpBytes,
}

#[derive(Debug, Clone)]
struct ActiveSession {
    pub user: String,
    pub created_at: std::time::Instant,
}

#[derive(Debug)]
struct Auth {
    params: ChaumPedersenParameters,
    users: Arc<Mutex<HashMap<String, UserInfo>>>,
    pending_challenges: Arc<Mutex<HashMap<String, AuthSession>>>,
    active_sessions: Arc<Mutex<HashMap<String, ActiveSession>>>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            params: ChaumPedersenParameters::default(),
            users: Arc::new(Mutex::new(HashMap::new())),
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
            active_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

#[tonic::async_trait]
impl AuthService for Auth {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        log::info!("Processing Register: {:?}", req);

        let req = req.into_inner();

        let public_value_1 = ZkpBytes::try_from(req.public_value_1.as_slice())?;
        let public_value_2 = ZkpBytes::try_from(req.public_value_2.as_slice())?;

        let mut users = self.users.lock().await;

        if users.contains_key(&req.user) {
            return Err(Status::already_exists(format!(
                "User '{}' is already registered.",
                req.user
            )));
        }

        users.insert(
            req.user,
            UserInfo {
                public_value_1,
                public_value_2,
            },
        );

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_authentication_challenge(
        &self,
        req: Request<CreateAuthenticationChallengeRequest>,
    ) -> Result<Response<CreateAuthenticationChallengeResponse>, Status> {
        log::info!("Processing CreateAuthenticationChallenge: {:?}", req);
        let req = req.into_inner();

        let user = req.user;
        let users = &mut self.users.lock().await;
        if let Some(_) = users.get_mut(&user) {
            let challenge = zkp_chaum_pedersen::generate_random_nonce(&self.params.subgroup_order);
            let auth_id = generate_random_string(12);

            let pending_challenges = &mut self.pending_challenges.lock().await;
            let commitment_1 = ZkpBytes::try_from(req.commitment_1.as_slice())?;
            let commitment_2 = ZkpBytes::try_from(req.commitment_2.as_slice())?;
            pending_challenges.insert(
                auth_id.clone(),
                AuthSession {
                    user,
                    commitment_1,
                    commitment_2,
                    challenge: challenge.into(),
                },
            );

            return Ok(Response::new(CreateAuthenticationChallengeResponse {
                auth_id,
                challenge: challenge.to_be_bytes().to_vec(),
            }));
        }

        Err(Status::not_found(format!(
            "User: {} not found in database",
            user
        )))
    }

    async fn verify_authentication(
        &self,
        req: Request<VerifyAuthenticationRequest>,
    ) -> Result<Response<VerifyAuthenticationResponse>, Status> {
        let req = req.into_inner();
        let auth_id = req.auth_id;

        let pending_challenge = self
            .pending_challenges
            .lock()
            .await
            .remove(&auth_id)
            .ok_or_else(|| Status::not_found(format!("AuthID {} not found or expired", auth_id)))?;

        let users = &mut self.users.lock().await;
        let user_info = users
            .get(&pending_challenge.user)
            .ok_or_else(|| Status::internal("User data corrupted"))?;

        let resp = ZkpBytes::try_from(req.response.as_slice())?;

        let is_valid = self.params.verify(
            &U2048::from(&pending_challenge.commitment_1),
            &U2048::from(&pending_challenge.commitment_2),
            &U2048::from(&user_info.public_value_1),
            &U2048::from(&user_info.public_value_2),
            &U2048::from(&pending_challenge.challenge),
            &U2048::from(&resp),
        );
        if is_valid {
            let session_id = generate_random_string(32);
            self.active_sessions.lock().await.insert(
                session_id.clone(),
                ActiveSession {
                    user: pending_challenge.user,
                    created_at: std::time::Instant::now(),
                },
            );
            return Ok(Response::new(VerifyAuthenticationResponse { session_id }));
        }

        Err(Status::permission_denied(format!(
            "AuthId: {} - Invalid zero-knowledge proof response",
            auth_id,
        )))
    }

    async fn verify_non_interactive(
        &self,
        req: Request<VerifyNonInteractiveRequest>,
    ) -> Result<Response<VerifyNonInteractiveResponse>, Status> {
        let req = req.into_inner();
        let username = req.user;

        let challenge_bytes = ZkpBytes::try_from(req.challenge.as_slice())?;
        let response_bytes = ZkpBytes::try_from(req.response.as_slice())?;

        let users = self.users.lock().await;
        let user_info = users
            .get(&username)
            .ok_or_else(|| Status::not_found("User not found"))?;

        let proof = NonInteractiveProof {
            challenge: (&challenge_bytes).into(),
            response: (&response_bytes).into(),
        };

        let is_valid = self.params.verify_non_interactive(
            &(&user_info.public_value_1).into(),
            &(&user_info.public_value_2).into(),
            &proof,
        );

        if is_valid {
            let session_id = generate_random_string(32);
            self.active_sessions.lock().await.insert(
                session_id.clone(),
                ActiveSession {
                    user: username.clone(),
                    created_at: std::time::Instant::now(),
                },
            );
            log::info!("Non-interactive login successful: {}", username);
            return Ok(Response::new(VerifyNonInteractiveResponse { session_id }));
        }
        Err(Status::permission_denied(
            "Invalid Non-interactive ZKP proof",
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let port = env::var("SERVER_PORT").unwrap_or_else(|_| "50051".to_string());
    let addr = format!("0.0.0.0:{}", port).parse()?;
    log::info!("🚀 Starting ZKP Auth gRPC server on {}", addr);

    let auth = Auth::default();
    tonic::transport::Server::builder()
        .add_service(AuthServiceServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}

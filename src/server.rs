pub mod zkp_auth {
    include!(concat!(env!("OUT_DIR"), "/zkp_auth.rs"));
}

use std::{collections::HashMap, env, sync::Arc};

use crypto_bigint::{Encoding, U2048};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use zkp_auth::auth_service_server::{AuthService, AuthServiceServer};
use zkp_chaum_pedersen::{ChaumPedersenParameters, generate_random_string};

use crate::zkp_auth::{
    CreateAuthenticationChallengeRequest, CreateAuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse, VerifyAuthenticationRequest, VerifyAuthenticationResponse,
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
    pub session_id: String,
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
        let user = req.user;
        let public_value_1 = ZkpBytes::try_from(req.public_value_1.as_slice())?;
        let public_value_2 = ZkpBytes::try_from(req.public_value_2.as_slice())?;

        let users = &mut self.users.lock().await;
        users.insert(
            user,
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

        let pending_challenges = self.pending_challenges.lock().await;
        if let Some(pending_challenge) = pending_challenges.get(&auth_id) {
            let users = &mut self.users.lock().await;
            if let Some(user_info) = users.get(&pending_challenge.user) {
                let resp = ZkpBytes::try_from(req.response.as_slice())?;

                let is_valid = self.params.verify(
                    &U2048::from(&pending_challenge.commitment_1),
                    &U2048::from(&pending_challenge.commitment_2),
                    &U2048::from(&user_info.public_value_1),
                    &U2048::from(&user_info.public_value_2),
                    &U2048::from(&pending_challenge.challenge),
                    &U2048::from(&resp),
                );

                match is_valid {
                    true => {
                        let session_id = generate_random_string(12);
                        let mut active_sessions = self.active_sessions.lock().await;
                        active_sessions.insert(
                            pending_challenge.user.clone(),
                            ActiveSession {
                                session_id: session_id.clone(),
                            },
                        );

                        return Ok(Response::new(VerifyAuthenticationResponse { session_id }));
                    }
                    false => {
                        return Err(Status::permission_denied(format!(
                            "AuthId: {} - Invalid zero-knowledge proof response",
                            auth_id,
                        )));
                    }
                }
            } else {
                return Err(Status::not_found(format!(
                    "UserId: {} not found for AuthId: {} in database",
                    pending_challenge.user, auth_id
                )));
            }
        }

        Err(Status::not_found(format!(
            "AuthId: {} not found in database",
            auth_id
        )))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let port = env::var("PORT").unwrap_or_else(|_| "50051".to_string());
    let addr = format!("0.0.0.0:{}", port).parse()?;
    log::info!("🚀 Starting ZKP Auth gRPC server on {}", addr);

    let auth = Auth::default();
    tonic::transport::Server::builder()
        .add_service(AuthServiceServer::new(auth))
        .serve(addr)
        .await?;

    Ok(())
}

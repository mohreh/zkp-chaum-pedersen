pub mod zkp_auth {
    include!(concat!(env!("OUT_DIR"), "/zkp_auth.rs"));
}

use num_bigint::BigUint;
use tokio::sync::Mutex;
use tonic::{Request, Response, Status};
use zkp_auth::auth_service_server::{AuthService, AuthServiceServer};
use zkp_chaum_pedersen::ChaumPedersenParameters;

use crate::zkp_auth::{
    CreateAuthenticationChallengeRequest, CreateAuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse, VerifyAuthenticationRequest, VerifyAuthenticationResponse,
};

#[derive(Debug, Default)]
pub struct UserInfo {
    pub user: String,
    pub public_value_1: Vec<u8>,
    pub public_value_2: Vec<u8>,
}

#[derive(Debug, Clone)]
struct AuthSession {
    pub commitment_1: Vec<u8>,
    pub commitment_2: Vec<u8>,
    pub challenge: Vec<u8>,
}

#[derive(Debug, Clone)]
struct ActiveSession {
    user: String,
    session_id: String,
}

#[derive(Debug)]
struct Auth {
    params: ChaumPedersenParameters,
    users: Arc<Mutex<HashMap<String, UserInfo>>>,
    pending_challenges: Arc<Mutex<HashMap<String, AuthSession>>>,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            params: ChaumPedersenParameters::default(),
            users: Arc::new(Mutex::new(HashMap::new())),
            pending_challenges: Arc::new(Mutex::new(HashMap::new())),
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
        let public_value_1 = req.public_value_1;
        let public_value_2 = req.public_value_2;

        let user_info = UserInfo {
            user: user.clone(),
            public_value_1,
            public_value_2,
        };

        let users = &mut self.users.lock().await;
        users.insert(user, user_info);

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
            let auth_id = "asdkjfa".to_string();

            let pending_challenges = &mut self.pending_challenges.lock().await;
            pending_challenges.insert(
                auth_id.clone(),
                AuthSession {
                    commitment_1: req.commitment_1,
                    commitment_2: req.commitment_2,
                    challenge: challenge.to_bytes_be(),
                },
            );

            return Ok(Response::new(CreateAuthenticationChallengeResponse {
                auth_id,
                challenge: challenge.to_bytes_be(),
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
        todo!()
    }
}

use std::{collections::HashMap, env, sync::Arc};

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

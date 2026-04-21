pub mod zkp_auth {
    // مسیر به فایل تولید شده توسط tonic-build
    include!(concat!(env!("OUT_DIR"), "/zkp_auth.rs"));
}

use tonic::{Request, Response, Status};
use zkp_auth::auth_service_server::{AuthService, AuthServiceServer};

use crate::zkp_auth::{
    CreateAuthenticationChallengeRequest, CreateAuthenticationChallengeResponse, RegisterRequest,
    RegisterResponse, VerifyAuthenticationRequest, VerifyAuthenticationResponse,
};

#[derive(Debug, Default)]
struct Auth {}

#[tonic::async_trait]
impl AuthService for Auth {
    async fn register(
        &self,
        req: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        todo!()
    }

    async fn create_authentication_challenge(
        &self,
        req: Request<CreateAuthenticationChallengeRequest>,
    ) -> Result<Response<CreateAuthenticationChallengeResponse>, Status> {
        todo!()
    }

    async fn verify_authentication(
        &self,
        req: Request<VerifyAuthenticationRequest>,
    ) -> Result<Response<VerifyAuthenticationResponse>, Status> {
        todo!()
    }
}

use std::env;

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

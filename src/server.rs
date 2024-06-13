pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use std::{collections::HashMap, sync::Mutex};

use num_bigint::BigUint;
use tonic::{transport::Server, Code, Request, Response, Status};
use zkp_auth::{
    auth_server::{Auth, AuthServer},
    AuthAnswerRensponse, AuthAnswerRequest, AuthChallengeRequest, AuthChallengeResponse,
    RegisterRequest, RegisterResponse,
};
use zkp_chaum_pedersen::ZKP;

#[derive(Default)]
pub struct UserAuthInfo {
    // registration
    pub user_name: String,
    pub y1: BigUint,
    pub y2: BigUint,
    // authorization
    pub r1: BigUint,
    pub r2: BigUint,
    // verification
    pub c: BigUint,
    pub s: BigUint,
    pub session_id: String,
}

#[derive(Default)]
struct AuthImpl {
    pub user_info: Mutex<HashMap<String, UserAuthInfo>>,
    pub auth_user: Mutex<HashMap<String, String>>,
}

#[tonic::async_trait]
impl Auth for AuthImpl {
    async fn register(
        &self,
        request: Request<RegisterRequest>,
    ) -> Result<Response<RegisterResponse>, Status> {
        println!("[register] ...");

        let RegisterRequest { user, y1, y2 } = request.into_inner();
        let y1 = BigUint::from_bytes_be(&y1);
        let y2 = BigUint::from_bytes_be(&y2);

        let user_auth_info = UserAuthInfo {
            y1,
            y2,
            user_name: user.clone(),
            ..Default::default()
        };

        let user_info = &mut self.user_info.lock().unwrap();
        user_info.insert(user, user_auth_info);

        Ok(Response::new(RegisterResponse {}))
    }

    async fn create_auth_challenge(
        &self,
        request: Request<AuthChallengeRequest>,
    ) -> Result<Response<AuthChallengeResponse>, Status> {
        println!("[create_auth_challenge] ...");

        let AuthChallengeRequest { user, r1, r2 } = request.into_inner();

        let user_info = &mut self.user_info.lock().unwrap();
        if let Some(user_info) = user_info.get_mut(&user) {
            let zkp = ZKP::new();
            let c = ZKP::generate_random_below(&zkp.q);
            user_info.c.clone_from(&c);
            user_info.r1 = BigUint::from_bytes_be(&r1);
            user_info.r2 = BigUint::from_bytes_be(&r2);

            let auth_user = &mut self.auth_user.lock().unwrap();
            let auth_id = ZKP::generate_random_string(12);
            auth_user.insert(auth_id.clone(), user);
            Ok(Response::new(AuthChallengeResponse {
                auth_id,
                c: c.to_bytes_be(),
            }))
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("User {:?} not found", user),
            ))
        }
    }

    async fn verify_auth(
        &self,
        request: Request<AuthAnswerRequest>,
    ) -> std::result::Result<Response<AuthAnswerRensponse>, Status> {
        println!("[verify_auth]");
        let AuthAnswerRequest { auth_id, s } = request.into_inner();

        let auth_user = &mut self.auth_user.lock().unwrap();
        if let Some(user_name) = auth_user.get(&auth_id) {
            let user_info = &mut self.user_info.lock().unwrap();
            let user_info = user_info.get_mut(user_name).expect("auth_id not found");

            let zkp = ZKP::new();
            let verification = zkp.verify(
                &user_info.r1,
                &user_info.r2,
                &user_info.y1,
                &user_info.y2,
                &user_info.c,
                &BigUint::from_bytes_be(&s),
            );

            if verification {
                let session_id = ZKP::generate_random_string(12);
                Ok(Response::new(AuthAnswerRensponse { session_id }))
            } else {
                Err(Status::new(
                    Code::PermissionDenied,
                    format!("AuthId: {} send an invalid challenge answer", auth_id),
                ))
            }
        } else {
            Err(Status::new(
                Code::NotFound,
                format!("AuthId: {} not found", auth_id),
            ))
        }
    }
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:50051".to_string();
    println!("Running the server in {:?}", addr);

    let auth_impl = AuthImpl::default();

    Server::builder()
        .add_service(AuthServer::new(auth_impl))
        .serve(addr.parse().expect("could not convert address"))
        .await
        .unwrap();
}

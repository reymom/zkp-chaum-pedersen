pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use std::io::stdin;

use num_bigint::BigUint;
use zkp_auth::{auth_client::AuthClient, AuthAnswerRequest, AuthChallengeRequest, RegisterRequest};
use zkp_chaum_pedersen::ZKP;

#[tokio::main]
async fn main() {
    let mut client = AuthClient::connect("http://127.0.0.1:50051")
        .await
        .expect("could not connect to the client");
    println!("Connected to the server");

    let mut buf = String::new();
    println!("Provide a username: ");
    stdin()
        .read_line(&mut buf)
        .expect("could not read user name");
    let user = buf.trim().to_string();
    buf.clear();

    println!("Provide a password: ");
    stdin()
        .read_line(&mut buf)
        .expect("could not read password");
    let password = BigUint::from_bytes_be(buf.trim().as_bytes());
    buf.clear();

    let zkp = ZKP::new();
    let y1 = ZKP::exponentiate(&zkp.alpha, &password, &zkp.p);
    let y2 = ZKP::exponentiate(&zkp.beta, &password, &zkp.p);
    let request = RegisterRequest {
        user: user.clone(),
        y1: y1.to_bytes_be(),
        y2: y2.to_bytes_be(),
    };

    let _response = client
        .register(request)
        .await
        .expect("could not register response");
    println!("{:?}", _response);

    let k = ZKP::generate_random_below(&zkp.q);
    let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
    let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);
    let request = AuthChallengeRequest {
        user,
        r1: r1.to_bytes_be(),
        r2: r2.to_bytes_be(),
    };

    let response = client
        .create_auth_challenge(request)
        .await
        .expect("could not request challenge")
        .into_inner();
    println!("{:?}", _response);

    let s = zkp.solve(&k, &BigUint::from_bytes_be(&response.c), &password);
    let request = AuthAnswerRequest {
        auth_id: response.auth_id,
        s: s.to_bytes_be(),
    };
    let response = client
        .verify_auth(request)
        .await
        .expect("could not authenticate in server")
        .into_inner();
    println!("You logged in! session_id = {:?}", response.session_id)
}

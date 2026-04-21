pub mod zkp_auth {
    include!("./zkp_auth.rs");
}

use zkp_auth::auth_service_server;

fn main() {
    println!("Hi, I am the server");
}

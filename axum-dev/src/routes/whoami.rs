use std::net::SocketAddr;

use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Extension, Router,
};

use crate::{
    middleware::{AuthenticatedUser, ClientIp},
    AppState,
};

pub fn router() -> Router<AppState> {
    // this router is responsible for everything under `/hello`
    Router::<AppState>::new().route("/", get(whoami_default))
}

async fn whoami_default(
    user: Option<Extension<AuthenticatedUser>>,
    client_ip: Option<Extension<ClientIp>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let email = match user {
        Some(Extension(AuthenticatedUser(email))) => email,
        None => "<unauthenticated>".to_string(),
    };

    let peer_ip = peer.ip();
    let client_ip = client_ip
        .map(|Extension(ClientIp(ip))| ip)
        .unwrap_or(peer_ip);

    let mut hdr_lines = String::new();
    for (name, value) in headers.iter() {
        let val_str = value.to_str().unwrap_or("<non-utf8>");
        hdr_lines.push_str(&format!("{name}: {val_str}\n"));
    }

    let body =
        format!("identity:\nuser={email}\npeer_ip={peer_ip}\nclient_ip={client_ip}\n\nheaders:\n{hdr_lines}");

    (StatusCode::OK, body)
}

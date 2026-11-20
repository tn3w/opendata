use crate::public;
use axum::{
    Json, Router, extract::Path, http::header::CACHE_CONTROL, response::IntoResponse,
    routing::get,
};
use listenfd::ListenFd;
use rdns::scan::lookup;
use serde_json::json;
use std::net::Ipv4Addr;
use tokio::{net::UnixListener, task::spawn_blocking};

pub async fn run() {
    let listener = ListenFd::from_env()
        .take_unix_listener(0)
        .ok()
        .flatten()
        .expect("systemd passes a unix socket");
    listener.set_nonblocking(true).unwrap();

    let routes = Router::new().route("/rdns/lookup/{address}", get(reverse));
    axum::serve(UnixListener::from_std(listener).unwrap(), routes)
        .await
        .unwrap();
}

async fn reverse(Path(address): Path<Ipv4Addr>) -> impl IntoResponse {
    let names = spawn_blocking(move || lookup(&public("rdns"), address))
        .await
        .unwrap();
    let lifetime = if names.is_empty() { 3600 } else { 86400 };
    let caching = [(CACHE_CONTROL, format!("public, max-age={lifetime}"))];
    (caching, Json(json!({ "ip": address, "ptr": names })))
}

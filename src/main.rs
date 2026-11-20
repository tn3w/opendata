mod api;
mod watch;

use std::{env, path::PathBuf, process::exit};
use tokio::runtime::Runtime;

fn public(dataset: &str) -> PathBuf {
    let root = env::var("OPENDATA_PUBLIC").unwrap_or_else(|_| "public".into());
    PathBuf::from(root).join(dataset)
}

fn main() {
    match env::args().nth(1).as_deref() {
        Some("api") => Runtime::new().unwrap().block_on(api::run()),
        Some("watch") => watch::run(),
        _ => {
            eprintln!("usage: opendata api|watch");
            exit(2);
        }
    }
}

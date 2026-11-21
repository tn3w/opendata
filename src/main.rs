mod api;
mod watch;

use std::{env, fs, path::PathBuf, process::exit};
use tokio::runtime::Runtime;

fn public(dataset: &str) -> PathBuf {
    let root = env::var("OPENDATA_PUBLIC").unwrap_or_else(|_| "public".into());
    PathBuf::from(root).join(dataset)
}

fn credential(name: &str) -> String {
    let directory = env::var("CREDENTIALS_DIRECTORY").unwrap_or_default();
    fs::read_to_string(PathBuf::from(directory).join(name))
        .unwrap_or_else(|error| panic!("{name} credential: {error}"))
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

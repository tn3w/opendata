use std::{env, net::Ipv4Addr, path::PathBuf, process::exit};

use rdns::scan;
use serde_json::json;
use tokio::runtime::Runtime;

fn usage() -> ! {
    eprintln!("usage: rdns scan <directory> | rdns lookup <directory> <ipv4>");
    exit(2);
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    match arguments.as_slice() {
        [command, directory] if command == "scan" => {
            Runtime::new()
                .unwrap()
                .block_on(scan::run(PathBuf::from(directory)));
        }
        [command, directory, address] if command == "lookup" => {
            let Ok(address) = address.parse::<Ipv4Addr>() else {
                usage();
            };
            let names = scan::lookup(&PathBuf::from(directory), address);
            println!("{}", json!({ "ip": address, "ptr": names }));
        }
        _ => usage(),
    }
}

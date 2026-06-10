use std::{env, net::TcpStream, process, time::Duration};

fn main() {
    let Some(addr) = env::args().nth(1) else {
        eprintln!("usage: static_rust_client HOST:PORT");
        process::exit(2);
    };

    match TcpStream::connect_timeout(
        &addr.parse().expect("valid socket address"),
        Duration::from_secs(3),
    ) {
        Ok(_) => println!("connect succeeds"),
        Err(e) => {
            println!("connect failed: {e}");
            process::exit(1);
        }
    }
}

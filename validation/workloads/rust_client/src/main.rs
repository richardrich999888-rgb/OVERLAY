use std::{env, io::Write, net::TcpStream, process, time::Duration};

fn main() {
    let Some(addr) = env::args().nth(1) else {
        eprintln!("usage: static_rust_client HOST:PORT PAYLOAD");
        process::exit(2);
    };
    let payload = env::args()
        .nth(2)
        .unwrap_or_else(|| "SYNTRIASS_PLAINTEXT_MARKER".to_string());
    match addr.parse() {
        Ok(sockaddr) => {
            match TcpStream::connect_timeout(&sockaddr, Duration::from_secs(3)) {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(payload.as_bytes()) {
                        println!("write failed: {e}");
                        process::exit(1);
                    }
                    println!("connect succeeds");
                }
                Err(e) => {
                    println!("connect failed: {e}");
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("invalid socket address: {e}");
            process::exit(2);
        }
    }
}

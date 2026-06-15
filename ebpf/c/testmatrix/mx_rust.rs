use std::net::TcpStream;
fn main(){
    let port: u16 = std::env::args().nth(1).unwrap().parse().unwrap();
    match TcpStream::connect(("127.0.0.1", port)) {
        Ok(_) => println!("MX rc=0 errno=0(ok)"),
        Err(e) => { let n=e.raw_os_error().unwrap_or(-1); println!("MX rc=-1 errno={n}({e})"); std::process::exit(n.max(1)); }
    }
}

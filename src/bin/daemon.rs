use serde::Serialize;
use std::env;
use syntriass_overlay::kernel_native::{self, KernelUpcall, DEFAULT_UPCALL_SOCKET};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Serialize)]
struct UpcallResponse<'a> {
    socket_id: u64,
    status: &'a str,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket_path =
        env::var("SYNTRIASS_UPCALL_SOCKET").unwrap_or_else(|_| DEFAULT_UPCALL_SOCKET.to_string());
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)?;
    eprintln!("syntriass daemon listening on {socket_path}");

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_stream(stream).await {
                eprintln!("syntriass daemon connection failed: {e}");
            }
        });
    }
}

async fn handle_stream(stream: UnixStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<KernelUpcall>(&line) {
        Ok(upcall) => match kernel_native::complete_kernel_upcall(&upcall) {
            Ok(()) => UpcallResponse {
                socket_id: upcall.socket_id,
                status: "ok",
                message: "kernel-native enforcement completed".to_string(),
            },
            Err(e) => UpcallResponse {
                socket_id: upcall.socket_id,
                status: "fail_closed",
                message: e.to_string(),
            },
        },
        Err(e) => UpcallResponse {
            socket_id: 0,
            status: "bad_request",
            message: e.to_string(),
        },
    };

    let mut stream = reader.into_inner();
    let mut body = serde_json::to_vec(&response)?;
    body.push(b'\n');
    stream.write_all(&body).await?;
    Ok(())
}

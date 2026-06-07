use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ml_dsa::{Keypair, MlDsa65, SigningKey as MlDsaSigningKey};

const SEED_LEN: usize = 32;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: syntriass-identity <ed25519-seed-hex> <mldsa65-seed-hex>");
        std::process::exit(2);
    }

    let ed_seed = match decode_hex_exact::<SEED_LEN>(&args[1]) {
        Ok(seed) => seed,
        Err(msg) => {
            eprintln!("invalid ed25519 seed: {msg}");
            std::process::exit(2);
        }
    };
    let ml_seed = match decode_hex_exact::<SEED_LEN>(&args[2]) {
        Ok(seed) => seed,
        Err(msg) => {
            eprintln!("invalid mldsa65 seed: {msg}");
            std::process::exit(2);
        }
    };

    let ed_key = Ed25519SigningKey::from_bytes(&ed_seed);
    let ml_seed = ml_dsa::Seed::try_from(&ml_seed[..]).expect("fixed seed length");
    let ml_key = MlDsaSigningKey::<MlDsa65>::from_seed(&ml_seed);

    println!("ed25519_public={}", hex(ed_key.verifying_key().as_bytes()));
    println!(
        "mldsa65_public={}",
        hex(ml_key.verifying_key().encode().as_slice())
    );
}

fn decode_hex_exact<const N: usize>(token: &str) -> Result<[u8; N], &'static str> {
    let compact: String = token.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    let hex = compact
        .strip_prefix("0x")
        .or_else(|| compact.strip_prefix("0X"))
        .unwrap_or(&compact);
    if hex.len() != N * 2 {
        return Err("wrong length");
    }
    let mut out = [0u8; N];
    for (idx, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or("non-hex digit")?;
        let low = hex_nibble(chunk[1]).ok_or("non-hex digit")?;
        out[idx] = (high << 4) | low;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

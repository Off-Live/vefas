use clap::Parser;
use hex::FromHex;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::convert::TryInto;

/// CLI
#[derive(Parser, Debug)]
#[command(name = "gen_rfc8448", about = "Generate TLS 1.3 key schedule JSON vectors (TLS_AES_128_GCM_SHA256)")]
struct Args {
    /// ECDH shared secret (hex)
    #[arg(long)]
    shared_secret: String,
    /// Transcript hash (SHA-256) as hex
    #[arg(long)]
    transcript_hash: String,
    /// Output file (JSON); if omitted, prints to stdout
    #[arg(long)]
    out: Option<String>,
}

#[derive(Serialize)]
struct VectorOut {
    shared_secret: String,
    transcript_hash: String,
    // raw secrets / PRKs
    early_secret: String,
    handshake_secret: String,
    master_secret: String,
    // traffic secrets (application)
    client_application_secret: String,
    server_application_secret: String,
    // keys / ivs (derived from application secrets)
    client_application_key: String,
    server_application_key: String,
    client_application_iv: String,
    server_application_iv: String,
    // resumption
    resumption_master_secret: String,
}

/// HKDF-Extract: returns PRK (HMAC(salt, ikm))
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    // RFC 5869 / TLS treatment: if salt is empty, use zeros of HashLen
    let salt_key: Vec<u8> = if salt.is_empty() {
        vec![0u8; Sha256::output_size()]
    } else {
        salt.to_vec()
    };

    // HMAC(salt_key, ikm)
    let mut mac = Hmac::<Sha256>::new_from_slice(&salt_key).expect("HMAC new_from_slice");
    mac.update(ikm);
    let prk = mac.finalize().into_bytes();
    prk.to_vec()
}

/// Build the "HKDF-Expand-Label" structure per RFC8446 §7.1 and perform expand using Hkdf::from_prk
fn hkdf_expand_label_from_prk(prk: &[u8], label: &str, context: &[u8], length: usize) -> Vec<u8> {
    // Build Hkdf label:
    // struct {
    //   uint16 length;
    //   opaque label<7..255>;   // "tls13 " + label
    //   opaque context<0..255>;
    // } HkdfLabel;
    let mut hkdf_label: Vec<u8> = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());

    // length (u16) big-endian
    hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());

    // full label = "tls13 " + label
    let full_label = format!("tls13 {}", label);
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());

    // context
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    // Use Hkdf::from_prk to expand
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("invalid PRK length for Hkdf::from_prk");
    let mut okm = vec![0u8; length];
    hk.expand(&hkdf_label, &mut okm).expect("hkdf expand failed");
    okm
}

fn main() {
    let args = Args::parse();

    // parse inputs
    let shared_secret = match Vec::from_hex(&args.shared_secret) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("shared_secret hex parse error: {}", e);
            std::process::exit(2);
        }
    };

    let transcript_hash = match Vec::from_hex(&args.transcript_hash) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("transcript_hash hex parse error: {}", e);
            std::process::exit(2);
        }
    };

    if transcript_hash.len() != 32 {
        eprintln!("transcript_hash must be 32 bytes (SHA-256)");
        std::process::exit(2);
    }

    // Hash("") used as context for "derived" label
    let empty_hash = Sha256::digest(&[]).to_vec();

    // early_secret = HKDF-Extract(0, 0)
    let early_prk = hkdf_extract(&[], &[]); // PRK bytes
    // derived = HKDF-Expand-Label(early_secret, "derived", Hash(""), 32)
    let derived = hkdf_expand_label_from_prk(&early_prk, "derived", &empty_hash, 32);

    // handshake_secret = HKDF-Extract(derived, shared_secret)
    let handshake_prk = hkdf_extract(&derived, &shared_secret);

    // derived2 = HKDF-Expand-Label(handshake_secret, "derived", Hash(""), 32)
    let derived2 = hkdf_expand_label_from_prk(&handshake_prk, "derived", &empty_hash, 32);

    // master_secret = HKDF-Extract(derived2, 0)
    let master_prk = hkdf_extract(&derived2, &[]);

    // application traffic secrets
    // c_ap = HKDF-Expand-Label(master_secret, "c ap traffic", TranscriptHash, 32)
    let c_ap = hkdf_expand_label_from_prk(&master_prk, "c ap traffic", &transcript_hash, 32);
    let s_ap = hkdf_expand_label_from_prk(&master_prk, "s ap traffic", &transcript_hash, 32);

    // derive traffic keys and ivs from the application secret (treat c_ap/s_ap as PRK for the sub-derives)
    let c_key = hkdf_expand_label_from_prk(&c_ap, "key", &[], 16);
    let s_key = hkdf_expand_label_from_prk(&s_ap, "key", &[], 16);

    let c_iv = hkdf_expand_label_from_prk(&c_ap, "iv", &[], 12);
    let s_iv = hkdf_expand_label_from_prk(&s_ap, "iv", &[], 12);

    // resumption master secret
    let res_master = hkdf_expand_label_from_prk(&master_prk, "res master", &transcript_hash, 32);

    // build output
    let out = VectorOut {
        shared_secret: args.shared_secret.clone(),
        transcript_hash: args.transcript_hash.clone(),
        early_secret: hex::encode(&early_prk),
        handshake_secret: hex::encode(&handshake_prk),
        master_secret: hex::encode(&master_prk),
        client_application_secret: hex::encode(&c_ap),
        server_application_secret: hex::encode(&s_ap),
        client_application_key: hex::encode(&c_key),
        server_application_key: hex::encode(&s_key),
        client_application_iv: hex::encode(&c_iv),
        server_application_iv: hex::encode(&s_iv),
        resumption_master_secret: hex::encode(&res_master),
    };

    let json = serde_json::to_string_pretty(&out).expect("serialize failed");
    if let Some(path) = args.out {
        std::fs::write(path, json).expect("write out file failed");
    } else {
        println!("{}", json);
    }
}

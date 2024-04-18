use std::{fs::File, path::Path};

mod types;

use base64::{engine::general_purpose, Engine};
use prio::codec::Encode;
use serde::Deserialize;
use types::HpkeConfig;

use crate::types::HpkeConfigId;

#[derive(Debug, Deserialize)]
struct JsonHpkeConfig {
    id: u8,
    kem_id: String,
    kdf_id: String,
    aead_id: String,
    public_key: String,
}

fn read_config(path: &Path) -> JsonHpkeConfig {
    let file = File::open(path).unwrap();
    serde_json::from_reader(file).expect("JSON was not well-formatted")
}

fn main() {
    let path = Path::new("collector_hpke_config.json");
    println!("Path: {:?}", path);
    let jsonconfig = read_config(path);
    println!("Config from JSON: {:?}", jsonconfig);
    let dapconfig = HpkeConfig {
        id: HpkeConfigId(jsonconfig.id),
        kem_id: match jsonconfig.kem_id.as_str() {
            "X25519HkdfSha256" => 0x20,
            _ => panic!("Unknown KEM: {}", jsonconfig.kem_id),
        },
        kdf_id: match jsonconfig.kdf_id.as_str() {
            "HkdfSha256" => 0x1,
            _ => panic!("Unknown KDF: {}", jsonconfig.kdf_id),
        },
        aead_id: match jsonconfig.aead_id.as_str() {
            "Aes128Gcm" => 0x1,
            _ => panic!("Unknown AEAD: {}", jsonconfig.aead_id),
        },
        public_key: general_purpose::URL_SAFE_NO_PAD.decode(jsonconfig.public_key).unwrap(),
    };
    println!("Config for DAP: {:?}", dapconfig);
    let bytes = dapconfig.get_encoded().expect("Failed to encode config.");
    println!("Bytes: {:?}", bytes);
    let b64 = general_purpose::URL_SAFE.encode(bytes);
    println!("b64: {}", b64);
}

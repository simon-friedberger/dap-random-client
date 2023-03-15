/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! This file implements a DAP client which will read task configurations from
//! a JSON file and generate random measurements for infrastructure testing.

use hpke::Deserializable;
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Kem as KemTrait, OpModeS, Serializable,
};
use prio::vdaf::{prio3::Prio3Aes128CountVec, Client};
use prio::{
    codec::{Decode, Encode},
    vdaf::prio3::Prio3Aes128Sum,
};
use rand::{thread_rng, Rng, SeedableRng};
use reqwest::StatusCode;
use serde::Deserialize;
use std::{
    error::Error,
    fs::File,
    io::{self, Write},
};
use types::{DAPHpkeInfo, HpkeCiphertext, Report, ReportMetadata};

mod types;
use crate::types::{DAPRole, HpkeConfig, ReportId, TaskId, Time, DAPAAD};

#[derive(Debug, Deserialize)]
struct Config {
    leader_url: String,
    helper_url: String,
    tasks: Vec<Task>,
}

#[derive(Debug, Deserialize)]
struct Task {
    id: TaskId,
    vdaf: String,
    veclen: usize,
    bits: u32,
    report_count: usize,
}

fn read_config() -> Config {
    let file = File::open("config.json").unwrap();
    let json_data = serde_json::from_reader(file).expect("JSON was not well-formatted");
    json_data
}

async fn get_hpke_config(base_url: &str, task_id: &TaskId) -> Result<HpkeConfig, Box<dyn Error>> {
    let url = format!(
        "{}/hpke_config?task_id={}",
        base_url,
        task_id.base64encoded()
    );
    println!("Getting HPKE config from: {}", url);
    let resp = reqwest::get(url).await?;
    let status = resp.status();
    if status != StatusCode::OK {
        panic!("Failed to get HPKE config: {:?}", &resp);
    }
    Ok(HpkeConfig::get_decoded(&resp.bytes().await?)?) // TODO use anyhow
}

fn dap_encrypt(
    hpke_config: &HpkeConfig,
    msg: &[u8],
    aad: &DAPAAD,
    info: &DAPHpkeInfo,
) -> HpkeCiphertext {
    let pubkey_bytes: &[u8] = &hpke_config.public_key;
    let pubkey = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(pubkey_bytes).unwrap();
    let mut csprng = rand::rngs::StdRng::from_entropy();
    let (encapped_key, ciphertext) =
        hpke::single_shot_seal::<AesGcm128, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &pubkey,
            info.bytes(),
            msg,
            aad.bytes(),
            &mut csprng,
        )
        .unwrap();

    HpkeCiphertext {
        config_id: hpke_config.id,
        enc: encapped_key.to_bytes().to_vec(),
        payload: ciphertext,
    }
}

async fn send_report(report: Report, config: &Config) -> Result<(), Box<dyn Error>> {
    let client = reqwest::Client::new();
    let res = client
        .post(format!("{}/upload", config.leader_url))
        .header("Content-Type", "application/dap-report")
        .body(report.get_encoded())
        .send()
        .await?;

    if res.status() != StatusCode::OK {
        println!("ERROR: Failed to send report. Response: {:?}", res);
    }

    Ok(())
}

async fn submit_reports_for_task(
    task: &Task,
    config: &Config,
    leader_hpke_config: &HpkeConfig,
    helper_hpke_config: &HpkeConfig,
) {
    // https://www.rfc-editor.org/rfc/rfc9180#name-kem-ids
    assert_eq!(leader_hpke_config.kem_id, 0x0020);
    assert_eq!(helper_hpke_config.kem_id, 0x0020);
    // https://www.rfc-editor.org/rfc/rfc9180#name-kdf-ids
    assert_eq!(leader_hpke_config.kdf_id, 1);
    assert_eq!(helper_hpke_config.kdf_id, 1);
    // https://www.rfc-editor.org/rfc/rfc9180#name-aead-ids
    assert_eq!(leader_hpke_config.aead_id, 1);
    assert_eq!(helper_hpke_config.aead_id, 1);

    let (_, input_shares) = if task.vdaf == "Prio3Aes128CountVec" {
        let prio = Prio3Aes128CountVec::new_aes128_count_vec(2, task.veclen).unwrap();
        let mut measurement = vec![0; task.veclen];
        measurement[0] = 1;
        if thread_rng().gen::<bool>() {
            measurement[2] = 1;
        } else {
            measurement[3] = 1;
        }
        prio.shard(&measurement).unwrap()
    } else if task.vdaf == "Prio3Aes128Sum" {
        let prio = Prio3Aes128Sum::new_aes128_sum(2, task.bits).unwrap();

        let measurement = thread_rng().gen_range(0..1 << task.bits);
        prio.shard(&measurement).unwrap()
    } else {
        panic!("Not implemented.");
    };

    debug_assert_eq!(input_shares.len(), 2);

    let time_precision = 60;
    let metadata = ReportMetadata {
        report_id: ReportId::generate(),
        time: Time::generate(time_precision),
        extensions: vec![],
    };

    let public_share: Vec<u8> = Vec::new();
    let aad = DAPAAD::new(&task.id, &metadata, &public_share);
    let leader_payload = dap_encrypt(
        &leader_hpke_config,
        &input_shares[0].get_encoded(),
        &aad,
        &DAPHpkeInfo::new(DAPRole::Client, DAPRole::Leader),
    );
    let helper_info = DAPHpkeInfo::new(DAPRole::Client, DAPRole::Helper);
    let helper_payload = dap_encrypt(
        &helper_hpke_config,
        &input_shares[1].get_encoded(),
        &aad,
        &helper_info,
    );

    let report = Report {
        task_id: task.id.clone(),
        metadata,
        public_share,
        encrypted_input_shares: vec![leader_payload, helper_payload],
    };

    send_report(report, &config).await.unwrap();
}

#[tokio::main]
async fn main() {
    let config = read_config();
    for task in &config.tasks {
        println!("Now processing: {:?}", task);

        let (leader_hpke_config, helper_hpke_config) = tokio::join!(
            get_hpke_config(&config.leader_url, &task.id),
            get_hpke_config(&config.helper_url, &task.id)
        );

        let leader_hpke_config: HpkeConfig = leader_hpke_config.unwrap();
        let helper_hpke_config: HpkeConfig = helper_hpke_config.unwrap();

        print!("Submitting reports: ({}) ", task.report_count);
        io::stdout().flush().unwrap();
        for i in 0..task.report_count {
            print!("{} ", i + 1);
            io::stdout().flush().unwrap();
            submit_reports_for_task(&task, &config, &leader_hpke_config, &helper_hpke_config).await;
        }
        println!("");
    }
}

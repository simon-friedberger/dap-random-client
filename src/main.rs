/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! This file implements a DAP client which will read task configurations from
//! a JSON file and generate random measurements for infrastructure testing.

use hpke::Deserializable;
use hpke::{
    aead::AesGcm128, kdf::HkdfSha256, kem::X25519HkdfSha256, Kem as KemTrait, OpModeS, Serializable,
};
use prio::codec::decode_u16_items;
use prio::vdaf::{prio3::Prio3SumVec, Client};
use prio::{codec::Encode, vdaf::prio3::Prio3Sum};
use rand::{thread_rng, Rng, SeedableRng};
use reqwest::{Client as HttpClient, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::{
    cmp::{max, min},
    error::Error,
    fmt::Write as _,
    fs::File,
    io::{self, Cursor, Write as _},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::task::JoinSet;
use types::{DAPHpkeInfo, HpkeCiphertext, Report, ReportMetadata};

mod types;
use crate::types::{DAPRole, DapAad, HpkeConfig, PlaintextInputShare, ReportID, TaskID, Time};

#[derive(Debug, Deserialize, Clone)]
struct Config {
    leader_url: String,
    helper_url: String,
    tasks: Vec<Task>,
}

#[derive(Debug, Deserialize, Clone)]
struct Task {
    #[serde(deserialize_with = "types::from_base64")]
    id: TaskID,
    vdaf: String,
    veclen: usize,
    bits: usize,
    report_count: usize,
}

fn read_config() -> Config {
    // Load config file based on `DAP_ENV`, which can be any of `dev`, `stage`, and `prod`.
    // `dev` is used if `DAP_ENV` is not specified.
    let path = format!(
        "divviupconfig-{}.json",
        option_env!("DAP_ENV").unwrap_or("dev")
    );
    let file = File::open(path).unwrap();
    serde_json::from_reader(file).expect("JSON was not well-formatted")
}

fn select_hpke_config(configs: Vec<HpkeConfig>) -> Result<HpkeConfig, Box<dyn Error>> {
    for config in configs {
        if config.kem_id == 0x20 /* DHKEM(X25519, HKDF-SHA256) */ &&
        config.kdf_id == 0x01 /* HKDF-SHA256 */ &&
        config.aead_id == 0x01
        /* AES-128-GCM */
        {
            return Ok(config);
        }
    }

    Err("No suitable HPKE config found.".into())
}

async fn get_hpke_config(base_url: &str, task_id: &TaskID) -> Result<HpkeConfig, Box<dyn Error>> {
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
    let configs = decode_u16_items(&(), &mut Cursor::new(&resp.bytes().await?))?;
    select_hpke_config(configs)
}

fn dap_encrypt(
    hpke_config: &HpkeConfig,
    msg: &[u8],
    aad: &DapAad,
    info: &DAPHpkeInfo,
) -> HpkeCiphertext {
    let pubkey_bytes: &[u8] = &hpke_config.public_key;
    let pubkey = <X25519HkdfSha256 as KemTrait>::PublicKey::from_bytes(pubkey_bytes)
        .expect("Could not parse public key");
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

async fn send_report(
    report: Report,
    config: &Config,
    task_id: &TaskID,
    http_client: HttpClient,
) -> Result<(), Box<dyn Error>> {
    let res = http_client
        .put(format!(
            "{}/tasks/{}/reports",
            config.leader_url,
            task_id.base64encoded()
        ))
        .header("Content-Type", "application/dap-report")
        .body(report.get_encoded())
        .send()
        .await?;

    if res.status() != StatusCode::OK {
        println!("\nERROR: Failed to send report.");
        println!("Response: {:?}", res);
        if res
            .headers()
            .get("Content-Type")
            .is_some_and(|ct| ct.to_str().unwrap().contains("json"))
        {
            println!("JSON: {:?}", res.json::<Value>().await?);
        } else {
            println!("CONTENT: {:?}", res.text().await.unwrap());
        }
        Err("Failed to send report".into())
    } else {
        Ok(())
    }
}

async fn submit_reports_for_task(
    task: Task,
    config: Config,
    leader_hpke_config: HpkeConfig,
    helper_hpke_config: HpkeConfig,
    http_client: HttpClient,
) -> Vec<u128> {
    // https://www.rfc-editor.org/rfc/rfc9180#name-kem-ids
    assert_eq!(leader_hpke_config.kem_id, 0x0020);
    assert_eq!(helper_hpke_config.kem_id, 0x0020);
    // https://www.rfc-editor.org/rfc/rfc9180#name-kdf-ids
    assert_eq!(leader_hpke_config.kdf_id, 1);
    assert_eq!(helper_hpke_config.kdf_id, 1);
    // https://www.rfc-editor.org/rfc/rfc9180#name-aead-ids
    assert_eq!(leader_hpke_config.aead_id, 1);
    assert_eq!(helper_hpke_config.aead_id, 1);

    let report_id = ReportID::generate();

    let mut measurement = vec![0; max(task.veclen, 1)];
    let (prio3public_share, input_shares) = if task.vdaf == "Prio3SumVec" {
        let prio = Prio3SumVec::new_sum_vec(2, task.bits, task.veclen, 4).unwrap();
        let total = thread_rng().gen_range(0..1 << task.bits);

        measurement[0] = total;
        if task.veclen > 2 {
            for _ in 0..total {
                if thread_rng().gen::<bool>() {
                    measurement[1] += 1;
                } else {
                    measurement[2] += 1;
                }
            }
        }
        //println!("Sending measurement for Prio3SumVec: {:?}", measurement);
        prio.shard(&measurement, report_id.as_ref()).unwrap()
    } else if task.vdaf == "Prio3Sum" {
        let prio = Prio3Sum::new_sum(2, task.bits).unwrap();

        measurement[0] = thread_rng().gen_range(0..1 << task.bits);
        //println!("Sending measurement for Prio3Sum: {:?}", measurement);
        prio.shard(&measurement[0], report_id.as_ref()).unwrap()
    } else {
        panic!("Not implemented. task.vdaf: {} unknown.", task.vdaf);
    };

    debug_assert_eq!(input_shares.len(), 2);
    let public_share = prio3public_share.get_encoded();

    let time_precision = 60;
    let metadata = ReportMetadata {
        report_id,
        time: Time::generate(time_precision),
    };

    let aad = DapAad::new(&task.id, &metadata, &public_share);

    let leader_pt_share = PlaintextInputShare {
        extensions: Vec::new(),
        payload: input_shares[0].get_encoded(),
    };
    let leader_payload = dap_encrypt(
        &leader_hpke_config,
        &leader_pt_share.get_encoded(),
        &aad,
        &DAPHpkeInfo::new(DAPRole::Client, DAPRole::Leader),
    );

    let helper_pt_share = PlaintextInputShare {
        extensions: Vec::new(),
        payload: input_shares[1].get_encoded(),
    };
    let helper_payload = dap_encrypt(
        &helper_hpke_config,
        &helper_pt_share.get_encoded(),
        &aad,
        &DAPHpkeInfo::new(DAPRole::Client, DAPRole::Helper),
    );

    let report = Report {
        metadata,
        public_share,
        leader_encrypted_input_share: leader_payload,
        helper_encrypted_input_share: helper_payload,
    };

    send_report(report, &config, &task.id, http_client)
        .await
        .unwrap();

    measurement
}

fn report_progress(done: usize, total: usize) -> String {
    const SCALER: usize = 25; // Such that the progress string can be shown in one line.
    let down_scale_by = max(total / SCALER, 1);
    let scaled_done = min(done / down_scale_by, SCALER);
    let mut buf = String::new();

    // The progress report will look like:
    //
    // Submitting reports: [・・・・・・・・・Co o o o o ] 75%
    write!(&mut buf, "Submitting reports: [").unwrap();
    write!(&mut buf, "{}", "・".repeat(scaled_done)).unwrap();
    write!(&mut buf, "C").unwrap();
    write!(&mut buf, "{}", "o ".repeat(SCALER - scaled_done)).unwrap();
    write!(
        &mut buf,
        "] {:3.0}%",
        (done as f32) / (total as f32) * 100.0
    )
    .unwrap();

    buf
}

#[tokio::main]
async fn main() {
    let config = read_config();
    let client = reqwest::Client::new();
    let counter = Arc::new(AtomicUsize::new(0));

    for task in &config.tasks {
        println!("Now processing: {:?}", task);

        let veclen = max(task.veclen, 1);
        let mut accumulator = vec![0; veclen];

        let (leader_hpke_config, helper_hpke_config) = tokio::join!(
            get_hpke_config(&config.leader_url, &task.id),
            get_hpke_config(&config.helper_url, &task.id)
        );

        let leader_hpke_config: HpkeConfig = leader_hpke_config.unwrap();
        let helper_hpke_config: HpkeConfig = helper_hpke_config.unwrap();

        println!("Total reports to submit: ({}) ", task.report_count);
        io::stdout().flush().unwrap();
        let mut tasks = JoinSet::new();

        for _ in 0..task.report_count {
            let client = client.clone();
            let task = task.clone();
            let config = config.clone();
            let leader_hpke_config = leader_hpke_config.clone();
            let helper_hpke_config = helper_hpke_config.clone();
            let counter = counter.clone();

            tasks.spawn(async move {
                let res = submit_reports_for_task(
                    task,
                    config,
                    leader_hpke_config,
                    helper_hpke_config,
                    client,
                )
                .await;
                counter.fetch_add(1, Ordering::Relaxed);

                res
            });
        }

        while let Some(res) = tasks.join_next().await {
            let res = res.expect("returned sum vector");
            for i in 0..veclen {
                accumulator[i] += res[i];
            }
            let done = counter.load(Ordering::Relaxed);
            let progress = report_progress(done, task.report_count);
            print!("\r{progress}");
            io::stdout().flush().unwrap();
        }
        print!("\rDone! Results: {accumulator:?}");
    }
}

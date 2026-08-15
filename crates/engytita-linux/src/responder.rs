//! Responder: advertise EID (service data + GATT) and complete pairing as Noise responder.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result};
use bluer::{
    adv::Advertisement,
    gatt::local::{
        characteristic_control, Application, Characteristic, CharacteristicControlEvent,
        CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicRead, CharacteristicWrite,
        CharacteristicWriteMethod, ReqError, Service,
    },
};
use engytita_core::PairingState;
use futures::{future::FutureExt, pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::time::sleep;

use crate::ids;
use crate::pairing_drive::{finish_complete, log_keys_ok, prompt_sas_and_confirm, PairingDrive};
use crate::store::{current_epoch, load_or_create_engine, random_bytes};

pub async fn run() -> Result<()> {
    let mut engine = load_or_create_engine()?;
    let epoch = current_epoch();
    let eid = engine.identity().beacon_eid(epoch);
    let peer_hex = hex::encode(engine.identity().peer_id().as_bytes());
    eprintln!(
        "peer_id={} epoch={epoch} eid={}",
        &peer_hex[..16.min(peer_hex.len())],
        hex::encode(eid)
    );

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;
    eprintln!(
        "adapter {} addr {}",
        adapter.name(),
        adapter.address().await?
    );

    let mut service_data = BTreeMap::new();
    service_data.insert(ids::service_uuid(), eid.to_vec());

    let adv = Advertisement {
        advertisement_type: bluer::adv::Type::Peripheral,
        service_uuids: [ids::service_uuid()].into_iter().collect(),
        service_data,
        discoverable: Some(true),
        local_name: Some("Engytita".into()),
        ..Default::default()
    };
    let _adv = adapter.advertise(adv).await.context("advertise")?;

    let eid_cell = std::sync::Arc::new(Mutex::new(eid));
    let eid_for_read = eid_cell.clone();

    let (write_ctrl, write_handle) = characteristic_control();
    let (notify_ctrl, notify_handle) = characteristic_control();

    let app = Application {
        services: vec![Service {
            uuid: ids::service_uuid(),
            primary: true,
            characteristics: vec![
                Characteristic {
                    uuid: ids::eid_uuid(),
                    read: Some(CharacteristicRead {
                        read: true,
                        fun: Box::new(move |req| {
                            let eid_for_read = eid_for_read.clone();
                            async move {
                                let eid = *eid_for_read.lock().await;
                                if req.offset as usize > eid.len() {
                                    return Err(ReqError::InvalidOffset);
                                }
                                Ok(eid[req.offset as usize..].to_vec())
                            }
                            .boxed()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Characteristic {
                    uuid: ids::pairing_write_uuid(),
                    write: Some(CharacteristicWrite {
                        write: true,
                        write_without_response: false,
                        method: CharacteristicWriteMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: write_handle,
                    ..Default::default()
                },
                Characteristic {
                    uuid: ids::pairing_notify_uuid(),
                    notify: Some(CharacteristicNotify {
                        notify: true,
                        method: CharacteristicNotifyMethod::Io,
                        ..Default::default()
                    }),
                    control_handle: notify_handle,
                    ..Default::default()
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    };
    let _app = adapter
        .serve_gatt_application(app)
        .await
        .context("gatt app")?;

    let eph = random_bytes::<32>();
    let (mut drive, state) = PairingDrive::start_responder(&engine, &eph)?;
    eprintln!("responder ready — waiting for initiator ({state:?})");

    let mut reader_opt = None;
    let mut writer_opt = None;
    let mut read_buf = vec![0u8; 512];
    pin_mut!(write_ctrl);
    pin_mut!(notify_ctrl);

    loop {
        tokio::select! {
            evt = write_ctrl.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Write(req)) => {
                        eprintln!("pairing write accepted mtu={}", req.mtu());
                        read_buf = vec![0u8; req.mtu()];
                        reader_opt = Some(req.accept()?);
                    }
                    Some(CharacteristicControlEvent::Notify(_)) => {}
                    None => break,
                }
            }
            evt = notify_ctrl.next() => {
                match evt {
                    Some(CharacteristicControlEvent::Notify(n)) => {
                        eprintln!("pairing notify subscribed mtu={}", n.mtu());
                        writer_opt = Some(n);
                    }
                    Some(CharacteristicControlEvent::Write(_)) => {}
                    None => break,
                }
            }
            n = async {
                match &mut reader_opt {
                    Some(r) => r.read(&mut read_buf).await,
                    None => std::future::pending().await,
                }
            } => {
                match n {
                    Ok(0) => { reader_opt = None; }
                    Ok(n) => {
                        let msg = read_buf[..n].to_vec();
                        eprintln!("<< {} bytes", msg.len());
                        let mut state = drive.apply_inbound(&msg);
                        if handle_state(
                            &mut engine,
                            &mut drive,
                            &mut state,
                            &mut writer_opt,
                        ).await? {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("read err: {e}");
                        reader_opt = None;
                    }
                }
            }
        }
    }

    sleep(Duration::from_secs(1)).await;
    Ok(())
}

async fn handle_state(
    engine: &mut engytita_core::ConsentEngine,
    drive: &mut PairingDrive,
    state: &mut PairingState,
    writer_opt: &mut Option<bluer::gatt::CharacteristicWriter>,
) -> Result<bool> {
    loop {
        match state {
            PairingState::AwaitingMessage => return Ok(false),
            PairingState::SendMessage(data) => {
                eprintln!(">> {} bytes", data.len());
                let Some(w) = writer_opt.as_mut() else {
                    anyhow::bail!("no notify writer yet — wait for central to subscribe");
                };
                w.write_all(data).await?;
                if let Some(next) = drive.poll_after_send() {
                    *state = next;
                    continue;
                }
                return Ok(false);
            }
            PairingState::ConfirmSas { digits } => {
                *state = prompt_sas_and_confirm(drive, digits).await?;
                continue;
            }
            PairingState::Complete { peer_id } => {
                let keys = finish_complete(engine, drive, *peer_id)?;
                log_keys_ok(&keys);
                eprintln!("pairing complete");
                return Ok(true);
            }
            PairingState::Failed(err) => {
                anyhow::bail!("pairing failed: {err:?}");
            }
        }
    }
}

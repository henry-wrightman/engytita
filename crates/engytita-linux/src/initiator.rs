//! Initiator: discover Engytita peripherals, connect, pair as Noise initiator.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use bluer::{AdapterEvent, Device};
use engytita_core::{PairingState, Resolver};
use futures::{pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

use crate::ids;
use crate::pairing_drive::{finish_complete, log_keys_ok, prompt_sas_and_confirm, PairingDrive};
use crate::store::{current_epoch, load_or_create_engine, random_bytes};

pub async fn run(target: Option<String>, scan_secs: u64) -> Result<()> {
    let mut engine = load_or_create_engine()?;
    let epoch = current_epoch();
    eprintln!(
        "local peer_id={} epoch={epoch}",
        hex::encode(engine.identity().peer_id().as_bytes())
    );

    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;

    let device = if let Some(addr) = target {
        let addr: bluer::Address = addr.parse().context("bad Bluetooth address")?;
        adapter.device(addr)?
    } else {
        discover_engytita(&adapter, scan_secs).await?
    };

    let addr = device.address();
    eprintln!("using device {addr}");
    if !device.is_connected().await? {
        device.connect().await.context("connect")?;
    }

    // Prefer service-data EID from advertisement when present.
    let mut remote_eid = [0u8; 8];
    if let Some(map) = device.service_data().await? {
        if let Some(v) = map.get(&ids::service_uuid()) {
            if v.len() == 8 {
                remote_eid.copy_from_slice(v);
                eprintln!("EID from service data: {}", hex::encode(remote_eid));
            }
        }
    }

    let mut eid_char = None;
    let mut write_char = None;
    let mut notify_char = None;
    for service in device.services().await? {
        if service.uuid().await? != ids::service_uuid() {
            continue;
        }
        for ch in service.characteristics().await? {
            let u = ch.uuid().await?;
            if u == ids::eid_uuid() {
                eid_char = Some(ch);
            } else if u == ids::pairing_write_uuid() {
                write_char = Some(ch);
            } else if u == ids::pairing_notify_uuid() {
                notify_char = Some(ch);
            }
        }
    }

    if remote_eid == [0u8; 8] {
        let eid_c = eid_char.context("missing EID characteristic")?;
        let v = eid_c.read().await.context("read EID")?;
        if v.len() != 8 {
            bail!("EID characteristic length {}", v.len());
        }
        remote_eid.copy_from_slice(&v);
        eprintln!("EID from GATT: {}", hex::encode(remote_eid));
    }

    let mut resolver = Resolver::new();
    resolver.rebuild(&engine.peer_records(), epoch)?;
    if let Some(pid) = resolver.resolve(&remote_eid) {
        eprintln!("already known peer {}", hex::encode(pid.as_bytes()));
    } else {
        eprintln!("unknown EID — starting pairing");
    }

    let write_c = write_char.context("missing pairing write char")?;
    let notify_c = notify_char.context("missing pairing notify char")?;

    let mut write_io = write_c.write_io().await.context("write_io")?;
    let mut notify_io = notify_c.notify_io().await.context("notify_io")?;

    // Drain stale notifications.
    let mut drain = [0u8; 512];
    while timeout(Duration::from_millis(200), notify_io.read(&mut drain))
        .await
        .is_ok()
    {}

    let eph = random_bytes::<32>();
    let (mut drive, state) = PairingDrive::start_initiator(&engine, &eph)?;
    let mut state = state;

    loop {
        match &state {
            PairingState::SendMessage(data) => {
                eprintln!(">> {} bytes", data.len());
                write_io.write_all(data).await?;
                if let Some(next) = drive.poll_after_send() {
                    state = next;
                    continue;
                }
                // Wait for peer response.
                let mut buf = vec![0u8; write_io.mtu().max(512)];
                let n = notify_io.read(&mut buf).await.context("notify read")?;
                if n == 0 {
                    bail!("notify EOF");
                }
                eprintln!("<< {n} bytes");
                state = drive.apply_inbound(&buf[..n]);
            }
            PairingState::AwaitingMessage => {
                let mut buf = vec![0u8; 512];
                let n = notify_io.read(&mut buf).await.context("notify read")?;
                if n == 0 {
                    bail!("notify EOF");
                }
                eprintln!("<< {n} bytes");
                state = drive.apply_inbound(&buf[..n]);
            }
            PairingState::ConfirmSas { digits } => {
                state = prompt_sas_and_confirm(&mut drive, digits).await?;
            }
            PairingState::Complete { peer_id } => {
                let keys = finish_complete(&mut engine, &mut drive, *peer_id)?;
                log_keys_ok(&keys);
                eprintln!("pairing complete");
                break;
            }
            PairingState::Failed(err) => bail!("pairing failed: {err:?}"),
        }
    }

    let _ = device.disconnect().await;
    sleep(Duration::from_millis(500)).await;
    Ok(())
}

async fn discover_engytita(adapter: &bluer::Adapter, scan_secs: u64) -> Result<Device> {
    eprintln!("scanning {scan_secs}s for Engytita service…");
    let discover = adapter.discover_devices().await?;
    pin_mut!(discover);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(scan_secs);
    while tokio::time::Instant::now() < deadline {
        let next = timeout(Duration::from_millis(500), discover.next()).await;
        let Ok(Some(evt)) = next else { continue };
        if let AdapterEvent::DeviceAdded(addr) = evt {
            let device = adapter.device(addr)?;
            let uuids = device.uuids().await?.unwrap_or_default();
            if uuids.contains(&ids::service_uuid()) {
                eprintln!("found {addr} name={:?}", device.name().await?);
                return Ok(device);
            }
            // Service data may appear before UUID list is populated.
            if let Some(map) = device.service_data().await? {
                if map.contains_key(&ids::service_uuid()) {
                    eprintln!("found {addr} via service data");
                    return Ok(device);
                }
            }
        }
    }
    bail!("no Engytita peripheral found in {scan_secs}s");
}

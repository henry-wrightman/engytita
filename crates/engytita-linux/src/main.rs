//! Linux/BlueZ reference host for Engytita (Raspberry Pi, robots, vehicles).
//!
//! BLE radio lives here — not in `engytita-core` / `engytita-ble`. GATT UUIDs
//! match the iOS reference sample for eventual cross-platform pairing.

#[cfg(target_os = "linux")]
mod ids;
#[cfg(target_os = "linux")]
mod initiator;
#[cfg(target_os = "linux")]
mod pairing_drive;
#[cfg(target_os = "linux")]
mod responder;
mod store;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "engytita-linux", about = "Engytita Linux/BlueZ reference host")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Show local peer id, epoch, and beacon EID.
    Status,
    /// Advertise EID + wait as Noise pairing responder (Linux + BlueZ).
    #[cfg(target_os = "linux")]
    Responder,
    /// Scan/connect and pair as Noise initiator (Linux + BlueZ).
    #[cfg(target_os = "linux")]
    Initiator {
        /// Bluetooth address (omit to scan for Engytita service).
        #[arg(long)]
        addr: Option<String>,
        /// Scan timeout seconds when `--addr` is omitted.
        #[arg(long, default_value_t = 20)]
        scan_secs: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Status => {
            let engine = store::load_or_create_engine()?;
            let epoch = store::current_epoch();
            let eid = engine.identity().beacon_eid(epoch);
            println!(
                "peer_id={}",
                hex::encode(engine.identity().peer_id().as_bytes())
            );
            println!("epoch={epoch}");
            println!("eid={}", hex::encode(eid));
            println!("identity={}", store::identity_path()?.display());
            Ok(())
        }
        #[cfg(target_os = "linux")]
        Command::Responder => responder::run().await,
        #[cfg(target_os = "linux")]
        Command::Initiator { addr, scan_secs } => initiator::run(addr, scan_secs).await,
    }
}

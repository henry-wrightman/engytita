//! Demo-quality on-disk identity (64-byte entropy). Not a secure enclave.

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use engytita_core::{ConsentEngine, Identity};
use rand::RngCore;

pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("no config dir")?;
    Ok(base.join("engytita"))
}

pub fn identity_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("identity.entropy"))
}

pub fn load_or_create_engine() -> Result<ConsentEngine> {
    let path = identity_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let entropy = if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() != 64 {
            bail!("{}: expected 64 bytes, got {}", path.display(), bytes.len());
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        let mut arr = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut arr);
        fs::write(&path, arr)?;
        eprintln!("wrote new identity entropy → {}", path.display());
        arr
    };
    let identity = Identity::from_entropy64(entropy);
    let mut engine = ConsentEngine::new(identity);
    engine.set_availability(engytita_core::Availability::ContactsOnly);
    Ok(engine)
}

pub fn current_epoch() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs / engytita_core::EPOCH_SECONDS
}

#[cfg(target_os = "linux")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

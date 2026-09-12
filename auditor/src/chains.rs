//! Multi-chain configuration: one entry per `<DEPLOYMENTS_DIR>/<chainId>.json`.
//! Per-chain env with `_<chainId>` suffix, falling back to the unsuffixed name:
//!   RPC_URL_<id>, AUDITOR_SECRET_<id>, POLL_SECS_<id>
//! `CHAINS` (comma-separated ids) restricts which deployment files are loaded.
use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentFile {
    pub chain_id: u64,
    pub app: String,
    pub deploy_block: u64,
    pub auditor_x: String,
    pub auditor_y: String,
    #[serde(default)]
    pub rpc_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub rpc_url: String,
    pub app: String,
    pub deploy_block: u64,
    pub auditor_x: String,
    pub auditor_y: String,
    pub auditor_secret: Vec<u8>,
    pub poll_secs: u64,
}

pub fn env_for(id: u64, key: &str, default: Option<&str>) -> Option<String> {
    std::env::var(format!("{key}_{id}"))
        .or_else(|_| std::env::var(key))
        .ok()
        .or_else(|| default.map(str::to_string))
}

pub fn chain_configs(dir: &Path) -> Result<Vec<ChainConfig>> {
    let only: Option<Vec<u64>> = std::env::var("CHAINS")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect());
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let d: DeploymentFile = serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("parsing {}", path.display()))?;
        if only.as_ref().is_some_and(|ids| !ids.contains(&d.chain_id)) {
            continue;
        }
        files.insert(d.chain_id, d);
    }
    if files.is_empty() {
        anyhow::bail!("no deployment files found in {}", dir.display());
    }
    let mut v = vec![];
    for (id, d) in files {
        let rpc_url = env_for(id, "RPC_URL", None).or(d.rpc_url.clone()).with_context(|| format!("RPC_URL_{id} not set"))?;
        let secret_hex = env_for(id, "AUDITOR_SECRET", None).with_context(|| format!("AUDITOR_SECRET_{id} / AUDITOR_SECRET not set"))?;
        let auditor_secret = hex::decode(secret_hex.trim_start_matches("0x")).with_context(|| format!("AUDITOR_SECRET_{id}"))?;
        let poll_secs = env_for(id, "POLL_SECS", Some("3")).unwrap().parse().context("POLL_SECS")?;
        v.push(ChainConfig {
            chain_id: id,
            rpc_url,
            app: d.app,
            deploy_block: d.deploy_block,
            auditor_x: d.auditor_x,
            auditor_y: d.auditor_y,
            auditor_secret,
            poll_secs,
        });
    }
    Ok(v)
}

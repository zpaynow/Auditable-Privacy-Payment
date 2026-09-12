//! Multi-chain configuration.
//!
//! Every `<DEPLOYMENTS_DIR>/<chainId>.json` written by `forge script script/Deploy.s.sol` becomes a
//! served chain. Per-chain secrets and tunables come from the environment with a `_<chainId>`
//! suffix, falling back to the unsuffixed variable:
//!
//!   RPC_URL_<id>          (required unless the deployment file carries `rpcUrl`)
//!   OPERATOR_KEY_<id>     (falls back to OPERATOR_KEY)
//!   FEE_ASSET_<id>, TRANSFER_FEE_<id>, WITHDRAW_FEE_<id>, BATCH_MAX_<id>, BATCH_INTERVAL_SECS_<id>
//!
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
    pub operator_key: String,
    pub fee_asset: u64,
    pub transfer_fee: u128,
    pub withdraw_fee: u128,
    pub batch_max: usize,
    pub batch_interval_secs: u64,
}

/// `VAR_<id>` then `VAR`, then default.
pub fn env_for(id: u64, key: &str, default: Option<&str>) -> Option<String> {
    std::env::var(format!("{key}_{id}"))
        .or_else(|_| std::env::var(key))
        .ok()
        .or_else(|| default.map(str::to_string))
}

pub fn load_deployments(dir: &Path) -> Result<BTreeMap<u64, DeploymentFile>> {
    let only: Option<Vec<u64>> = std::env::var("CHAINS")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect());
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let d: DeploymentFile = serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("parsing {}", path.display()))?;
        if let Some(ids) = &only {
            if !ids.contains(&d.chain_id) {
                continue;
            }
        }
        out.insert(d.chain_id, d);
    }
    if out.is_empty() {
        anyhow::bail!("no deployment files found in {}", dir.display());
    }
    Ok(out)
}

pub fn chain_configs(dir: &Path) -> Result<Vec<ChainConfig>> {
    let mut v = vec![];
    for (id, d) in load_deployments(dir)? {
        let rpc_url = env_for(id, "RPC_URL", None)
            .or(d.rpc_url.clone())
            .with_context(|| format!("RPC_URL_{id} not set"))?;
        let operator_key = env_for(id, "OPERATOR_KEY", None).with_context(|| format!("OPERATOR_KEY_{id} / OPERATOR_KEY not set"))?;
        let parse = |k: &str, dflt: &str| -> Result<u128> {
            env_for(id, k, Some(dflt)).unwrap().parse().with_context(|| format!("{k}_{id}"))
        };
        v.push(ChainConfig {
            chain_id: id,
            rpc_url,
            app: d.app,
            deploy_block: d.deploy_block,
            auditor_x: d.auditor_x,
            auditor_y: d.auditor_y,
            operator_key,
            fee_asset: parse("FEE_ASSET", "1")? as u64,
            transfer_fee: parse("TRANSFER_FEE", "10000")?,
            withdraw_fee: parse("WITHDRAW_FEE", "10000")?,
            batch_max: parse("BATCH_MAX", "10")? as usize,
            batch_interval_secs: parse("BATCH_INTERVAL_SECS", "30")? as u64,
        });
    }
    Ok(v)
}

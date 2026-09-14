//! APP aggregator service (multi-chain).
//!
//! Accepts shielded transfers (3-output shapes, output #2 = fee to this service's payment key)
//! and withdraws (fee field paid to the operator), verifies them natively, queues them per chain,
//! and periodically settles a batch per chain with `APP.submitBatch` — one pairing check and one
//! tree update for the whole batch. After each batch it folds the batch's proofs per circuit
//! with snarkfold and serves the aggregated proofs.
//!
//! One instance serves every chain that has a deployment file in `DEPLOYMENTS_DIR`; every API
//! route is prefixed with `/chains/{chainId}`. See `chains.rs` for the per-chain environment.
//!
//! Global environment: DEPLOYMENTS_DIR (default ../solidity/deployments), AGGREGATOR_SECRET,
//! KEYS_DIR (default ../artifacts), DB_PATH, PORT.

mod api;
mod batcher;
mod chain;
mod chains;
mod db;
mod verify;

use anyhow::{Context, Result};
use app_payment::{Keypair, evm};
use ark_serialize::CanonicalSerialize;
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
use tokio::sync::Notify;
use tower_http::cors::CorsLayer;

pub use chains::ChainConfig;

/// Everything the service holds for one chain.
pub struct ChainCtx {
    pub cfg: ChainConfig,
    pub chain: chain::Chain,
    pub verifier: verify::Verifier,
    pub nudge: Notify,
}

impl ChainCtx {
    /// Chain-state checks shared by both submit endpoints and the batcher.
    pub async fn precheck(&self, c: &verify::Checked, freezers: &[String]) -> Result<()> {
        if !self.chain.is_known_root(&c.root).await? {
            anyhow::bail!("root is not known to the contract (resync and re-prove)");
        }
        for n in &c.nullifiers {
            if self.chain.nullifier_used(n).await? {
                anyhow::bail!("nullifier already spent on-chain");
            }
        }
        for f in freezers {
            if self.chain.is_frozen(f).await? {
                anyhow::bail!("input note is frozen by the auditor");
            }
        }
        Ok(())
    }
}

pub struct AppState {
    pub chains: BTreeMap<u64, Arc<ChainCtx>>,
    pub db: db::Db,
    pub aggregator_pk_hex: String,
}

impl AppState {
    pub fn chain(&self, id: u64) -> Option<Arc<ChainCtx>> {
        self.chains.get(&id).cloned()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let opt = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());

    let deployments_dir = PathBuf::from(opt("DEPLOYMENTS_DIR", "../solidity/deployments"));
    let keys_dir = PathBuf::from(opt("KEYS_DIR", "../artifacts"));
    let secret = hex::decode(std::env::var("AGGREGATOR_SECRET").context("missing env AGGREGATOR_SECRET")?.trim_start_matches("0x"))
        .context("AGGREGATOR_SECRET")?;
    let aggregator = Keypair::from_secret_bytes(&secret).map_err(|e| anyhow::anyhow!("AGGREGATOR_SECRET: {e:?}"))?;
    let mut pk = vec![];
    aggregator.public.x.serialize_compressed(&mut pk)?;
    aggregator.public.y.serialize_compressed(&mut pk)?;
    let aggregator_pk_hex = format!("0x{}", hex::encode(&pk));

    let mut chains = BTreeMap::new();
    for cfg in chains::chain_configs(&deployments_dir)? {
        let app = cfg.app.parse().context("app address")?;
        let chain = chain::Chain::connect(&cfg.rpc_url, app, &cfg.operator_key).await
            .with_context(|| format!("connecting to chain {}", cfg.chain_id))?;
        if chain.chain_id != cfg.chain_id {
            anyhow::bail!("RPC for chain {} reports chain id {}", cfg.chain_id, chain.chain_id);
        }
        if !chain.is_operator().await? {
            anyhow::bail!("{:?} is not an operator of {} on chain {}; call APP.setOperator first", chain.operator, cfg.app, cfg.chain_id);
        }
        let (ax, ay) = chain.auditor().await?;
        let auditor_x = evm::fr_from_bytes32(ax.as_slice()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let auditor_y = evm::fr_from_bytes32(ay.as_slice()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let verifier =
            verify::Verifier::load(&keys_dir, auditor_x, auditor_y, aggregator.clone(), chain.operator.as_slice())?;
        tracing::info!(
            chain_id = cfg.chain_id,
            app = %cfg.app,
            operator = ?chain.operator,
            transfer_fee = cfg.transfer_fee,
            withdraw_fee = cfg.withdraw_fee,
            "chain ready"
        );
        chains.insert(cfg.chain_id, Arc::new(ChainCtx { cfg, chain, verifier, nudge: Notify::new() }));
    }

    let db = db::Db::open(&opt("DB_PATH", "aggregator.sqlite"))?;
    let port: u16 = opt("PORT", "8787").parse()?;
    tracing::info!(aggregator_pk = %aggregator_pk_hex, chains = ?chains.keys().collect::<Vec<_>>(), "aggregator ready");

    let state = Arc::new(AppState { chains, db, aggregator_pk_hex });
    for id in state.chains.keys().copied().collect::<Vec<_>>() {
        tokio::spawn(batcher::run(state.clone(), id));
    }

    let app = api::router(state).layer(CorsLayer::permissive());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}

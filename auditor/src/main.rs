//! APP auditor service (multi-chain).
//!
//! Indexes the pool on every configured chain (commitments, nullifiers, freezes), opens every
//! audit memo with the auditor key, and keeps one commitment tree per chain. Wallets authenticate
//! with their payment key and fetch their own notes and Merkle proofs instead of scanning the
//! chain; the auditor UI reads the full decrypted view with an admin token.
//!
//! Chains come from `DEPLOYMENTS_DIR/<chainId>.json`; per-chain env in `chains.rs`. Every API
//! route is prefixed with `/chains/{chainId}`.
//!
//! Global environment: DEPLOYMENTS_DIR (default ../solidity/deployments), DB_PATH, PORT, ADMIN_TOKEN

mod api;
mod chains;
mod db;
mod indexer;

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder, RootProvider},
};
use anyhow::{Context, Result};
use app_payment::{Keypair, MemoryStorage, MerkleTree};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower_http::cors::CorsLayer;

pub use chains::ChainConfig;

/// Everything the service holds for one chain.
pub struct ChainCtx {
    pub cfg: ChainConfig,
    pub app: Address,
    pub provider: RootProvider,
    pub db: Arc<db::Db>,
    pub auditor: Keypair,
    pub tree: Mutex<MerkleTree<MemoryStorage>>,
}

pub struct AppState {
    pub chains: BTreeMap<u64, Arc<ChainCtx>>,
    pub db: Arc<db::Db>,
    pub admin_token: Option<String>,
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
    let db = Arc::new(db::Db::open(&opt("DB_PATH", "auditor.sqlite"))?);
    let admin_token = std::env::var("ADMIN_TOKEN").ok().filter(|t| !t.is_empty());

    let mut chains = BTreeMap::new();
    for cfg in chains::chain_configs(&deployments_dir)? {
        let id = cfg.chain_id;
        let app: Address = cfg.app.parse().context("app address")?;
        let provider = ProviderBuilder::new().connect(&cfg.rpc_url).await.with_context(|| format!("rpc for chain {id}"))?;
        let reported = provider.get_chain_id().await?;
        if reported != id {
            anyhow::bail!("RPC for chain {id} reports chain id {reported}");
        }
        let auditor = Keypair::from_secret_bytes(&cfg.auditor_secret).map_err(|e| anyhow::anyhow!("AUDITOR_SECRET_{id}: {e:?}"))?;
        // the key must match the auditor registered in the deployment, otherwise memos will not open
        let want_x = alloy::primitives::U256::from_str_radix(cfg.auditor_x.trim_start_matches("0x"), if cfg.auditor_x.starts_with("0x") { 16 } else { 10 })
            .context("auditorX")?;
        let have_x = alloy::primitives::U256::from_be_slice(&auditor.public.x.into_bigint().to_bytes_be());
        if want_x != have_x {
            tracing::warn!(chain_id = id, "AUDITOR_SECRET does not match the auditor key in the deployment file; audit memos will not decrypt");
        }

        // rebuild the tree from the indexed commitments
        let mut tree = MerkleTree::new(0, MemoryStorage::default()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let comms = db.commitments(id)?;
        for c in &comms {
            let bytes = hex::decode(c.trim_start_matches("0x"))?;
            tree.add_leaf(Fr::from_be_bytes_mod_order(&bytes)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        }
        if !comms.is_empty() {
            tree.commit().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        }
        tracing::info!(chain_id = id, app = %cfg.app, notes = comms.len(), "chain ready");
        chains.insert(
            id,
            Arc::new(ChainCtx { cfg, app, provider: provider.root().clone(), db: db.clone(), auditor, tree: Mutex::new(tree) }),
        );
    }

    let port: u16 = opt("PORT", "8788").parse()?;
    let state = Arc::new(AppState { chains, db, admin_token });
    for ctx in state.chains.values() {
        tokio::spawn(indexer::run(ctx.clone()));
    }
    tracing::info!(chains = ?state.chains.keys().collect::<Vec<_>>(), "auditor ready");

    let app = api::router(state).layer(CorsLayer::permissive());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}

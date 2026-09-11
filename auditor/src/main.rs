//! APP auditor service.
//!
//! Indexes the pool (commitments, nullifiers, freezes), opens every audit memo with the auditor
//! key, and keeps the commitment tree. Wallets authenticate with their payment key and fetch
//! their own notes and Merkle proofs instead of scanning the chain; the auditor UI reads the
//! full decrypted view with an admin token.
//!
//! Environment: RPC_URL, APP_ADDRESS, AUDITOR_SECRET, DEPLOY_BLOCK, POLL_SECS, DB_PATH, PORT, ADMIN_TOKEN

mod api;
mod db;
mod indexer;

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder, RootProvider},
};
use anyhow::{Context, Result};
use app_payment::{Keypair, MemoryStorage, MerkleTree};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use std::sync::{Arc, Mutex};
use tower_http::cors::CorsLayer;

pub struct Config {
    pub rpc_url: String,
    pub app: Address,
    pub deploy_block: u64,
    pub poll_secs: u64,
    pub db_path: String,
    pub port: u16,
    pub admin_token: Option<String>,
}

pub struct AppState {
    pub cfg: Config,
    pub chain_id: u64,
    pub provider: RootProvider,
    pub db: db::Db,
    pub auditor: Keypair,
    pub tree: Mutex<MerkleTree<MemoryStorage>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let var = |k: &str| std::env::var(k).with_context(|| format!("missing env {k}"));
    let opt = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());

    let cfg = Config {
        rpc_url: opt("RPC_URL", "http://127.0.0.1:8545"),
        app: indexer::app_address(&var("APP_ADDRESS")?)?,
        deploy_block: opt("DEPLOY_BLOCK", "0").parse()?,
        poll_secs: opt("POLL_SECS", "3").parse()?,
        db_path: opt("DB_PATH", "auditor.sqlite"),
        port: opt("PORT", "8788").parse()?,
        admin_token: std::env::var("ADMIN_TOKEN").ok(),
    };
    let secret = hex::decode(var("AUDITOR_SECRET")?.trim_start_matches("0x")).context("AUDITOR_SECRET")?;
    let auditor = Keypair::from_secret_bytes(&secret).map_err(|e| anyhow::anyhow!("AUDITOR_SECRET: {e:?}"))?;

    let provider = ProviderBuilder::new().connect(&cfg.rpc_url).await.context("rpc")?;
    let chain_id = provider.get_chain_id().await?;
    let db = db::Db::open(&cfg.db_path)?;

    // rebuild the tree from the indexed commitments
    let mut tree = MerkleTree::new(0, MemoryStorage::default()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let comms = db.commitments()?;
    for c in &comms {
        let bytes = hex::decode(c.trim_start_matches("0x"))?;
        tree.add_leaf(Fr::from_be_bytes_mod_order(&bytes)).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    }
    if !comms.is_empty() {
        tree.commit().map_err(|e| anyhow::anyhow!("{e:?}"))?;
    }
    tracing::info!(chain_id, app = ?cfg.app, notes = comms.len(), "auditor ready");

    let port = cfg.port;
    let state = Arc::new(AppState { cfg, chain_id, provider: provider.root().clone(), db, auditor, tree: Mutex::new(tree) });
    tokio::spawn(indexer::run(state.clone()));

    let app = api::router(state).layer(CorsLayer::permissive());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}

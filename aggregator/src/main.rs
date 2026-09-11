//! APP aggregator service.
//!
//! Accepts shielded transfers (3-output shapes, output #2 = fee to this service's payment key)
//! and withdraws (fee field paid to the operator), verifies them natively, queues them, and
//! periodically settles a batch with `APP.submitBatch` — one pairing check and one tree update
//! for the whole batch. After each batch it folds the batch's proofs per circuit with snarkfold
//! and serves the aggregated proofs at `/batch/:id/proof/:group`.
//!
//! Environment (see `.env.example`):
//!   RPC_URL, APP_ADDRESS, OPERATOR_KEY, AGGREGATOR_SECRET, KEYS_DIR,
//!   FEE_ASSET, TRANSFER_FEE, WITHDRAW_FEE, BATCH_MAX, BATCH_INTERVAL_SECS, DB_PATH, PORT

mod api;
mod batcher;
mod chain;
mod db;
mod verify;

use alloy::primitives::Address;
use anyhow::{Context, Result};
use app_payment::{Keypair, evm};
use ark_serialize::CanonicalSerialize;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Notify;
use tower_http::cors::CorsLayer;

pub struct Config {
    pub rpc_url: String,
    pub app: Address,
    pub operator_key: String,
    pub aggregator_secret: Vec<u8>,
    pub keys_dir: PathBuf,
    pub fee_asset: u64,
    pub transfer_fee: u128,
    pub withdraw_fee: u128,
    pub batch_max: usize,
    pub batch_interval_secs: u64,
    pub db_path: String,
    pub port: u16,
}

impl Config {
    fn from_env() -> Result<Self> {
        let var = |k: &str| std::env::var(k).with_context(|| format!("missing env {k}"));
        let opt = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        Ok(Self {
            rpc_url: opt("RPC_URL", "http://127.0.0.1:8545"),
            app: var("APP_ADDRESS")?.parse().context("APP_ADDRESS")?,
            operator_key: var("OPERATOR_KEY")?,
            aggregator_secret: hex::decode(var("AGGREGATOR_SECRET")?.trim_start_matches("0x")).context("AGGREGATOR_SECRET")?,
            keys_dir: PathBuf::from(opt("KEYS_DIR", "../artifacts")),
            fee_asset: opt("FEE_ASSET", "1").parse()?,
            transfer_fee: opt("TRANSFER_FEE", "10000").parse()?,
            withdraw_fee: opt("WITHDRAW_FEE", "10000").parse()?,
            batch_max: opt("BATCH_MAX", "10").parse()?,
            batch_interval_secs: opt("BATCH_INTERVAL_SECS", "30").parse()?,
            db_path: opt("DB_PATH", "aggregator.sqlite"),
            port: opt("PORT", "8787").parse()?,
        })
    }
}

pub struct AppState {
    pub cfg: Config,
    pub db: db::Db,
    pub chain: chain::Chain,
    pub verifier: verify::Verifier,
    pub aggregator_pk_hex: String,
    pub nudge: Notify,
}

impl AppState {
    /// Chain-state checks shared by both submit endpoints.
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

#[tokio::main]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cfg = Config::from_env()?;

    let chain = chain::Chain::connect(&cfg.rpc_url, cfg.app, &cfg.operator_key).await?;
    if !chain.is_operator().await? {
        anyhow::bail!("{:?} is not an operator of {:?}; call APP.setOperator first", chain.operator, cfg.app);
    }
    let (ax, ay) = chain.auditor().await?;
    let auditor_x = evm::fr_from_bytes32(ax.as_slice()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let auditor_y = evm::fr_from_bytes32(ay.as_slice()).map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let aggregator = Keypair::from_secret_bytes(&cfg.aggregator_secret).map_err(|e| anyhow::anyhow!("AGGREGATOR_SECRET: {e:?}"))?;
    let mut pk = vec![];
    aggregator.public.x.serialize_compressed(&mut pk)?;
    aggregator.public.y.serialize_compressed(&mut pk)?;
    let aggregator_pk_hex = format!("0x{}", hex::encode(&pk));

    let verifier = verify::Verifier::load(&cfg.keys_dir, auditor_x, auditor_y, aggregator)?;
    let db = db::Db::open(&cfg.db_path)?;

    tracing::info!(
        chain_id = chain.chain_id,
        app = ?cfg.app,
        operator = ?chain.operator,
        aggregator_pk = %aggregator_pk_hex,
        transfer_fee = cfg.transfer_fee,
        withdraw_fee = cfg.withdraw_fee,
        "aggregator ready"
    );

    let port = cfg.port;
    let state = Arc::new(AppState { cfg, db, chain, verifier, aggregator_pk_hex, nudge: Notify::new() });
    tokio::spawn(batcher::run(state.clone()));

    let app = api::router(state).layer(CorsLayer::permissive());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    tracing::info!("listening on http://0.0.0.0:{port}");
    axum::serve(listener, app).await?;
    Ok(())
}

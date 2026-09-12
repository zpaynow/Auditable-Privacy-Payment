//! HTTP API. Every route is scoped to a chain: `/chains/{chain_id}/…`.
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{AppState, ChainCtx, verify::to_hex};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransferSubmit {
    /// "2x3" or "1x3"
    pub shape: String,
    /// 256-byte EVM proof, hex
    pub proof: String,
    pub nullifiers: Vec<String>,
    pub freezers: Vec<String>,
    pub commitments: Vec<String>,
    pub root: String,
    pub owner_memos: Vec<String>,
    pub audit_memos: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WithdrawSubmit {
    pub proof: String,
    pub asset: u64,
    /// u128 as decimal string
    pub amount: String,
    pub nullifier: String,
    pub freezer: String,
    pub root: String,
    pub recipient: String,
    /// u128 as decimal string, must be >= the quoted withdraw fee
    pub fee: String,
}

#[derive(Serialize)]
pub struct Info {
    pub chain_id: u64,
    pub app: String,
    pub operator: String,
    /// aggregator payment key, 64 bytes x||y (LE) hex — the owner of fee notes
    pub aggregator_pk: String,
    pub fee_asset: u64,
    pub transfer_fee: String,
    pub withdraw_fee: String,
    pub batch_max: usize,
    pub batch_interval_secs: u64,
    pub pending: i64,
}

#[derive(Serialize)]
struct ChainsView {
    aggregator_pk: String,
    chains: Vec<ChainSummary>,
}

#[derive(Serialize)]
struct ChainSummary {
    chain_id: u64,
    app: String,
    operator: String,
}

#[derive(Serialize)]
struct Submitted {
    id: i64,
    status: &'static str,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}
type Err = (StatusCode, Json<ApiError>);

fn bad(msg: impl ToString) -> Err {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: msg.to_string() }))
}

fn internal(msg: impl ToString) -> Err {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: msg.to_string() }))
}

fn not_found(msg: &str) -> Err {
    (StatusCode::NOT_FOUND, Json(ApiError { error: msg.to_string() }))
}

fn chain_of(s: &AppState, id: u64) -> Result<Arc<ChainCtx>, Err> {
    s.chain(id).ok_or_else(|| not_found(&format!("chain {id} is not served by this aggregator")))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/chains", get(chains))
        .route("/chains/{chain_id}/info", get(info))
        .route("/chains/{chain_id}/tx/transfer", post(submit_transfer))
        .route("/chains/{chain_id}/tx/withdraw", post(submit_withdraw))
        .route("/chains/{chain_id}/tx/{id}", get(tx_status))
        .route("/chains/{chain_id}/batch/{id}", get(batch_status))
        .route("/chains/{chain_id}/batch/{id}/proof/{group}", get(batch_proof))
        .with_state(state)
}

async fn chains(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    Json(ChainsView {
        aggregator_pk: s.aggregator_pk_hex.clone(),
        chains: s
            .chains
            .values()
            .map(|c| ChainSummary { chain_id: c.cfg.chain_id, app: c.cfg.app.clone(), operator: format!("{:?}", c.chain.operator) })
            .collect(),
    })
}

async fn info(State(s): State<Arc<AppState>>, Path(chain_id): Path<u64>) -> Result<Json<Info>, Err> {
    let c = chain_of(&s, chain_id)?;
    let pending = s.db.count_pending(chain_id).unwrap_or(0);
    Ok(Json(Info {
        chain_id,
        app: c.cfg.app.clone(),
        operator: format!("{:?}", c.chain.operator),
        aggregator_pk: s.aggregator_pk_hex.clone(),
        fee_asset: c.cfg.fee_asset,
        transfer_fee: c.cfg.transfer_fee.to_string(),
        withdraw_fee: c.cfg.withdraw_fee.to_string(),
        batch_max: c.cfg.batch_max,
        batch_interval_secs: c.cfg.batch_interval_secs,
        pending,
    }))
}

async fn submit_transfer(
    State(s): State<Arc<AppState>>,
    Path(chain_id): Path<u64>,
    Json(t): Json<TransferSubmit>,
) -> Result<Json<Submitted>, Err> {
    let c = chain_of(&s, chain_id)?;
    let checked = c.verifier.check_transfer(&t, c.cfg.fee_asset, c.cfg.transfer_fee).map_err(bad)?;
    c.precheck(&checked, &t.freezers).await.map_err(bad)?;
    let payload = serde_json::to_string(&t).map_err(internal)?;
    let id = s.db.insert_tx(chain_id, "transfer", &payload, &checked.nullifiers).map_err(bad)?;
    tracing::info!(chain_id, id, shape = %t.shape, "queued transfer");
    c.nudge.notify_one();
    Ok(Json(Submitted { id, status: "pending" }))
}

async fn submit_withdraw(
    State(s): State<Arc<AppState>>,
    Path(chain_id): Path<u64>,
    Json(w): Json<WithdrawSubmit>,
) -> Result<Json<Submitted>, Err> {
    let c = chain_of(&s, chain_id)?;
    let checked = c.verifier.check_withdraw(&w, c.cfg.withdraw_fee).map_err(bad)?;
    c.precheck(&checked, std::slice::from_ref(&w.freezer)).await.map_err(bad)?;
    let payload = serde_json::to_string(&w).map_err(internal)?;
    let id = s.db.insert_tx(chain_id, "withdraw", &payload, &checked.nullifiers).map_err(bad)?;
    tracing::info!(chain_id, id, "queued withdraw");
    c.nudge.notify_one();
    Ok(Json(Submitted { id, status: "pending" }))
}

async fn tx_status(State(s): State<Arc<AppState>>, Path((chain_id, id)): Path<(u64, i64)>) -> Result<impl IntoResponse, Err> {
    chain_of(&s, chain_id)?;
    match s.db.get_tx(chain_id, id) {
        Ok(Some(row)) => Ok(Json(row)),
        Ok(None) => Err(not_found("unknown tx")),
        Err(e) => Err(internal(e)),
    }
}

#[derive(Serialize)]
struct BatchView {
    #[serde(flatten)]
    batch: crate::db::BatchRow,
    /// per circuit group: number of folded proofs and the SnarkFold proof size
    aggregated: Vec<AggView>,
}

#[derive(Serialize)]
struct AggView {
    group: String,
    proofs: i64,
    bytes: usize,
    url: String,
}

async fn batch_status(State(s): State<Arc<AppState>>, Path((chain_id, id)): Path<(u64, i64)>) -> Result<impl IntoResponse, Err> {
    chain_of(&s, chain_id)?;
    let batch = match s.db.get_batch(chain_id, id) {
        Ok(Some(b)) => b,
        Ok(None) => return Err(not_found("unknown batch")),
        Err(e) => return Err(internal(e)),
    };
    let aggregated = s
        .db
        .agg_proofs(id)
        .map_err(internal)?
        .into_iter()
        .map(|(group, proofs, bytes)| AggView {
            url: format!("/chains/{chain_id}/batch/{id}/proof/{group}"),
            group,
            proofs,
            bytes: bytes.len(),
        })
        .collect();
    Ok(Json(BatchView { batch, aggregated }))
}

async fn batch_proof(
    State(s): State<Arc<AppState>>,
    Path((chain_id, id, group)): Path<(u64, i64, String)>,
) -> Result<impl IntoResponse, Err> {
    chain_of(&s, chain_id)?;
    if s.db.get_batch(chain_id, id).map_err(internal)?.is_none() {
        return Err(not_found("unknown batch"));
    }
    let rows = s.db.agg_proofs(id).map_err(internal)?;
    match rows.into_iter().find(|(g, _, _)| *g == group) {
        Some((_, _, bytes)) => Ok(([("content-type", "application/octet-stream")], bytes)),
        None => Err(not_found("no aggregated proof for that group")),
    }
}

#[allow(dead_code)]
pub fn hex(b: &[u8]) -> String {
    to_hex(b)
}

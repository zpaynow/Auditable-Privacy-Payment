//! HTTP API.
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{AppState, verify::to_hex};

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
struct Submitted {
    id: i64,
    status: &'static str,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn bad(msg: impl ToString) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: msg.to_string() }))
}

fn internal(msg: impl ToString) -> (StatusCode, Json<ApiError>) {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: msg.to_string() }))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/info", get(info))
        .route("/tx/transfer", post(submit_transfer))
        .route("/tx/withdraw", post(submit_withdraw))
        .route("/tx/{id}", get(tx_status))
        .route("/batch/{id}", get(batch_status))
        .route("/batch/{id}/proof/{group}", get(batch_proof))
        .with_state(state)
}

async fn info(State(s): State<Arc<AppState>>) -> impl IntoResponse {
    let pending = s.db.count_pending().unwrap_or(0);
    Json(Info {
        chain_id: s.chain.chain_id,
        app: format!("{:?}", s.chain.app),
        operator: format!("{:?}", s.chain.operator),
        aggregator_pk: s.aggregator_pk_hex.clone(),
        fee_asset: s.cfg.fee_asset,
        transfer_fee: s.cfg.transfer_fee.to_string(),
        withdraw_fee: s.cfg.withdraw_fee.to_string(),
        batch_max: s.cfg.batch_max,
        batch_interval_secs: s.cfg.batch_interval_secs,
        pending,
    })
}

async fn submit_transfer(State(s): State<Arc<AppState>>, Json(t): Json<TransferSubmit>) -> impl IntoResponse {
    let checked = match s.verifier.check_transfer(&t, s.cfg.fee_asset, s.cfg.transfer_fee) {
        Ok(c) => c,
        Err(e) => return Err(bad(e)),
    };
    if let Err(e) = s.precheck(&checked, &t.freezers).await {
        return Err(bad(e));
    }
    let payload = serde_json::to_string(&t).map_err(internal)?;
    let id = s.db.insert_tx("transfer", &payload, &checked.nullifiers).map_err(bad)?;
    tracing::info!(id, shape = %t.shape, "queued transfer");
    s.nudge.notify_one();
    Ok(Json(Submitted { id, status: "pending" }))
}

async fn submit_withdraw(State(s): State<Arc<AppState>>, Json(w): Json<WithdrawSubmit>) -> impl IntoResponse {
    let checked = match s.verifier.check_withdraw(&w, s.cfg.withdraw_fee) {
        Ok(c) => c,
        Err(e) => return Err(bad(e)),
    };
    if let Err(e) = s.precheck(&checked, std::slice::from_ref(&w.freezer)).await {
        return Err(bad(e));
    }
    let payload = serde_json::to_string(&w).map_err(internal)?;
    let id = s.db.insert_tx("withdraw", &payload, &checked.nullifiers).map_err(bad)?;
    tracing::info!(id, "queued withdraw");
    s.nudge.notify_one();
    Ok(Json(Submitted { id, status: "pending" }))
}

async fn tx_status(State(s): State<Arc<AppState>>, Path(id): Path<i64>) -> impl IntoResponse {
    match s.db.get_tx(id) {
        Ok(Some(row)) => Ok(Json(row)),
        Ok(None) => Err((StatusCode::NOT_FOUND, Json(ApiError { error: "unknown tx".into() }))),
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

async fn batch_status(State(s): State<Arc<AppState>>, Path(id): Path<i64>) -> impl IntoResponse {
    let batch = match s.db.get_batch(id) {
        Ok(Some(b)) => b,
        Ok(None) => return Err((StatusCode::NOT_FOUND, Json(ApiError { error: "unknown batch".into() }))),
        Err(e) => return Err(internal(e)),
    };
    let aggregated = s
        .db
        .agg_proofs(id)
        .map_err(internal)?
        .into_iter()
        .map(|(group, proofs, bytes)| AggView {
            url: format!("/batch/{id}/proof/{group}"),
            group,
            proofs,
            bytes: bytes.len(),
        })
        .collect();
    Ok(Json(BatchView { batch, aggregated }))
}

async fn batch_proof(State(s): State<Arc<AppState>>, Path((id, group)): Path<(i64, String)>) -> impl IntoResponse {
    let rows = s.db.agg_proofs(id).map_err(internal)?;
    match rows.into_iter().find(|(g, _, _)| *g == group) {
        Some((_, _, bytes)) => Ok(([("content-type", "application/octet-stream")], bytes)),
        None => Err((StatusCode::NOT_FOUND, Json(ApiError { error: "no aggregated proof for that group".into() }))),
    }
}

#[allow(dead_code)]
pub fn hex(b: &[u8]) -> String {
    to_hex(b)
}

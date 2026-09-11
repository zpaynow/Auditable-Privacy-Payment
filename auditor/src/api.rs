//! HTTP API. Note queries are authenticated with a Schnorr signature by the payment key, so
//! only the holder of a key can list its notes; nullifiers and the tree are public data.
use crate::AppState;
use app_payment::{PublicKey, verify_signature};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalDeserialize;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize)]
struct ApiError {
    error: String,
}
type Err = (StatusCode, Json<ApiError>);

fn err(code: StatusCode, msg: impl ToString) -> Err {
    (code, Json(ApiError { error: msg.to_string() }))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/auth/message", get(auth_message))
        .route("/notes", get(notes))
        .route("/proof/{index}", get(proof))
        .route("/nullifiers/check", post(nullifiers_check))
        .route("/audit/notes", get(audit_notes))
        .with_state(state)
}

// ------------------------------------------------------------------ auth
/// The client signs `auth_string(chain, app, ts)` with its payment key and sends
/// `X-APP-Auth: <pk 64B hex>.<ts>.<sig 64B hex>`.
pub fn auth_string(chain_id: u64, app: &str, ts: u64) -> String {
    format!("APP-auditor-auth-v1\n{chain_id}\n{}\n{ts}", app.to_lowercase())
}

const AUTH_WINDOW_SECS: u64 = 300;

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Returns the authenticated owner key as 64-byte x||y LE hex.
fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, Err> {
    let h = headers
        .get("x-app-auth")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-APP-Auth header"))?;
    let parts: Vec<&str> = h.split('.').collect();
    if parts.len() != 3 {
        return Err(err(StatusCode::UNAUTHORIZED, "malformed X-APP-Auth"));
    }
    let pk_bytes = hex::decode(parts[0].trim_start_matches("0x")).map_err(|_| err(StatusCode::UNAUTHORIZED, "bad pk hex"))?;
    let ts: u64 = parts[1].parse().map_err(|_| err(StatusCode::UNAUTHORIZED, "bad timestamp"))?;
    let sig = hex::decode(parts[2].trim_start_matches("0x")).map_err(|_| err(StatusCode::UNAUTHORIZED, "bad sig hex"))?;
    if pk_bytes.len() != 64 {
        return Err(err(StatusCode::UNAUTHORIZED, "pk must be 64 bytes"));
    }
    let n = now();
    if ts + AUTH_WINDOW_SECS < n || ts > n + AUTH_WINDOW_SECS {
        return Err(err(StatusCode::UNAUTHORIZED, "timestamp outside the allowed window"));
    }
    let x = Fr::deserialize_compressed(&pk_bytes[..32]).map_err(|_| err(StatusCode::UNAUTHORIZED, "bad pk"))?;
    let y = Fr::deserialize_compressed(&pk_bytes[32..]).map_err(|_| err(StatusCode::UNAUTHORIZED, "bad pk"))?;
    let pk = PublicKey::new_unchecked(x, y);
    let msg = auth_string(state.chain_id, &format!("{:?}", state.cfg.app), ts);
    if !verify_signature(&pk, msg.as_bytes(), &sig) {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid signature"));
    }
    Ok(format!("0x{}", hex::encode(pk_bytes)))
}

fn admin(state: &AppState, headers: &HeaderMap) -> Result<(), Err> {
    let Some(expected) = state.cfg.admin_token.as_deref().filter(|t| !t.is_empty()) else {
        return Err(err(StatusCode::FORBIDDEN, "admin endpoints disabled (set ADMIN_TOKEN)"));
    };
    let got = headers.get("x-admin-token").and_then(|v| v.to_str().ok()).unwrap_or("");
    if got != expected {
        return Err(err(StatusCode::FORBIDDEN, "bad admin token"));
    }
    Ok(())
}

// ------------------------------------------------------------ handlers
#[derive(Serialize)]
struct Status {
    chain_id: u64,
    app: String,
    indexed_block: Option<u64>,
    notes: u32,
    nullifiers: u64,
    root: String,
    tree_version: u32,
}

async fn status(State(s): State<Arc<AppState>>) -> Result<Json<Status>, Err> {
    let (root, version) = {
        let t = s.tree.lock().unwrap();
        (t.get_root().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))?, t.get_version())
    };
    Ok(Json(Status {
        chain_id: s.chain_id,
        app: format!("{:?}", s.cfg.app),
        indexed_block: s.db.indexed_block().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?,
        notes: s.db.count_notes().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?,
        nullifiers: s.db.count_nullifiers().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?,
        root: format!("0x{}", hex::encode(root.into_bigint().to_bytes_be())),
        tree_version: version,
    }))
}

#[derive(Serialize)]
struct AuthMessage {
    ts: u64,
    message: String,
}

/// Convenience: the exact string to sign for the current time.
async fn auth_message(State(s): State<Arc<AppState>>) -> Json<AuthMessage> {
    let ts = now();
    Json(AuthMessage { ts, message: auth_string(s.chain_id, &format!("{:?}", s.cfg.app), ts) })
}

async fn notes(State(s): State<Arc<AppState>>, headers: HeaderMap) -> Result<impl IntoResponse, Err> {
    let owner = authenticate(&s, &headers)?;
    let notes = s.db.notes_of(&owner).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(notes))
}

#[derive(Serialize)]
struct ProofView {
    index: u32,
    /// MTProof bytes (see app-payment `MTProof::to_bytes`), hex
    proof: String,
    /// root the proof opens to, EVM bytes32
    root: String,
    version: u32,
    count: u32,
}

async fn proof(State(s): State<Arc<AppState>>, headers: HeaderMap, Path(index): Path<u32>) -> Result<Json<ProofView>, Err> {
    let _owner = authenticate(&s, &headers)?;
    let t = s.tree.lock().unwrap();
    if index >= t.get_count() {
        return Err(err(StatusCode::NOT_FOUND, "no such leaf yet"));
    }
    let p = t.generate_proof(index).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))?;
    Ok(Json(ProofView {
        index,
        proof: format!("0x{}", hex::encode(p.to_bytes())),
        root: format!("0x{}", hex::encode(p.root.into_bigint().to_bytes_be())),
        version: p.version,
        count: t.get_count(),
    }))
}

#[derive(Deserialize)]
struct CheckReq {
    nullifiers: Vec<String>,
}

#[derive(Serialize)]
struct CheckResp {
    spent: Vec<bool>,
}

async fn nullifiers_check(State(s): State<Arc<AppState>>, Json(req): Json<CheckReq>) -> Result<Json<CheckResp>, Err> {
    if req.nullifiers.len() > 1000 {
        return Err(err(StatusCode::BAD_REQUEST, "at most 1000 nullifiers per request"));
    }
    let mut spent = Vec::with_capacity(req.nullifiers.len());
    for n in &req.nullifiers {
        spent.push(s.db.nullifier_spent(&n.to_lowercase()).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?);
    }
    Ok(Json(CheckResp { spent }))
}

#[derive(Deserialize)]
struct Page {
    offset: Option<u32>,
    limit: Option<u32>,
}

async fn audit_notes(State(s): State<Arc<AppState>>, headers: HeaderMap, Query(p): Query<Page>) -> Result<impl IntoResponse, Err> {
    admin(&s, &headers)?;
    let notes = s
        .db
        .all_notes(p.offset.unwrap_or(0), p.limit.unwrap_or(200).min(1000))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(notes))
}

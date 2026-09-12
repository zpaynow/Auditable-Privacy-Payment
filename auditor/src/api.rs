//! HTTP API, scoped per chain: `/chains/{chain_id}/…`. Note queries are authenticated with a
//! Schnorr signature by the payment key, so only the holder of a key can list its notes;
//! nullifiers and the tree are public data.
use crate::{AppState, ChainCtx};
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

fn chain_of(s: &AppState, id: u64) -> Result<Arc<ChainCtx>, Err> {
    s.chain(id).ok_or_else(|| err(StatusCode::NOT_FOUND, format!("chain {id} is not served by this auditor")))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/chains", get(chains))
        .route("/chains/{chain_id}/status", get(status))
        .route("/chains/{chain_id}/auth/message", get(auth_message))
        .route("/chains/{chain_id}/notes", get(notes))
        .route("/chains/{chain_id}/proof/{index}", get(proof))
        .route("/chains/{chain_id}/nullifiers/check", post(nullifiers_check))
        .route("/chains/{chain_id}/audit/notes", get(audit_notes))
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
fn authenticate(c: &ChainCtx, headers: &HeaderMap) -> Result<String, Err> {
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
    let msg = auth_string(c.cfg.chain_id, &format!("{:?}", c.app), ts);
    if !verify_signature(&pk, msg.as_bytes(), &sig) {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid signature"));
    }
    Ok(format!("0x{}", hex::encode(pk_bytes)))
}

fn admin(state: &AppState, headers: &HeaderMap) -> Result<(), Err> {
    let Some(expected) = state.admin_token.as_deref() else {
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
struct ChainSummary {
    chain_id: u64,
    app: String,
    indexed_block: Option<u64>,
    notes: u32,
}

async fn chains(State(s): State<Arc<AppState>>) -> Json<Vec<ChainSummary>> {
    Json(
        s.chains
            .values()
            .map(|c| ChainSummary {
                chain_id: c.cfg.chain_id,
                app: format!("{:?}", c.app),
                indexed_block: s.db.indexed_block(c.cfg.chain_id).ok().flatten(),
                notes: s.db.count_notes(c.cfg.chain_id).unwrap_or(0),
            })
            .collect(),
    )
}

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

async fn status(State(s): State<Arc<AppState>>, Path(chain_id): Path<u64>) -> Result<Json<Status>, Err> {
    let c = chain_of(&s, chain_id)?;
    let (root, version) = {
        let t = c.tree.lock().unwrap();
        (t.get_root().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:?}")))?, t.get_version())
    };
    Ok(Json(Status {
        chain_id,
        app: format!("{:?}", c.app),
        indexed_block: s.db.indexed_block(chain_id).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?,
        notes: s.db.count_notes(chain_id).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?,
        nullifiers: s.db.count_nullifiers(chain_id).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?,
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
async fn auth_message(State(s): State<Arc<AppState>>, Path(chain_id): Path<u64>) -> Result<Json<AuthMessage>, Err> {
    let c = chain_of(&s, chain_id)?;
    let ts = now();
    Ok(Json(AuthMessage { ts, message: auth_string(chain_id, &format!("{:?}", c.app), ts) }))
}

async fn notes(State(s): State<Arc<AppState>>, Path(chain_id): Path<u64>, headers: HeaderMap) -> Result<impl IntoResponse, Err> {
    let c = chain_of(&s, chain_id)?;
    let owner = authenticate(&c, &headers)?;
    let notes = s.db.notes_of(chain_id, &owner).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
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

async fn proof(
    State(s): State<Arc<AppState>>,
    Path((chain_id, index)): Path<(u64, u32)>,
    headers: HeaderMap,
) -> Result<Json<ProofView>, Err> {
    let c = chain_of(&s, chain_id)?;
    let _owner = authenticate(&c, &headers)?;
    let t = c.tree.lock().unwrap();
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

async fn nullifiers_check(
    State(s): State<Arc<AppState>>,
    Path(chain_id): Path<u64>,
    Json(req): Json<CheckReq>,
) -> Result<Json<CheckResp>, Err> {
    chain_of(&s, chain_id)?;
    if req.nullifiers.len() > 1000 {
        return Err(err(StatusCode::BAD_REQUEST, "at most 1000 nullifiers per request"));
    }
    let mut spent = Vec::with_capacity(req.nullifiers.len());
    for n in &req.nullifiers {
        spent.push(s.db.nullifier_spent(chain_id, &n.to_lowercase()).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?);
    }
    Ok(Json(CheckResp { spent }))
}

#[derive(Deserialize)]
struct Page {
    offset: Option<u32>,
    limit: Option<u32>,
}

async fn audit_notes(
    State(s): State<Arc<AppState>>,
    Path(chain_id): Path<u64>,
    headers: HeaderMap,
    Query(p): Query<Page>,
) -> Result<impl IntoResponse, Err> {
    chain_of(&s, chain_id)?;
    admin(&s, &headers)?;
    let notes = s
        .db
        .all_notes(chain_id, p.offset.unwrap_or(0), p.limit.unwrap_or(200).min(1000))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(notes))
}

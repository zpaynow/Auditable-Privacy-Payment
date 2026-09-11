//! Batch loop: collect pending txs, re-check them against the chain, submit, fold.
use crate::{
    AppState,
    api::{TransferSubmit, WithdrawSubmit},
    chain::Chain,
    verify::{Checked, Group},
};
use ark_serialize::CanonicalSerialize;
use snarkfold::{Aggregator, GrothVerifyingKey, Instance, Proof as SfProof};
use std::{collections::HashMap, sync::Arc, time::Duration};

pub async fn run(state: Arc<AppState>) {
    let interval = Duration::from_secs(state.cfg.batch_interval_secs);
    loop {
        // wake up on the interval, or early when the queue reaches batch_max
        let _ = tokio::time::timeout(interval, state.nudge.notified()).await;
        let pending = state.db.count_pending().unwrap_or(0) as usize;
        if pending == 0 {
            continue;
        }
        if pending < state.cfg.batch_max {
            // not full: wait for the interval to elapse (the notify may have woken us early)
            tokio::time::sleep(interval).await;
        }
        if let Err(e) = settle(&state).await {
            tracing::error!("batch failed: {e:#}");
        }
    }
}

async fn settle(state: &Arc<AppState>) -> anyhow::Result<()> {
    let rows = state.db.pending(state.cfg.batch_max)?;
    if rows.is_empty() {
        return Ok(());
    }

    let mut transfers = vec![];
    let mut withdraws = vec![];
    let mut ids = vec![];
    let mut folds: Vec<(Group, Checked)> = vec![];

    for (id, kind, payload) in rows {
        let checked = match kind.as_str() {
            "transfer" => {
                let t: TransferSubmit = serde_json::from_str(&payload)?;
                match state.verifier.check_transfer(&t, state.cfg.fee_asset, state.cfg.transfer_fee) {
                    Ok(c) => match state.precheck(&c, &t.freezers).await {
                        Ok(()) => {
                            transfers.push(Chain::transfer_arg(&t)?);
                            c
                        }
                        Err(e) => {
                            state.db.fail_tx(id, &e.to_string())?;
                            continue;
                        }
                    },
                    Err(e) => {
                        state.db.fail_tx(id, &e.to_string())?;
                        continue;
                    }
                }
            }
            "withdraw" => {
                let w: WithdrawSubmit = serde_json::from_str(&payload)?;
                match state.verifier.check_withdraw(&w, state.cfg.withdraw_fee) {
                    Ok(c) => match state.precheck(&c, std::slice::from_ref(&w.freezer)).await {
                        Ok(()) => {
                            withdraws.push(Chain::withdraw_arg(&w)?);
                            c
                        }
                        Err(e) => {
                            state.db.fail_tx(id, &e.to_string())?;
                            continue;
                        }
                    },
                    Err(e) => {
                        state.db.fail_tx(id, &e.to_string())?;
                        continue;
                    }
                }
            }
            other => {
                state.db.fail_tx(id, &format!("unknown kind {other}"))?;
                continue;
            }
        };
        ids.push(id);
        folds.push((checked.group, checked));
    }
    if ids.is_empty() {
        return Ok(());
    }

    let batch_id = state.db.new_batch(transfers.len(), withdraws.len(), &ids)?;
    tracing::info!(batch_id, transfers = transfers.len(), withdraws = withdraws.len(), "submitting batch");

    match state.chain.submit_batch(transfers, withdraws).await {
        Ok((hash, true, gas)) => {
            let h = format!("{hash:?}");
            state.db.finish_batch(batch_id, true, Some(&h), None)?;
            tracing::info!(batch_id, tx = %h, gas, "batch confirmed");
            fold_and_store(state, batch_id, folds)?;
        }
        Ok((hash, false, gas)) => {
            let h = format!("{hash:?}");
            state.db.finish_batch(batch_id, false, Some(&h), Some("submitBatch reverted"))?;
            tracing::warn!(batch_id, tx = %h, gas, "batch reverted");
        }
        Err(e) => {
            state.db.finish_batch(batch_id, false, None, Some(&format!("{e:#}")))?;
            tracing::warn!(batch_id, "batch send failed: {e:#}");
        }
    }
    Ok(())
}

/// Fold the batch's proofs per circuit group with snarkfold and persist the aggregated proofs.
fn fold_and_store(state: &Arc<AppState>, batch_id: i64, folds: Vec<(Group, Checked)>) -> anyhow::Result<()> {
    let mut by_group: HashMap<Group, Vec<Checked>> = HashMap::new();
    for (g, c) in folds {
        by_group.entry(g).or_default().push(c);
    }
    for (g, txs) in by_group {
        let gvk = GrothVerifyingKey::from_ark_vk(state.verifier.vk(g));
        let mut agg = Aggregator::new(&gvk);
        for c in &txs {
            agg.push(&Instance { public_inputs: c.publics.clone() }, &SfProof::from(c.proof.clone()))
                .map_err(|e| anyhow::anyhow!("fold: {e}"))?;
        }
        let proof = agg.finish();
        debug_assert!(snarkfold::verify_aggregated(&gvk, &proof).unwrap_or(false));
        let mut bytes = vec![];
        proof.serialize_compressed(&mut bytes)?;
        state.db.put_agg_proof(batch_id, g.key_name(), txs.len(), &bytes)?;
        tracing::info!(batch_id, group = g.key_name(), proofs = txs.len(), bytes = bytes.len(), "aggregated proof stored");
    }
    Ok(())
}

//! Follows the APP contract's events, opens every audit memo, and maintains the commitment tree.
use crate::{ChainCtx, db::Note};
use alloy::{
    primitives::{B256, U256},
    providers::Provider,
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use anyhow::{Context, Result};
use app_payment::{Keypair, OpenCommitment, poseidon::poseidon_hash};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use std::{sync::Arc, time::Duration};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    APP,
    "abi/APP.json"
);

const CHUNK: u64 = 5_000;

fn be_hex(f: &Fr) -> String {
    format!("0x{}", hex::encode(f.into_bigint().to_bytes_be()))
}

fn u256_hex(v: U256) -> String {
    format!("0x{}", hex::encode(v.to_be_bytes::<32>()))
}

fn u256_to_fr(v: U256) -> Fr {
    Fr::from_be_bytes_mod_order(&v.to_be_bytes::<32>())
}

/// Open an audit memo: (owner pk as 64-byte x||y LE hex, asset, amount, freezer hex).
fn open_audit_memo(auditor: &Keypair, commitment: Fr, memo: &[u8]) -> Option<(String, u64, u128, String)> {
    let oc = OpenCommitment::audit_decrypt(auditor, &commitment, memo).ok()?;
    let mut pk = vec![];
    oc.owner.x.serialize_compressed(&mut pk).ok()?;
    oc.owner.y.serialize_compressed(&mut pk).ok()?;
    let freezer = poseidon_hash(&[commitment, oc.owner.x]);
    Some((format!("0x{}", hex::encode(pk)), oc.asset, oc.amount, be_hex(&freezer)))
}

pub async fn run(ctx: Arc<ChainCtx>) {
    loop {
        if let Err(e) = step(&ctx).await {
            tracing::warn!(chain_id = ctx.cfg.chain_id, "indexer: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(ctx.cfg.poll_secs)).await;
    }
}

async fn step(state: &Arc<ChainCtx>) -> Result<()> {
    let chain_id = state.cfg.chain_id;
    let head = state.provider.get_block_number().await.context("block number")?;
    let mut from = match state.db.indexed_block(chain_id)? {
        Some(b) => b + 1,
        None => state.cfg.deploy_block,
    };
    while from <= head {
        let to = (from + CHUNK - 1).min(head);
        let filter = Filter::new().address(state.app).from_block(from).to_block(to);
        let logs = state.provider.get_logs(&filter).await.context("get_logs")?;
        let mut new_leaves: Vec<Fr> = vec![];
        for log in logs {
            let block = log.block_number.unwrap_or(0);
            let tx = log.transaction_hash.map(|h: B256| format!("{h:?}")).unwrap_or_default();
            let Some(topic0) = log.topic0().copied() else { continue };
            if topic0 == APP::NewCommitment::SIGNATURE_HASH {
                let ev = APP::NewCommitment::decode_log(&log.inner).context("NewCommitment")?;
                let index: u32 = ev.index;
                let expected = state.db.count_notes(chain_id)?;
                if index != expected {
                    anyhow::bail!("commitment index gap: have {expected}, got {index}");
                }
                let comm_fr = u256_to_fr(ev.commitment);
                let (owner, asset, amount, freezer) =
                    open_audit_memo(&state.auditor, comm_fr, &ev.auditMemo).unwrap_or_else(|| {
                        tracing::warn!(index, "audit memo did not decrypt");
                        (String::new(), 0, 0, String::new())
                    });
                state.db.insert_note(&Note {
                    chain_id,
                    index,
                    commitment: u256_hex(ev.commitment),
                    owner_memo: format!("0x{}", hex::encode(&ev.ownerMemo)),
                    audit_memo: format!("0x{}", hex::encode(&ev.auditMemo)),
                    owner,
                    asset,
                    amount: amount.to_string(),
                    freezer,
                    frozen: false,
                    block,
                    tx_hash: tx,
                })?;
                new_leaves.push(comm_fr);
            } else if topic0 == APP::NewNullifier::SIGNATURE_HASH {
                let ev = APP::NewNullifier::decode_log(&log.inner).context("NewNullifier")?;
                state.db.insert_nullifier(chain_id, &u256_hex(ev.nullifier), block, &tx)?;
            } else if topic0 == APP::FrozenSet::SIGNATURE_HASH {
                let ev = APP::FrozenSet::decode_log(&log.inner).context("FrozenSet")?;
                state.db.set_frozen(chain_id, &u256_hex(ev.freezer), ev.isFrozen, block)?;
            }
        }
        if !new_leaves.is_empty() {
            let mut tree = state.tree.lock().unwrap();
            for leaf in &new_leaves {
                tree.add_leaf(*leaf).map_err(|e| anyhow::anyhow!("tree: {e:?}"))?;
            }
            tree.commit().map_err(|e| anyhow::anyhow!("tree commit: {e:?}"))?;
            tracing::info!(chain_id, leaves = new_leaves.len(), total = tree.get_count(), to, "indexed");
        }
        state.db.set_indexed_block(chain_id, to)?;
        from = to + 1;
    }
    Ok(())
}

//! Native verification of submitted proofs, exactly as the contract will see them.
use anyhow::{Context, Result, bail};
use app_payment::{Keypair, OpenCommitment, evm, transfer::{Proof, VerifyingKey}};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use std::{collections::HashMap, fs, path::Path};

use crate::api::{TransferSubmit, WithdrawSubmit};

pub const OWNER_MEMO_LEN: usize = 104;
pub const AUDIT_MEMO_LEN: usize = 160;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Transfer2x3,
    Transfer1x3,
    Withdraw,
}

impl Group {
    pub fn key_name(self) -> &'static str {
        match self {
            Group::Transfer2x3 => "transfer_2x3",
            Group::Transfer1x3 => "transfer_1x3",
            Group::Withdraw => "withdraw",
        }
    }
    pub fn from_shape(s: &str) -> Option<Group> {
        match s {
            "2x3" => Some(Group::Transfer2x3),
            "1x3" => Some(Group::Transfer1x3),
            _ => None,
        }
    }
    pub fn inputs(self) -> usize {
        match self {
            Group::Transfer2x3 => 2,
            Group::Transfer1x3 => 1,
            Group::Withdraw => 1,
        }
    }
}

pub struct Verifier {
    vks: HashMap<Group, VerifyingKey>,
    pub auditor_x: Fr,
    pub auditor_y: Fr,
    pub aggregator: Keypair,
}

/// A validated, contract-ready transaction.
#[derive(Clone, Debug)]
pub struct Checked {
    pub group: Group,
    pub proof: Proof,
    pub publics: Vec<Fr>,
    /// nullifiers as EVM hex (0x + 64)
    pub nullifiers: Vec<String>,
    pub root: [u8; 32],
}

pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim_start_matches("0x")).context("bad hex")?;
    if b.len() != 32 {
        bail!("expected 32 bytes, got {}", b.len());
    }
    Ok(b.try_into().unwrap())
}

pub fn hexbytes(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.trim_start_matches("0x")).context("bad hex")?)
}

pub fn to_hex(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn fr_be(s: &str) -> Result<Fr> {
    evm::fr_from_bytes32(&hex32(s)?).map_err(|e| anyhow::anyhow!("field element: {e:?}"))
}

/// The three little-endian ciphertext field elements of an audit memo.
fn audit_cts(memo: &[u8]) -> Result<[Fr; 3]> {
    if memo.len() != AUDIT_MEMO_LEN {
        bail!("audit memo must be {AUDIT_MEMO_LEN} bytes");
    }
    let mut out = [Fr::from(0u64); 3];
    for (i, chunk) in memo[64..].chunks(32).enumerate() {
        out[i] = Fr::deserialize_compressed(chunk).map_err(|_| anyhow::anyhow!("audit ciphertext"))?;
    }
    Ok(out)
}

impl Verifier {
    pub fn load(keys_dir: &Path, auditor_x: Fr, auditor_y: Fr, aggregator: Keypair) -> Result<Self> {
        let mut vks = HashMap::new();
        for g in [Group::Transfer2x3, Group::Transfer1x3, Group::Withdraw] {
            let bytes = fs::read(keys_dir.join(format!("{}.vk", g.key_name())))
                .with_context(|| format!("reading {}.vk", g.key_name()))?;
            let vk = VerifyingKey::deserialize_compressed(&bytes[..]).context("vk decode")?;
            vks.insert(g, vk);
        }
        Ok(Self { vks, auditor_x, auditor_y, aggregator })
    }

    pub fn vk(&self, g: Group) -> &VerifyingKey {
        &self.vks[&g]
    }

    fn groth16(&self, g: Group, proof: &Proof, publics: &[Fr]) -> Result<()> {
        let ok = Groth16::<Bn254>::verify(self.vk(g), publics, proof).context("verify")?;
        if !ok {
            bail!("invalid proof");
        }
        Ok(())
    }

    /// Validate a transfer submission: shapes, memo lengths, proof, and that output #2 is a
    /// fee note owned by the aggregator worth at least `min_fee` of `fee_asset`.
    pub fn check_transfer(&self, t: &TransferSubmit, fee_asset: u64, min_fee: u128) -> Result<Checked> {
        let group = Group::from_shape(&t.shape).context("shape must be 2x3 or 1x3")?;
        let n_in = group.inputs();
        if t.nullifiers.len() != n_in || t.freezers.len() != n_in {
            bail!("expected {n_in} nullifiers/freezers");
        }
        if t.commitments.len() != 3 || t.owner_memos.len() != 3 || t.audit_memos.len() != 3 {
            bail!("expected 3 outputs");
        }
        let proof = evm::proof_from_evm(&hexbytes(&t.proof)?).map_err(|e| anyhow::anyhow!("proof: {e:?}"))?;

        let mut publics = vec![];
        for n in &t.nullifiers {
            publics.push(fr_be(n)?);
        }
        for f in &t.freezers {
            publics.push(fr_be(f)?);
        }
        for c in &t.commitments {
            publics.push(fr_be(c)?);
        }
        publics.push(fr_be(&t.root)?);
        publics.push(self.auditor_x);
        publics.push(self.auditor_y);
        let mut memos = vec![];
        for (i, m) in t.audit_memos.iter().enumerate() {
            let bytes = hexbytes(m)?;
            let owner = hexbytes(&t.owner_memos[i])?;
            if owner.len() != OWNER_MEMO_LEN {
                bail!("owner memo must be {OWNER_MEMO_LEN} bytes");
            }
            publics.extend(audit_cts(&bytes)?);
            memos.push(owner);
        }
        self.groth16(group, &proof, &publics)?;

        // fee note: owner memo #2 must decrypt with our key to (fee_asset, >= min_fee)
        let fee_comm = Fr::deserialize_compressed(&hex32(&t.commitments[2]).map(|b| {
            let mut le = b;
            le.reverse();
            le
        })?[..])
        .map_err(|_| anyhow::anyhow!("fee commitment"))?;
        let note = OpenCommitment::memo_decrypt(&self.aggregator, &fee_comm, &memos[2])
            .map_err(|_| anyhow::anyhow!("output #2 is not a fee note for this aggregator"))?;
        if note.asset != fee_asset {
            bail!("fee note asset {} is not accepted (want {fee_asset})", note.asset);
        }
        if note.amount < min_fee {
            bail!("fee {} below quote {min_fee}", note.amount);
        }

        Ok(Checked {
            group,
            proof,
            publics,
            nullifiers: t.nullifiers.clone(),
            root: hex32(&t.root)?,
        })
    }

    pub fn check_withdraw(&self, w: &WithdrawSubmit, min_fee: u128) -> Result<Checked> {
        let proof = evm::proof_from_evm(&hexbytes(&w.proof)?).map_err(|e| anyhow::anyhow!("proof: {e:?}"))?;
        let amount: u128 = w.amount.parse().context("amount")?;
        let fee: u128 = w.fee.parse().context("fee")?;
        if fee < min_fee {
            bail!("fee {fee} below quote {min_fee}");
        }
        if fee > amount {
            bail!("fee exceeds amount");
        }
        let recipient = hexbytes(&w.recipient)?;
        if recipient.len() != 20 {
            bail!("recipient must be an address");
        }
        let publics = vec![
            Fr::from(w.asset),
            Fr::from(amount),
            fr_be(&w.nullifier)?,
            fr_be(&w.freezer)?,
            fr_be(&w.root)?,
            ark_ff::PrimeField::from_be_bytes_mod_order(&recipient),
            Fr::from(fee),
        ];
        self.groth16(Group::Withdraw, &proof, &publics)?;
        Ok(Checked {
            group: Group::Withdraw,
            proof,
            publics,
            nullifiers: vec![w.nullifier.clone()],
            root: hex32(&w.root)?,
        })
    }
}

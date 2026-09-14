//! Native verification of submitted proofs, exactly as the contract will see them.
use anyhow::{Context, Result, bail};
use app_payment::{
    Keypair, OpenCommitment, evm,
    ext::{address_to_fr, memos_hash},
    transfer::{Proof, VerifyingKey},
};
use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_serialize::CanonicalDeserialize;
use std::{collections::HashMap, fs, path::Path};

use crate::api::{TransferSubmit, WithdrawSubmit};

// Memo lengths come from app-payment so the aggregator, the circuits and the contract
// can never disagree about how the calldata hash is laid out.
pub use app_payment::ext::{AUDIT_MEMO_LEN, OWNER_MEMO_LEN};

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
    /// This operator's EVM address as a field element. Withdraw proofs are bound to the
    /// account that submits them, so a proof made for anyone else must be rejected here
    /// rather than reverting the whole batch on-chain.
    pub relayer: Fr,
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
    /// `relayer` is the 20-byte address this aggregator submits batches from.
    pub fn load(
        keys_dir: &Path,
        auditor_x: Fr,
        auditor_y: Fr,
        aggregator: Keypair,
        relayer: &[u8],
    ) -> Result<Self> {
        let relayer = address_to_fr(relayer).map_err(|e| anyhow::anyhow!("relayer address: {e:?}"))?;
        let mut vks = HashMap::new();
        for g in [Group::Transfer2x3, Group::Transfer1x3, Group::Withdraw] {
            let bytes = fs::read(keys_dir.join(format!("{}.vk", g.key_name())))
                .with_context(|| format!("reading {}.vk", g.key_name()))?;
            let vk = VerifyingKey::deserialize_compressed(&bytes[..]).context("vk decode")?;
            vks.insert(g, vk);
        }
        Ok(Self { vks, auditor_x, auditor_y, aggregator, relayer })
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
        let mut audit = vec![];
        for (i, m) in t.audit_memos.iter().enumerate() {
            let bytes = hexbytes(m)?;
            let owner = hexbytes(&t.owner_memos[i])?;
            if owner.len() != OWNER_MEMO_LEN {
                bail!("owner memo must be {OWNER_MEMO_LEN} bytes");
            }
            publics.extend(audit_cts(&bytes)?);
            memos.push(owner);
            audit.push(bytes);
        }
        // Binds the memo calldata the contract will hash, so a swapped owner memo cannot
        // ride along with a valid proof.
        publics.push(memos_hash(&memos, Some(&audit)));
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
            self.relayer,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Fixtures and keys come from `cargo run -p app-tools -- setup` + `-- e2e`, so these tests
    /// fail the moment a circuit gains or loses a public input and the aggregator is not updated.
    fn fixture() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../solidity/test/fixtures/e2e.json");
        let raw = fs::read_to_string(path).expect("run `cargo run -p app-tools -- e2e` first");
        serde_json::from_str(&raw).expect("e2e.json")
    }

    fn verifier(j: &Value, relayer: &str) -> Verifier {
        let keys = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../artifacts"));
        let kp = Keypair::from_secret_bytes(&hexbytes(s(&j["batch"]["aggregatorSecret"])).unwrap())
            .expect("aggregator secret");
        Verifier::load(
            keys,
            fr_be(s(&j["auditorX"])).unwrap(),
            fr_be(s(&j["auditorY"])).unwrap(),
            kp,
            &hexbytes(relayer).unwrap(),
        )
        .expect("load vks")
    }

    fn s(v: &Value) -> &str {
        v.as_str().unwrap()
    }

    fn list(v: &Value) -> Vec<String> {
        v.as_array().unwrap().iter().map(|x| s(x).to_string()).collect()
    }

    /// Fixtures store a proof as 8 EVM words; the wire format is one 256-byte blob.
    fn proof_hex(v: &Value) -> String {
        let mut out = String::from("0x");
        for w in v.as_array().unwrap() {
            out.push_str(s(w).trim_start_matches("0x"));
        }
        out
    }

    fn flip_first_byte(hex_str: &str) -> String {
        let mut b = hexbytes(hex_str).unwrap();
        b[0] ^= 1;
        to_hex(&b)
    }

    fn withdraw_submit(j: &Value) -> WithdrawSubmit {
        let w = &j["withdraw"];
        WithdrawSubmit {
            proof: proof_hex(&w["proof"]),
            asset: w["asset"].as_u64().unwrap(),
            amount: w["amount"].to_string(),
            nullifier: s(&w["nullifier"]).into(),
            freezer: s(&w["freezer"]).into(),
            root: s(&w["root"]).into(),
            recipient: s(&w["recipient"]).into(),
            fee: w["fee"].to_string(),
        }
    }

    fn transfer_submit(j: &Value) -> TransferSubmit {
        let t = &j["batch"]["transfers"][0];
        TransferSubmit {
            shape: if t["shape"].as_u64().unwrap() == 0 { "2x3".into() } else { "1x3".into() },
            proof: proof_hex(&t["proof"]),
            nullifiers: list(&t["nullifiers"]),
            freezers: list(&t["freezers"]),
            commitments: list(&t["commitments"]),
            root: s(&t["root"]).into(),
            owner_memos: list(&t["ownerMemos"]),
            audit_memos: list(&t["auditMemos"]),
        }
    }

    /// The public-input vector must have exactly the width the verifying key was generated for.
    fn expected_inputs(v: &Verifier, g: Group) -> usize {
        v.vk(g).gamma_abc_g1.len() - 1
    }

    #[test]
    fn withdraw_is_bound_to_the_submitting_operator() {
        let j = fixture();
        let w = withdraw_submit(&j);

        let ok = verifier(&j, s(&j["relayer"]));
        let checked = ok.check_withdraw(&w, 0).expect("proof made for this operator");
        assert_eq!(checked.publics.len(), expected_inputs(&ok, Group::Withdraw));

        // the fee is paid to msg.sender, so a proof made for someone else must not be batched
        let thief = verifier(&j, "0x000000000000000000000000000000000000dead");
        assert!(thief.check_withdraw(&w, 0).is_err(), "relayer must be bound");
    }

    #[test]
    fn transfer_is_bound_to_the_memo_calldata() {
        let j = fixture();
        let v = verifier(&j, s(&j["operator"]));
        let t = transfer_submit(&j);

        let checked = v.check_transfer(&t, 1, 1).expect("valid 2x3 transfer with a fee note");
        assert_eq!(checked.publics.len(), expected_inputs(&v, Group::Transfer2x3));

        let mut swapped = t.clone();
        swapped.owner_memos[0] = flip_first_byte(&swapped.owner_memos[0]);
        assert!(v.check_transfer(&swapped, 1, 1).is_err(), "owner memo must be bound");

        let mut swapped_audit = t.clone();
        swapped_audit.audit_memos[0] = flip_first_byte(&swapped_audit.audit_memos[0]);
        assert!(v.check_transfer(&swapped_audit, 1, 1).is_err(), "audit memo must be bound");
    }
}

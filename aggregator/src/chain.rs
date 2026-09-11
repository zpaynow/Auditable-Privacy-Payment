//! Chain access through alloy: reads for validation, submitBatch for settlement.
use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};
use anyhow::{Context, Result};

use crate::api::{TransferSubmit, WithdrawSubmit};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    APP,
    "abi/APP.json"
);

pub type Prov = alloy::providers::fillers::FillProvider<
    alloy::providers::fillers::JoinFill<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::fillers::WalletFiller<EthereumWallet>,
    >,
    alloy::providers::RootProvider,
>;

pub struct Chain {
    pub provider: Prov,
    pub app: Address,
    pub operator: Address,
    pub chain_id: u64,
}

fn u256(hex: &str) -> Result<U256> {
    Ok(U256::from_str_radix(hex.trim_start_matches("0x"), 16).context("u256")?)
}

fn bytes(hex: &str) -> Result<Bytes> {
    Ok(Bytes::from(hex::decode(hex.trim_start_matches("0x")).context("bytes")?))
}

fn words(hex: &str) -> Result<[U256; 8]> {
    let b = hex::decode(hex.trim_start_matches("0x")).context("proof")?;
    if b.len() != 256 {
        anyhow::bail!("proof must be 256 bytes");
    }
    let mut out = [U256::ZERO; 8];
    for i in 0..8 {
        out[i] = U256::from_be_slice(&b[i * 32..(i + 1) * 32]);
    }
    Ok(out)
}

impl Chain {
    pub async fn connect(rpc: &str, app: Address, operator_key: &str) -> Result<Self> {
        let signer: PrivateKeySigner = operator_key.parse().context("OPERATOR_KEY")?;
        let operator = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new().wallet(wallet).connect(rpc).await.context("rpc")?;
        let chain_id = provider.get_chain_id().await?;
        Ok(Self { provider, app, operator, chain_id })
    }

    fn contract(&self) -> APP::APPInstance<&Prov> {
        APP::new(self.app, &self.provider)
    }

    pub async fn auditor(&self) -> Result<(B256, B256)> {
        let c = self.contract();
        let x = c.auditorX().call().await?;
        let y = c.auditorY().call().await?;
        Ok((B256::from(x), B256::from(y)))
    }

    pub async fn is_operator(&self) -> Result<bool> {
        Ok(self.contract().operators(self.operator).call().await?)
    }

    pub async fn is_known_root(&self, root: &[u8; 32]) -> Result<bool> {
        Ok(self.contract().isKnownRoot(U256::from_be_bytes(*root)).call().await?)
    }

    pub async fn nullifier_used(&self, n: &str) -> Result<bool> {
        Ok(self.contract().nullifiers(u256(n)?).call().await?)
    }

    pub async fn is_frozen(&self, f: &str) -> Result<bool> {
        Ok(self.contract().frozen(u256(f)?).call().await?)
    }

    pub async fn last_root(&self) -> Result<B256> {
        Ok(B256::from(self.contract().getLastRoot().call().await?))
    }

    pub fn transfer_arg(t: &TransferSubmit) -> Result<APP::BatchTransfer> {
        let mut commitments = [U256::ZERO; 3];
        let mut owner_memos: [Bytes; 3] = Default::default();
        let mut audit_memos: [Bytes; 3] = Default::default();
        for i in 0..3 {
            commitments[i] = u256(&t.commitments[i])?;
            owner_memos[i] = bytes(&t.owner_memos[i])?;
            audit_memos[i] = bytes(&t.audit_memos[i])?;
        }
        Ok(APP::BatchTransfer {
            shape: if t.shape == "2x3" { 0 } else { 1 },
            nullifiers: t.nullifiers.iter().map(|n| u256(n)).collect::<Result<_>>()?,
            freezers: t.freezers.iter().map(|n| u256(n)).collect::<Result<_>>()?,
            commitments,
            root: u256(&t.root)?,
            ownerMemos: owner_memos,
            auditMemos: audit_memos,
            proof: words(&t.proof)?,
        })
    }

    pub fn withdraw_arg(w: &WithdrawSubmit) -> Result<APP::BatchWithdraw> {
        Ok(APP::BatchWithdraw {
            asset: w.asset,
            amount: w.amount.parse().context("amount")?,
            nullifier: u256(&w.nullifier)?,
            freezer: u256(&w.freezer)?,
            root: u256(&w.root)?,
            recipient: w.recipient.parse().context("recipient")?,
            fee: w.fee.parse().context("fee")?,
            proof: words(&w.proof)?,
        })
    }

    /// Send submitBatch and wait for the receipt. Returns (tx hash, success).
    pub async fn submit_batch(
        &self,
        transfers: Vec<APP::BatchTransfer>,
        withdraws: Vec<APP::BatchWithdraw>,
    ) -> Result<(B256, bool, u64)> {
        let c = self.contract();
        let pending = c.submitBatch(transfers, withdraws).send().await.context("send submitBatch")?;
        let hash = *pending.tx_hash();
        let receipt = pending.get_receipt().await.context("receipt")?;
        Ok((hash, receipt.status(), receipt.gas_used))
    }
}

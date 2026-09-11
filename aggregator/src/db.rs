//! SQLite persistence: submitted transactions, batches, aggregated proofs.
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct TxRow {
    pub id: i64,
    pub kind: String,
    pub status: String,
    pub batch_id: Option<i64>,
    pub tx_hash: Option<String>,
    pub error: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchRow {
    pub id: i64,
    pub status: String,
    pub tx_hash: Option<String>,
    pub transfers: i64,
    pub withdraws: i64,
    pub error: Option<String>,
    pub created_at: i64,
}

pub struct Db(Mutex<Connection>);

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let c = Connection::open(path)?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS txs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                batch_id INTEGER,
                tx_hash TEXT,
                error TEXT,
                created_at INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS txs_status ON txs(status);
             CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier TEXT PRIMARY KEY,
                tx_id INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL,
                tx_hash TEXT,
                transfers INTEGER NOT NULL,
                withdraws INTEGER NOT NULL,
                error TEXT,
                created_at INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS agg_proofs (
                batch_id INTEGER NOT NULL,
                grp TEXT NOT NULL,
                count INTEGER NOT NULL,
                proof BLOB NOT NULL,
                PRIMARY KEY (batch_id, grp)
             );",
        )?;
        Ok(Db(Mutex::new(c)))
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Insert a pending tx and reserve its nullifiers. Fails if a nullifier is already queued.
    pub fn insert_tx(&self, kind: &str, payload: &str, nullifiers: &[String]) -> Result<i64> {
        let c = self.0.lock().unwrap();
        let tx = c.unchecked_transaction()?;
        for n in nullifiers {
            let used: Option<i64> = tx
                .query_row(
                    "SELECT t.id FROM nullifiers n JOIN txs t ON t.id = n.tx_id WHERE n.nullifier = ?1 AND t.status IN ('pending','submitted','confirmed')",
                    params![n],
                    |r| r.get(0),
                )
                .optional()?;
            if used.is_some() {
                anyhow::bail!("nullifier already queued or spent: {n}");
            }
        }
        tx.execute(
            "INSERT INTO txs (kind, payload, status, created_at) VALUES (?1, ?2, 'pending', ?3)",
            params![kind, payload, Self::now()],
        )?;
        let id = tx.last_insert_rowid();
        for n in nullifiers {
            tx.execute("INSERT OR REPLACE INTO nullifiers (nullifier, tx_id) VALUES (?1, ?2)", params![n, id])?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn get_tx(&self, id: i64) -> Result<Option<TxRow>> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row(
            "SELECT id, kind, status, batch_id, tx_hash, error, created_at FROM txs WHERE id = ?1",
            params![id],
            |r| {
                Ok(TxRow {
                    id: r.get(0)?,
                    kind: r.get(1)?,
                    status: r.get(2)?,
                    batch_id: r.get(3)?,
                    tx_hash: r.get(4)?,
                    error: r.get(5)?,
                    created_at: r.get(6)?,
                })
            },
        )
        .optional()?)
    }

    /// (id, kind, payload) of pending txs, oldest first.
    pub fn pending(&self, limit: usize) -> Result<Vec<(i64, String, String)>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare("SELECT id, kind, payload FROM txs WHERE status = 'pending' ORDER BY id LIMIT ?1")?;
        let rows = st
            .query_map(params![limit as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn count_pending(&self) -> Result<i64> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row("SELECT COUNT(*) FROM txs WHERE status = 'pending'", [], |r| r.get(0))?)
    }

    pub fn fail_tx(&self, id: i64, error: &str) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute("UPDATE txs SET status = 'failed', error = ?2 WHERE id = ?1", params![id, error])?;
        Ok(())
    }

    pub fn new_batch(&self, transfers: usize, withdraws: usize, tx_ids: &[i64]) -> Result<i64> {
        let c = self.0.lock().unwrap();
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO batches (status, transfers, withdraws, created_at) VALUES ('submitted', ?1, ?2, ?3)",
            params![transfers as i64, withdraws as i64, Self::now()],
        )?;
        let id = tx.last_insert_rowid();
        for t in tx_ids {
            tx.execute("UPDATE txs SET status = 'submitted', batch_id = ?2 WHERE id = ?1", params![t, id])?;
        }
        tx.commit()?;
        Ok(id)
    }

    pub fn finish_batch(&self, id: i64, ok: bool, tx_hash: Option<&str>, error: Option<&str>) -> Result<()> {
        let c = self.0.lock().unwrap();
        let status = if ok { "confirmed" } else { "failed" };
        c.execute(
            "UPDATE batches SET status = ?2, tx_hash = ?3, error = ?4 WHERE id = ?1",
            params![id, status, tx_hash, error],
        )?;
        c.execute(
            "UPDATE txs SET status = ?2, tx_hash = ?3, error = ?4 WHERE batch_id = ?1",
            params![id, status, tx_hash, error],
        )?;
        Ok(())
    }

    pub fn get_batch(&self, id: i64) -> Result<Option<BatchRow>> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row(
            "SELECT id, status, tx_hash, transfers, withdraws, error, created_at FROM batches WHERE id = ?1",
            params![id],
            |r| {
                Ok(BatchRow {
                    id: r.get(0)?,
                    status: r.get(1)?,
                    tx_hash: r.get(2)?,
                    transfers: r.get(3)?,
                    withdraws: r.get(4)?,
                    error: r.get(5)?,
                    created_at: r.get(6)?,
                })
            },
        )
        .optional()?)
    }

    pub fn put_agg_proof(&self, batch_id: i64, grp: &str, count: usize, proof: &[u8]) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO agg_proofs (batch_id, grp, count, proof) VALUES (?1, ?2, ?3, ?4)",
            params![batch_id, grp, count as i64, proof],
        )?;
        Ok(())
    }

    /// (group, count, proof bytes)
    pub fn agg_proofs(&self, batch_id: i64) -> Result<Vec<(String, i64, Vec<u8>)>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare("SELECT grp, count, proof FROM agg_proofs WHERE batch_id = ?1 ORDER BY grp")?;
        let rows = st
            .query_map(params![batch_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

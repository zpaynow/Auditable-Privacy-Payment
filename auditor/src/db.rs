//! SQLite index of the pool: every note (opened with the auditor key), nullifiers, freezes.
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct Note {
    pub chain_id: u64,
    pub index: u32,
    pub commitment: String, // 0x bytes32 BE
    pub owner_memo: String, // 0x hex
    pub audit_memo: String, // 0x hex
    /// 64-byte x||y LE hex of the owner's payment key (empty if the memo did not decrypt)
    pub owner: String,
    pub asset: u64,
    pub amount: String, // u128 decimal
    pub freezer: String, // 0x bytes32 BE
    pub frozen: bool,
    pub block: u64,
    pub tx_hash: String,
}

pub struct Db(Mutex<Connection>);

impl Db {
    pub fn open(path: &str) -> Result<Self> {
        let c = Connection::open(path)?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS meta (chain_id INTEGER NOT NULL, k TEXT NOT NULL, v TEXT NOT NULL, PRIMARY KEY (chain_id, k));
             CREATE TABLE IF NOT EXISTS notes (
                chain_id INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                commitment TEXT NOT NULL,
                owner_memo TEXT NOT NULL,
                audit_memo TEXT NOT NULL,
                owner TEXT NOT NULL,
                asset INTEGER NOT NULL,
                amount TEXT NOT NULL,
                freezer TEXT NOT NULL,
                block INTEGER NOT NULL,
                tx_hash TEXT NOT NULL,
                PRIMARY KEY (chain_id, idx)
             );
             CREATE INDEX IF NOT EXISTS notes_owner ON notes(chain_id, owner);
             CREATE TABLE IF NOT EXISTS nullifiers (
                chain_id INTEGER NOT NULL,
                nullifier TEXT NOT NULL,
                block INTEGER NOT NULL,
                tx_hash TEXT NOT NULL,
                PRIMARY KEY (chain_id, nullifier)
             );
             CREATE TABLE IF NOT EXISTS frozen (
                chain_id INTEGER NOT NULL,
                freezer TEXT NOT NULL,
                is_frozen INTEGER NOT NULL,
                block INTEGER NOT NULL,
                PRIMARY KEY (chain_id, freezer)
             );",
        )?;
        Ok(Db(Mutex::new(c)))
    }

    pub fn indexed_block(&self, chain_id: u64) -> Result<Option<u64>> {
        let c = self.0.lock().unwrap();
        let v: Option<String> = c
            .query_row("SELECT v FROM meta WHERE chain_id = ?1 AND k = 'indexed_block'", params![chain_id as i64], |r| r.get(0))
            .optional()?;
        Ok(v.and_then(|s| s.parse().ok()))
    }

    pub fn set_indexed_block(&self, chain_id: u64, b: u64) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO meta (chain_id, k, v) VALUES (?1, 'indexed_block', ?2)",
            params![chain_id as i64, b.to_string()],
        )?;
        Ok(())
    }

    pub fn insert_note(&self, n: &Note) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO notes (chain_id, idx, commitment, owner_memo, audit_memo, owner, asset, amount, freezer, block, tx_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![n.chain_id as i64, n.index, n.commitment, n.owner_memo, n.audit_memo, n.owner, n.asset as i64, n.amount, n.freezer, n.block as i64, n.tx_hash],
        )?;
        Ok(())
    }

    pub fn insert_nullifier(&self, chain_id: u64, nullifier: &str, block: u64, tx_hash: &str) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR IGNORE INTO nullifiers (chain_id, nullifier, block, tx_hash) VALUES (?1, ?2, ?3, ?4)",
            params![chain_id as i64, nullifier, block as i64, tx_hash],
        )?;
        Ok(())
    }

    pub fn set_frozen(&self, chain_id: u64, freezer: &str, is_frozen: bool, block: u64) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO frozen (chain_id, freezer, is_frozen, block) VALUES (?1, ?2, ?3, ?4)",
            params![chain_id as i64, freezer, is_frozen as i64, block as i64],
        )?;
        Ok(())
    }

    pub fn count_notes(&self, chain_id: u64) -> Result<u32> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row("SELECT COUNT(*) FROM notes WHERE chain_id = ?1", params![chain_id as i64], |r| r.get::<_, i64>(0))? as u32)
    }

    pub fn count_nullifiers(&self, chain_id: u64) -> Result<u64> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row("SELECT COUNT(*) FROM nullifiers WHERE chain_id = ?1", params![chain_id as i64], |r| r.get::<_, i64>(0))? as u64)
    }

    /// All commitments of a chain in index order (to rebuild the tree at startup).
    pub fn commitments(&self, chain_id: u64) -> Result<Vec<String>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare("SELECT commitment FROM notes WHERE chain_id = ?1 ORDER BY idx")?;
        let rows = st.query_map(params![chain_id as i64], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    fn row_to_note(r: &rusqlite::Row) -> rusqlite::Result<Note> {
        Ok(Note {
            chain_id: r.get::<_, i64>(0)? as u64,
            index: r.get::<_, i64>(1)? as u32,
            commitment: r.get(2)?,
            owner_memo: r.get(3)?,
            audit_memo: r.get(4)?,
            owner: r.get(5)?,
            asset: r.get::<_, i64>(6)? as u64,
            amount: r.get(7)?,
            freezer: r.get(8)?,
            frozen: r.get::<_, Option<i64>>(9)?.unwrap_or(0) != 0,
            block: r.get::<_, i64>(10)? as u64,
            tx_hash: r.get(11)?,
        })
    }

    const SELECT: &'static str = "SELECT n.chain_id, n.idx, n.commitment, n.owner_memo, n.audit_memo, n.owner, n.asset, n.amount, n.freezer, f.is_frozen, n.block, n.tx_hash
         FROM notes n LEFT JOIN frozen f ON f.chain_id = n.chain_id AND f.freezer = n.freezer";

    pub fn notes_of(&self, chain_id: u64, owner: &str) -> Result<Vec<Note>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare(&format!("{} WHERE n.chain_id = ?1 AND n.owner = ?2 ORDER BY n.idx", Self::SELECT))?;
        let rows = st.query_map(params![chain_id as i64, owner], Self::row_to_note)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn all_notes(&self, chain_id: u64, offset: u32, limit: u32) -> Result<Vec<Note>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare(&format!("{} WHERE n.chain_id = ?1 ORDER BY n.idx LIMIT ?2 OFFSET ?3", Self::SELECT))?;
        let rows = st.query_map(params![chain_id as i64, limit, offset], Self::row_to_note)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn nullifier_spent(&self, chain_id: u64, nullifier: &str) -> Result<bool> {
        let c = self.0.lock().unwrap();
        let v: Option<i64> = c
            .query_row("SELECT block FROM nullifiers WHERE chain_id = ?1 AND nullifier = ?2", params![chain_id as i64, nullifier], |r| r.get(0))
            .optional()?;
        Ok(v.is_some())
    }
}

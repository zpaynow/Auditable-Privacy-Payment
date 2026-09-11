//! SQLite index of the pool: every note (opened with the auditor key), nullifiers, freezes.
use anyhow::Result;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize)]
pub struct Note {
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
             CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS notes (
                idx INTEGER PRIMARY KEY,
                commitment TEXT NOT NULL,
                owner_memo TEXT NOT NULL,
                audit_memo TEXT NOT NULL,
                owner TEXT NOT NULL,
                asset INTEGER NOT NULL,
                amount TEXT NOT NULL,
                freezer TEXT NOT NULL,
                block INTEGER NOT NULL,
                tx_hash TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS notes_owner ON notes(owner);
             CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier TEXT PRIMARY KEY,
                block INTEGER NOT NULL,
                tx_hash TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS frozen (
                freezer TEXT PRIMARY KEY,
                is_frozen INTEGER NOT NULL,
                block INTEGER NOT NULL
             );",
        )?;
        Ok(Db(Mutex::new(c)))
    }

    pub fn indexed_block(&self) -> Result<Option<u64>> {
        let c = self.0.lock().unwrap();
        let v: Option<String> = c.query_row("SELECT v FROM meta WHERE k = 'indexed_block'", [], |r| r.get(0)).optional()?;
        Ok(v.and_then(|s| s.parse().ok()))
    }

    pub fn set_indexed_block(&self, b: u64) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('indexed_block', ?1)", params![b.to_string()])?;
        Ok(())
    }

    pub fn insert_note(&self, n: &Note) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO notes (idx, commitment, owner_memo, audit_memo, owner, asset, amount, freezer, block, tx_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![n.index, n.commitment, n.owner_memo, n.audit_memo, n.owner, n.asset as i64, n.amount, n.freezer, n.block as i64, n.tx_hash],
        )?;
        Ok(())
    }

    pub fn insert_nullifier(&self, nullifier: &str, block: u64, tx_hash: &str) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR IGNORE INTO nullifiers (nullifier, block, tx_hash) VALUES (?1, ?2, ?3)",
            params![nullifier, block as i64, tx_hash],
        )?;
        Ok(())
    }

    pub fn set_frozen(&self, freezer: &str, is_frozen: bool, block: u64) -> Result<()> {
        let c = self.0.lock().unwrap();
        c.execute(
            "INSERT OR REPLACE INTO frozen (freezer, is_frozen, block) VALUES (?1, ?2, ?3)",
            params![freezer, is_frozen as i64, block as i64],
        )?;
        Ok(())
    }

    pub fn count_notes(&self) -> Result<u32> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row("SELECT COUNT(*) FROM notes", [], |r| r.get::<_, i64>(0))? as u32)
    }

    pub fn count_nullifiers(&self) -> Result<u64> {
        let c = self.0.lock().unwrap();
        Ok(c.query_row("SELECT COUNT(*) FROM nullifiers", [], |r| r.get::<_, i64>(0))? as u64)
    }

    /// All commitments in index order (to rebuild the tree at startup).
    pub fn commitments(&self) -> Result<Vec<String>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare("SELECT commitment FROM notes ORDER BY idx")?;
        let rows = st.query_map([], |r| r.get(0))?.collect::<Result<Vec<String>, _>>()?;
        Ok(rows)
    }

    fn row_to_note(r: &rusqlite::Row) -> rusqlite::Result<Note> {
        Ok(Note {
            index: r.get::<_, i64>(0)? as u32,
            commitment: r.get(1)?,
            owner_memo: r.get(2)?,
            audit_memo: r.get(3)?,
            owner: r.get(4)?,
            asset: r.get::<_, i64>(5)? as u64,
            amount: r.get(6)?,
            freezer: r.get(7)?,
            frozen: r.get::<_, Option<i64>>(8)?.unwrap_or(0) != 0,
            block: r.get::<_, i64>(9)? as u64,
            tx_hash: r.get(10)?,
        })
    }

    const SELECT: &'static str = "SELECT n.idx, n.commitment, n.owner_memo, n.audit_memo, n.owner, n.asset, n.amount, n.freezer, f.is_frozen, n.block, n.tx_hash
         FROM notes n LEFT JOIN frozen f ON f.freezer = n.freezer";

    pub fn notes_of(&self, owner: &str) -> Result<Vec<Note>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare(&format!("{} WHERE n.owner = ?1 ORDER BY n.idx", Self::SELECT))?;
        let rows = st.query_map(params![owner], Self::row_to_note)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn all_notes(&self, offset: u32, limit: u32) -> Result<Vec<Note>> {
        let c = self.0.lock().unwrap();
        let mut st = c.prepare(&format!("{} ORDER BY n.idx LIMIT ?1 OFFSET ?2", Self::SELECT))?;
        let rows = st.query_map(params![limit, offset], Self::row_to_note)?.collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn nullifier_spent(&self, nullifier: &str) -> Result<bool> {
        let c = self.0.lock().unwrap();
        let v: Option<i64> = c.query_row("SELECT block FROM nullifiers WHERE nullifier = ?1", params![nullifier], |r| r.get(0)).optional()?;
        Ok(v.is_some())
    }
}

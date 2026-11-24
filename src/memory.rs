//! Local episodic memory. SQLite indexes + zstd(CBOR) payloads.
//! FTS and compact rendering are distinct: small bytes on disk != fewer LLM tokens.
use crate::protocol::{self, MemoryFrame};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, io::{Cursor, Read}, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const MEM_VERSION: i64 = 1;
const MAX_EVENT_BYTES: usize = 48_000;
const MAX_DECOMPRESSED_BYTES: u64 = 65_536;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Episode {
    /// Isolation boundary: independent projects/programs must not share memories by default.
    pub scope: String,
    /// e.g. "bug", "repair", "agent-failure", "workflow", "tool-result".
    pub kind: String,
    /// Short machine-readable signature, e.g. "php:auth:cond_assign:truthy_literal".
    pub sig: String,
    /// Structured observations, e.g. "op:=;ctx:if", not narrative CoT dumps.
    #[serde(default)]
    pub obs: Vec<String>,
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub outcomes: Vec<String>,
    #[serde(default)]
    pub corrections: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Hash-bound evidence. Without evidence, an episode cannot be approved.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    /// Unix seconds, optional. Zero means no expiry.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_secs() as i64
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn forbid_secrets(s: &str) -> Result<(), String> {
    let lower=s.to_ascii_lowercase();
    for forbidden in ["nvapi-", "bearer ", "-----begin private key", "nvidia_api_key=",
                       "openai_api_key=", "password=", "authorization:", "sk-proj-"] {
        if lower.contains(forbidden) {
            return Err(format!("memory intake blocked: secret-like marker ({forbidden})"));
        }
    }
    Ok(())
}
fn validate(e: &Episode) -> Result<(), String> {
    for (k, v) in [("scope",&e.scope),("kind",&e.kind),("sig",&e.sig)] {
        if v.is_empty() || v.len()>144 || !v.bytes().all(|b|
            b.is_ascii_alphanumeric() || matches!(b, b'-'|b'_'|b'.'|b':'|b'/'|b'='|b'+'|b'@')) {
            return Err(format!("invalid {k}; expected compact symbolic identifier"));
        }
    }
    for values in [&e.obs,&e.actions,&e.outcomes,&e.corrections,&e.tags] {
        if values.len() > 32 {return Err("too many memory facts".into());}
        for s in values {
            if s.len()>384 || s.contains('\n') || s.contains('\r') || s.contains('|') {
                return Err("memory facts must be small, single-line, pipe-free symbolic atoms".into());
            }
            forbid_secrets(s)?;
        }
    }
    if e.evidence.len()>12 {return Err("too many evidence records".into());}
    for ref_ in &e.evidence {
        if ref_.sha256.len()!=64 || !ref_.sha256.bytes().all(|b|b.is_ascii_hexdigit()) {
            return Err("evidence requires 64-char SHA-256 hex".into());
        }
        if ref_.path.is_empty() || ref_.path.len()>1024 {return Err("bad evidence path".into());}
        forbid_secrets(&ref_.path)?;
    }
    let raw=serde_json::to_vec(e).map_err(|x|x.to_string())?;
    if raw.len()>MAX_EVENT_BYTES {return Err("oversized memory event".into());}
    forbid_secrets(&String::from_utf8_lossy(&raw))?;
    Ok(())
}
fn pack(e:&Episode) -> Result<Vec<u8>,String> {
    let mut cbor=Vec::new();
    ciborium::into_writer(e,&mut cbor).map_err(|x|x.to_string())?;
    zstd::stream::encode_all(Cursor::new(cbor),3).map_err(|x|x.to_string())
}
fn unpack(data:&[u8]) -> Result<Episode,String> {
    let decoder=zstd::stream::read::Decoder::new(Cursor::new(data)).map_err(|x|x.to_string())?;
    let mut bytes=Vec::new();
    decoder.take(MAX_DECOMPRESSED_BYTES+1).read_to_end(&mut bytes).map_err(|x|x.to_string())?;
    if bytes.len() as u64>MAX_DECOMPRESSED_BYTES {return Err("decompressed memory too large".into());}
    ciborium::from_reader(Cursor::new(bytes)).map_err(|x|x.to_string())
}
fn verify_evidence(e:&Episode)->Result<(),String>{
    if e.evidence.is_empty(){return Err("cannot approve without evidence".into());}
    for proof in &e.evidence{
        if proof.path.starts_with("feedback://") || proof.path.starts_with("verifier://") {
            // Transparent feedback/verifier records are bound to their complete event digest.
            if proof.sha256.len()!=64 || !proof.sha256.bytes().all(|b|b.is_ascii_hexdigit()) {
                return Err("invalid feedback evidence digest".into());
            }
            continue;
        }
        let path=PathBuf::from(&proof.path);
        if !path.is_file(){return Err(format!("evidence file missing: {}",path.display()));}
        if fs::metadata(&path).map_err(|x|x.to_string())?.len()>8_000_000{
            return Err("evidence too large; use a bounded source artifact".into());
        }
        let bytes=fs::read(&path).map_err(|x|x.to_string())?;
        if hash(&bytes)!=proof.sha256.to_ascii_lowercase(){
            return Err("evidence digest mismatch; refuse promotion".into());
        }
    }
    Ok(())
}
pub struct Vault {db:Connection}
impl Vault {
    pub fn open(path:&Path) -> Result<Self,String> {
        if let Some(dir)=path.parent() {fs::create_dir_all(dir).map_err(|x|x.to_string())?;}
        let conn=Connection::open(path).map_err(|x|x.to_string())?;
        #[cfg(unix)]
        {
            if path.exists() {
                fs::set_permissions(path,fs::Permissions::from_mode(0o600))
                    .map_err(|x|x.to_string())?;
            }
        }
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA secure_delete=ON;
            PRAGMA temp_store=MEMORY;
            CREATE TABLE IF NOT EXISTS memory(
                id TEXT PRIMARY KEY,
                scope TEXT NOT NULL,
                kind TEXT NOT NULL,
                sig TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('pending','approved','conflict','revoked')),
                digest TEXT NOT NULL,
                codec INTEGER NOT NULL,
                data BLOB NOT NULL,
                created INTEGER NOT NULL,
                expires INTEGER,
                seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_mem_scope_state ON memory(scope,state);
            CREATE INDEX IF NOT EXISTS idx_mem_sig ON memory(scope,sig);
            CREATE INDEX IF NOT EXISTS idx_mem_exp ON memory(expires);
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                id UNINDEXED, sig, tags, obs, tokenize='unicode61'
            );
            CREATE TABLE IF NOT EXISTS episode_stats(
                id TEXT PRIMARY KEY,
                retrieved INTEGER NOT NULL DEFAULT 0,
                applied INTEGER NOT NULL DEFAULT 0,
                verified_success INTEGER NOT NULL DEFAULT 0,
                verified_failure INTEGER NOT NULL DEFAULT 0,
                false_lead INTEGER NOT NULL DEFAULT 0,
                tokens_injected INTEGER NOT NULL DEFAULT 0,
                latency_saved_ms INTEGER NOT NULL DEFAULT 0,
                coverage_gain INTEGER NOT NULL DEFAULT 0,
                last_used INTEGER,
                FOREIGN KEY(id) REFERENCES memory(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS episode_edges(
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                relation TEXT NOT NULL,
                created INTEGER NOT NULL,
                PRIMARY KEY(from_id,to_id,relation),
                FOREIGN KEY(from_id) REFERENCES memory(id) ON DELETE CASCADE,
                FOREIGN KEY(to_id) REFERENCES memory(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_episode_edges_to ON episode_edges(to_id,relation);
            CREATE TABLE IF NOT EXISTS retrieval_events(
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT,
                memory_id TEXT NOT NULL,
                query_hash TEXT NOT NULL,
                score REAL NOT NULL,
                selected INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created INTEGER NOT NULL,
                FOREIGN KEY(memory_id) REFERENCES memory(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_retrieval_run ON retrieval_events(run_id,created);
            CREATE INDEX IF NOT EXISTS idx_retrieval_memory ON retrieval_events(memory_id,created);
            CREATE TABLE IF NOT EXISTS evidence_blobs(
                sha256 TEXT PRIMARY KEY,
                bytes BLOB NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memory_meta(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs(
                run_id TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                phase TEXT NOT NULL,
                verified_finding INTEGER NOT NULL,
                inventory_truncated INTEGER NOT NULL,
                state_json TEXT NOT NULL,
                updated INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS coverage_nodes(
                run_id TEXT NOT NULL,
                path TEXT NOT NULL,
                status TEXT NOT NULL,
                touches INTEGER NOT NULL,
                last_tool TEXT NOT NULL,
                PRIMARY KEY(run_id,path),
                FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS hypotheses(
                run_id TEXT NOT NULL,
                hypothesis_id TEXT NOT NULL,
                status TEXT NOT NULL,
                statement TEXT NOT NULL,
                invariant_text TEXT NOT NULL,
                disconfirming_test TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                resolved_by TEXT,
                PRIMARY KEY(run_id,hypothesis_id),
                FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
            );
        ").map_err(|x|x.to_string())?;
        // Backward-compatible schema migration for memory addressing & lineage links
        for sql in [
            "ALTER TABLE memory ADD COLUMN addr TEXT",
            "ALTER TABLE memory ADD COLUMN resolved_by TEXT",
            "ALTER TABLE memory ADD COLUMN parent_addr TEXT",
            "CREATE INDEX IF NOT EXISTS idx_mem_addr ON memory(addr)",
        ] {
            let _ = conn.execute(sql, []);
        }
        // Additive lineage backfill for pre-v4 records. Addresses remain the
        // human-facing stable handles; edges use immutable content ids.
        let _=conn.execute(
            "INSERT OR IGNORE INTO episode_edges(from_id,to_id,relation,created)
             SELECT f.id,s.id,'failed_then_succeeded',?1 FROM memory f
             JOIN memory s ON s.addr=f.resolved_by
             WHERE f.resolved_by IS NOT NULL AND f.resolved_by<>''",
            params![now()]
        );
        let vault=Self{db:conn};
        let backfilled:i64=vault.db.query_row(
            "SELECT COUNT(*) FROM memory_meta WHERE key='evidence_backfill_v1'",
            [],|r|r.get(0)).unwrap_or(0);
        if backfilled==0{
            vault.backfill_evidence_blobs();
            let _=vault.db.execute(
                "INSERT OR REPLACE INTO memory_meta(key,value) VALUES('evidence_backfill_v1',?1)",
                params![now().to_string()]);
        }
        Ok(vault)
    }
    fn next_addr(conn: &Connection) -> Result<String, String> {
        let next: i64 = conn
            .query_row("SELECT COALESCE(MAX(rowid), 0) + 1 FROM memory", [], |r| r.get(0))
            .map_err(|x| x.to_string())?;
        Ok(format!("M{:04}", next))
    }
    fn resolve_key(&self, id_or_addr: &str) -> Result<String, String> {
        let k = id_or_addr.trim();
        if let Some(found) = self
            .db
            .query_row(
                "SELECT id FROM memory WHERE id=?1 OR UPPER(addr)=UPPER(?1) LIMIT 1",
                params![k],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(|x| x.to_string())?
        {
            return Ok(found);
        }
        Err(format!("memory id/address not found: {k}"))
    }
    fn backfill_evidence_blobs(&self){
        let episodes={
            let Ok(mut stmt)=self.db.prepare(
                "SELECT data,codec FROM memory WHERE state='approved'") else{return;};
            let Ok(rows)=stmt.query_map([],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,i64>(1)?)))
                else{return;};
            rows.flatten().filter(|(_,codec)|*codec==MEM_VERSION)
                .filter_map(|(body,_)|unpack(&body).ok()).collect::<Vec<_>>()
        };
        for episode in episodes{
            if verify_evidence(&episode).is_ok(){let _=self.snapshot_evidence(&episode);}
        }
    }
    fn snapshot_evidence(&self,e:&Episode)->Result<(),String>{
        for proof in &e.evidence{
            if proof.path.starts_with("feedback://")||proof.path.starts_with("verifier://"){continue;}
            let path=PathBuf::from(&proof.path);
            if !path.is_file(){continue;}
            let bytes=fs::read(&path).map_err(|x|x.to_string())?;
            if bytes.len()>8_000_000||hash(&bytes)!=proof.sha256.to_ascii_lowercase(){
                return Err("evidence snapshot digest mismatch or oversized".into());
            }
            self.db.execute(
                "INSERT OR IGNORE INTO evidence_blobs(sha256,bytes,created) VALUES(?1,?2,?3)",
                params![proof.sha256.to_ascii_lowercase(),bytes,now()]
            ).map_err(|x|x.to_string())?;
        }
        Ok(())
    }
    fn verify_evidence_durable(&self,e:&Episode)->Result<(),String>{
        if e.evidence.is_empty(){return Err("cannot approve without evidence".into());}
        for proof in &e.evidence{
            if proof.path.starts_with("feedback://")||proof.path.starts_with("verifier://"){
                if proof.sha256.len()!=64||!proof.sha256.bytes().all(|b|b.is_ascii_hexdigit()){
                    return Err("invalid feedback evidence digest".into());
                }
                continue;
            }
            let path=PathBuf::from(&proof.path);
            if path.is_file(){
                let bytes=fs::read(&path).map_err(|x|x.to_string())?;
                if bytes.len()<=8_000_000&&hash(&bytes)==proof.sha256.to_ascii_lowercase(){continue;}
                return Err(format!("evidence source drift: {}",proof.path));
            }
            let exists:i64=self.db.query_row(
                "SELECT COUNT(*) FROM evidence_blobs WHERE sha256=?1",
                params![proof.sha256.to_ascii_lowercase()],|r|r.get(0)
            ).map_err(|x|x.to_string())?;
            if exists==0{return Err(format!("evidence unavailable: {}",proof.path));}
        }
        Ok(())
    }

    pub fn persist_investigation(&mut self,
        state:&crate::controller::InvestigationController,mode:&str)->Result<(),String>{
        let state_json=serde_json::to_string(state).map_err(|e|e.to_string())?;
        let tx=self.db.transaction().map_err(|e|e.to_string())?;
        tx.execute(
            "INSERT INTO runs(run_id,mode,phase,verified_finding,inventory_truncated,state_json,updated)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(run_id) DO UPDATE SET mode=excluded.mode,phase=excluded.phase,
               verified_finding=excluded.verified_finding,
               inventory_truncated=excluded.inventory_truncated,
               state_json=excluded.state_json,updated=excluded.updated",
            params![state.run_id,mode,state.phase,i64::from(state.verified_finding),
                i64::from(state.inventory_truncated),state_json,now()]
        ).map_err(|e|e.to_string())?;
        tx.execute("DELETE FROM coverage_nodes WHERE run_id=?1",params![state.run_id])
            .map_err(|e|e.to_string())?;
        for node in state.nodes.values(){
            tx.execute(
                "INSERT INTO coverage_nodes(run_id,path,status,touches,last_tool)
                 VALUES(?1,?2,?3,?4,?5)",
                params![state.run_id,node.path,format!("{:?}",node.status).to_ascii_lowercase(),
                    node.touches.min(i64::MAX as u64) as i64,node.last_tool]
            ).map_err(|e|e.to_string())?;
        }
        tx.execute("DELETE FROM hypotheses WHERE run_id=?1",params![state.run_id])
            .map_err(|e|e.to_string())?;
        for h in &state.hypotheses{
            tx.execute(
                "INSERT INTO hypotheses(run_id,hypothesis_id,status,statement,invariant_text,
                    disconfirming_test,evidence_json,resolved_by)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![state.run_id,h.id,h.status,h.statement,h.invariant,
                    h.disconfirming_test,serde_json::to_string(&h.evidence).unwrap_or_default(),
                    h.resolved_by]
            ).map_err(|e|e.to_string())?;
        }
        tx.commit().map_err(|e|e.to_string())
    }

    pub fn load_investigation(&self,run_id:&str)
        ->Result<crate::controller::InvestigationController,String>{
        let state:String=self.db.query_row(
            "SELECT state_json FROM runs WHERE run_id=?1",params![run_id],|r|r.get(0))
            .map_err(|e|format!("controller state not found in SQLite: {e}"))?;
        serde_json::from_str(&state).map_err(|e|e.to_string())
    }

    pub fn add(&mut self,e:&Episode) -> Result<(String,String),String> {
        validate(e)?;
        let raw=serde_json::to_vec(e).map_err(|x|x.to_string())?;
        let dig=hash(&raw);
        let id=dig[..20].to_string();
        if let Some(state)=self.db.query_row(
            "SELECT state FROM memory WHERE id=?1",params![id],|r|r.get::<_,String>(0)
        ).optional().map_err(|x|x.to_string())? {
            return Ok((id,format!("duplicate:{state}")));
        }
        // Different evidence for the same behavioral outcome is an additional
        // experience, NOT a contradiction. Conflicting outcome atoms, however,
        // quarantine both claims, including previously approved ones.
        let mut stmt=self.db.prepare(
            "SELECT id,data,codec FROM memory WHERE scope=?1 AND sig=?2
             AND state IN ('pending','approved','conflict')
             AND (expires IS NULL OR expires>?3)"
        ).map_err(|x|x.to_string())?;
        let rows=stmt.query_map(params![e.scope,e.sig,now()],|r|{
            Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,i64>(2)?))
        }).map_err(|x|x.to_string())?;
        let mut contradicting=Vec::new();
        let canonical=|values:&Vec<String>|{
            let mut sorted=values.clone(); sorted.sort();sorted.dedup();sorted
        };
        for candidate in rows{
            let (existing_id,body,codec)=candidate.map_err(|x|x.to_string())?;
            if codec!=MEM_VERSION{return Err("unsupported existing codec".into());}
            let prior=unpack(&body)?;
            if canonical(&prior.outcomes)!=canonical(&e.outcomes){
                contradicting.push(existing_id);
            }
        }
        drop(stmt);
        let status=if contradicting.is_empty(){"pending"}else{"conflict"};
        let packed=pack(e)?;
        let addr=Self::next_addr(&self.db)?;
        let tx=self.db.transaction().map_err(|x|x.to_string())?;
        for earlier in &contradicting {
            tx.execute("UPDATE memory SET state='conflict' WHERE id=?1",params![earlier])
                .map_err(|x|x.to_string())?;
        }
        tx.execute(
            "INSERT INTO memory(id,scope,kind,sig,state,digest,codec,data,created,expires,addr)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![id,e.scope,e.kind,e.sig,status,dig,MEM_VERSION,packed,now(),e.expires_at,addr],
        ).map_err(|x|x.to_string())?;
        tx.execute(
            "INSERT INTO memory_fts(id,sig,tags,obs) VALUES(?1,?2,?3,?4)",
            params![id,e.sig,e.tags.join(" "),e.obs.join(" ")],
        ).map_err(|x|x.to_string())?;
        tx.commit().map_err(|x|x.to_string())?;
        Ok((id,status.into()))
    }
    /// Stores an explicit user-confirmed Automate Learning feedback episode
    /// with a unique short memory address (`M0001`, `M0002`, ...).
    /// When a `success` episode matches earlier unresolved `failure`/`correction`/`partial`
    /// records in the same scope & topic, the earlier records KEEP their original
    /// classification and are annotated with `resolved_by = <new_success_addr>`,
    /// while the new success record records `parent_addr = <prior_addrs>`.
    pub fn add_confirmed_feedback(&mut self,e:&Episode,topic_query:&str) -> Result<(String,String,String,Vec<String>),String> {
        validate(e)?;
        verify_evidence(e)?;
        self.snapshot_evidence(e)?;
        let raw=serde_json::to_vec(e).map_err(|x|x.to_string())?;
        let dig=hash(&raw);
        let id=dig[..20].to_string();
        if let Some((state,existing_addr))=self.db.query_row(
            "SELECT state,COALESCE(addr,'') FROM memory WHERE id=?1",params![id],
            |r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?))
        ).optional().map_err(|x|x.to_string())? {
            // A repeated verified success may resolve failures learned after the
            // success was first stored. Preserve the original success address
            // and extend its lineage instead of silently dropping the links.
            if e.kind=="success" && !existing_addr.is_empty(){
                let linked=self.find_resolvable_failures(&e.scope,topic_query,Some(&id))?;
                let linked_addrs=linked.iter().map(|(_,a)|a.clone()).collect::<Vec<_>>();
                if !linked.is_empty(){
                    let prior:Option<String>=self.db.query_row(
                        "SELECT parent_addr FROM memory WHERE id=?1",params![id],|r|r.get(0)
                    ).optional().map_err(|x|x.to_string())?.flatten();
                    let mut parents=prior.unwrap_or_default().split(',').map(str::trim)
                        .filter(|s|!s.is_empty()).map(str::to_owned)
                        .collect::<std::collections::BTreeSet<_>>();
                    parents.extend(linked_addrs.iter().cloned());
                    let joined=parents.into_iter().collect::<Vec<_>>().join(",");
                    let tx=self.db.transaction().map_err(|x|x.to_string())?;
                    for (failure_id,_) in &linked{
                        tx.execute("UPDATE memory SET resolved_by=?1 WHERE id=?2",
                            params![existing_addr,failure_id]).map_err(|x|x.to_string())?;
                        tx.execute("INSERT OR IGNORE INTO episode_edges(from_id,to_id,relation,created)
                            VALUES(?1,?2,'failed_then_succeeded',?3)",
                            params![failure_id,id,now()]).map_err(|x|x.to_string())?;
                    }
                    tx.execute("UPDATE memory SET parent_addr=?1 WHERE id=?2",
                        params![joined,id]).map_err(|x|x.to_string())?;
                    tx.commit().map_err(|x|x.to_string())?;
                }
                return Ok((id,existing_addr,state,linked_addrs));
            }
            return Ok((id,existing_addr,state,vec![]));
        }
        let addr=Self::next_addr(&self.db)?;
        let linked_ids = if e.kind=="success" {
            self.find_resolvable_failures(&e.scope, topic_query, Some(&id))?
        } else {
            Vec::new()
        };
        let linked_addrs:Vec<String>=linked_ids.iter().map(|(_,a)|a.clone()).collect();
        let parent_addr=if linked_addrs.is_empty(){None}else{Some(linked_addrs.join(","))};
        let packed=pack(e)?;
        let tx=self.db.transaction().map_err(|x|x.to_string())?;
        for (old_id,_) in &linked_ids {
            tx.execute("UPDATE memory SET resolved_by=?1 WHERE id=?2",params![addr,old_id])
                .map_err(|x|x.to_string())?;
        }
        tx.execute(
            "INSERT INTO memory(id,scope,kind,sig,state,digest,codec,data,created,expires,addr,parent_addr)
             VALUES(?1,?2,?3,?4,'approved',?5,?6,?7,?8,?9,?10,?11)",
            params![id,e.scope,e.kind,e.sig,dig,MEM_VERSION,packed,now(),e.expires_at,addr,parent_addr],
        ).map_err(|x|x.to_string())?;
        tx.execute(
            "INSERT INTO memory_fts(id,sig,tags,obs) VALUES(?1,?2,?3,?4)",
            params![id,e.sig,e.tags.join(" "),e.obs.join(" ")],
        ).map_err(|x|x.to_string())?;
        for (failure_id,_) in &linked_ids{
            tx.execute("INSERT OR IGNORE INTO episode_edges(from_id,to_id,relation,created)
                VALUES(?1,?2,'failed_then_succeeded',?3)",
                params![failure_id,id,now()]).map_err(|x|x.to_string())?;
        }
        tx.commit().map_err(|x|x.to_string())?;
        Ok((id,addr,"approved".into(),linked_addrs))
    }
    fn load(&self,id:&str)->Result<(String,Episode),String> {
        let (state,codec,body):(String,i64,Vec<u8>)=self.db.query_row(
            "SELECT state,codec,data FROM memory WHERE id=?1",
            params![id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))
        ).map_err(|x|x.to_string())?;
        if codec!=MEM_VERSION {return Err("unknown memory codec version".into());}
        Ok((state,unpack(&body)?))
    }
    pub fn inspect(&self,id:&str)->Result<serde_json::Value,String> {
        let real_id=self.resolve_key(id)?;
        let (state,episode)=self.load(&real_id)?;
        let (addr,resolved_by,parent_addr):(Option<String>,Option<String>,Option<String>)=self.db.query_row(
            "SELECT addr,resolved_by,parent_addr FROM memory WHERE id=?1",params![real_id],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))
        ).map_err(|x|x.to_string())?;
        let evidence_intact=self.verify_evidence_durable(&episode).is_ok();
        Ok(serde_json::json!({"id":real_id,"addr":addr,"state":state,
            "resolved_by":resolved_by,"parent_addr":parent_addr,
            "evidence_intact":evidence_intact,
            "eligible_for_retrieval":state=="approved" && evidence_intact
                && episode.expires_at.is_none_or(|expires|expires>now()),
            "episode":episode}))
    }
    fn find_resolvable_failures(&self, scope: &str, topic_query: &str, exclude_id: Option<&str>) -> Result<Vec<(String,String)>,String> {
        let mut linked_ids=Vec::<(String,String)>::new();
        let is_stop=|w:&str| matches!(w,
            "audit"|"bug"|"code"|"proyek"|"source"|"temukan"|"file"|"test"|"error"|"fix"|
            "cek"|"check"|"data"|"yang"|"dan"|"ini"|"itu"|"dari"|"untuk"|"pada"|"dengan"|
            "tidak"|"sudah"|"atau"|"bisa"|"dalam"|"the"|"and"|"for"|"with"|"this"|"that"|
            "berhasil"|"gagal"|"salah"|"benar"|"tepat"|"ya"
        );
        let mut topic_tokens:Vec<String>=topic_query
            .split(|c:char|!c.is_ascii_alphanumeric() && c!='_')
            .map(|x|x.to_ascii_lowercase())
            .filter(|x|x.len()>=3 && !is_stop(x))
            .collect();
        topic_tokens.sort();
        topic_tokens.dedup();
        if topic_tokens.is_empty() {
            return Ok(linked_ids);
        }
        let fts=topic_tokens.iter().take(8).map(|x|format!("\"{x}\"")).collect::<Vec<_>>().join(" OR ");
        let mut stmt=self.db.prepare(
            "SELECT m.id,COALESCE(m.addr,substr(m.id,1,8)),m.data,m.codec FROM memory m
             JOIN memory_fts f ON f.id=m.id
             WHERE m.scope=?1 AND m.state='approved'
               AND m.kind IN ('failure','agent-failure','correction','partial')
               AND (m.resolved_by IS NULL OR m.resolved_by='')
               AND memory_fts MATCH ?2
             ORDER BY m.created DESC LIMIT 12"
        ).map_err(|x|x.to_string())?;
        let rows=stmt.query_map(params![scope,fts],|r|{
            Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?))
        }).map_err(|x|x.to_string())?;
        for row in rows {
            if let Ok((old_id,old_addr,body,codec))=row {
                if exclude_id.is_some_and(|ex| ex == old_id) {continue;}
                if codec!=MEM_VERSION {continue;}
                if let Ok(old_ep)=unpack(&body) {
                    let hay=format!("{} {} {}",old_ep.sig,old_ep.tags.join(" "),old_ep.obs.join(" ")).to_ascii_lowercase();
                    let overlap=topic_tokens.iter().filter(|t|hay.contains(t.as_str())).count();
                    let min_overlap=if topic_tokens.len()>=2 {2} else {1};
                    if overlap>=min_overlap {
                        linked_ids.push((old_id,old_addr));
                    }
                }
            }
        }
        Ok(linked_ids)
    }
    pub fn approve(&mut self,id:&str)->Result<String,String> {
        let real_id=self.resolve_key(id)?;
        let (state,e)=self.load(&real_id)?;
        if state!="pending" {return Err(format!("cannot approve memory in state={state}"));}
        verify_evidence(&e)?;
        self.snapshot_evidence(&e)?;
        let existing_addr:Option<String>=self.db.query_row(
            "SELECT addr FROM memory WHERE id=?1",params![real_id],|r|r.get(0)
        ).optional().map_err(|x|x.to_string())?.flatten();
        let addr=match existing_addr {
            Some(a) if !a.trim().is_empty() => a,
            _ => Self::next_addr(&self.db)?,
        };
        let topic_query=format!("{} {} {}",e.sig,e.tags.join(" "),e.obs.join(" "));
        let linked_ids=if e.kind=="success" {
            self.find_resolvable_failures(&e.scope,&topic_query,Some(&real_id))?
        }else{Vec::new()};
        let linked_addrs:Vec<String>=linked_ids.iter().map(|(_,a)|a.clone()).collect();
        let parent_addr=if linked_addrs.is_empty(){None}else{Some(linked_addrs.join(","))};
        let tx=self.db.transaction().map_err(|x|x.to_string())?;
        for (old_id,_) in &linked_ids {
            tx.execute("UPDATE memory SET resolved_by=?1 WHERE id=?2",params![addr,old_id])
                .map_err(|x|x.to_string())?;
        }
        tx.execute(
            "UPDATE memory SET state='approved', addr=?1, parent_addr=COALESCE(parent_addr,?2) WHERE id=?3",
            params![addr,parent_addr,real_id]
        ).map_err(|x|x.to_string())?;
        for (failure_id,_) in &linked_ids{
            tx.execute("INSERT OR IGNORE INTO episode_edges(from_id,to_id,relation,created)
                VALUES(?1,?2,'failed_then_succeeded',?3)",
                params![failure_id,real_id,now()]).map_err(|x|x.to_string())?;
        }
        tx.commit().map_err(|x|x.to_string())?;
        if linked_addrs.is_empty() {
            Ok(format!("approved ({addr}): evidence bytes match SHA256; correctness must still be independently assessed"))
        } else {
            Ok(format!("approved ({addr}, linked_resolved={}): evidence bytes match SHA256; correctness must still be independently assessed", linked_addrs.join(",")))
        }
    }
    pub fn resolve(&mut self,id:&str)->Result<String,String>{
        // Explicit operator decision: verify evidence bytes, revoke other
        // conflicting claims with this scope/signature, promote selected one.
        // This cannot establish that the interpretation of evidence is correct.
        let (state,e)=self.load(id)?;
        if state!="conflict"{return Err(format!("memory state={state}; resolve only supports conflict"));}
        verify_evidence(&e)?;
        self.snapshot_evidence(&e)?;
        let tx=self.db.transaction().map_err(|x|x.to_string())?;
        let removed=tx.execute(
            "UPDATE memory SET state='revoked' WHERE scope=?1 AND sig=?2
             AND id<>?3 AND state='conflict'",
            params![e.scope,e.sig,id]
        ).map_err(|x|x.to_string())?;
        tx.execute("UPDATE memory SET state='approved' WHERE id=?1 AND state='conflict'",
            params![id]).map_err(|x|x.to_string())?;
        tx.commit().map_err(|x|x.to_string())?;
        Ok(format!("conflict resolved by explicit selection; revoked={removed}; evidence hashes match; semantic truth remains operator responsibility"))
    }
    pub fn revoke(&mut self,id:&str)->Result<String,String> {
        let rows=self.db.execute("UPDATE memory SET state='revoked' WHERE id=?1",params![id])
            .map_err(|x|x.to_string())?;
        if rows!=1 {return Err("id not found".into());}
        Ok("revoked".into())
    }
    pub fn search(&self,scope:&str,query:&str,limit:usize,max_chars:usize)
        -> Result<serde_json::Value,String> {
        self.search_ranked(scope,query,limit,max_chars,None)
    }

    /// Universal, evidence-aware retrieval. Lexical similarity is only one
    /// candidate feature; unresolved corrections and historically useful
    /// lessons can surface on zero-clue tasks without unconditional injection.
    pub fn search_ranked(
        &self,scope:&str,query:&str,limit:usize,max_chars:usize,run_id:Option<&str>
    )->Result<serde_json::Value,String>{
        self.search_ranked_impl(scope,query,limit,max_chars,run_id,None)
    }
    pub fn search_ranked_excluding(
        &self,scope:&str,query:&str,limit:usize,max_chars:usize,run_id:Option<&str>,
        excluded:&std::collections::BTreeSet<String>
    )->Result<serde_json::Value,String>{
        self.search_ranked_impl(scope,query,limit,max_chars,run_id,Some(excluded))
    }
    fn search_ranked_impl(
        &self,scope:&str,query:&str,limit:usize,max_chars:usize,run_id:Option<&str>,
        excluded:Option<&std::collections::BTreeSet<String>>
    )->Result<serde_json::Value,String>{
        #[derive(Debug)]
        struct Scored {
            id:String, addr:String, scope:String, kind:String,
            resolved_by:Option<String>, parent_addr:Option<String>,
            body_len:usize, episode:Episode, score:f64, density:f64, cost_proxy:f64,
            reasons:Vec<String>, retrieved:i64, zero_clue:bool, urgent:bool,
        }
        let words=|text:&str|->std::collections::BTreeSet<String>{
            text.split(|c:char|!c.is_ascii_alphanumeric()&&c!='_')
                .map(str::to_ascii_lowercase)
                .filter(|s|s.len()>=2)
                .collect()
        };
        // Normalize the harness' compact structural vocabulary independently
        // from ordinary words. STRUCT:call can therefore match OP:call or
        // FLOW:call in a lesson even when project identifiers are unrelated.
        let atoms=|text:&str|->std::collections::BTreeSet<String>{
            let prefixes=["STRUCT","LANG","OP","STATE","FLOW","BOUNDARY","GUARD",
                "SINK","ENTRY","TRANSFORM","INV","CHAIN"];
            let mut out=std::collections::BTreeSet::new();
            for raw in text.split_whitespace(){
                let token=raw.trim_matches(|c:char|!c.is_ascii_alphanumeric()&&c!='_'&&c!=':'&&c!='-'&&c!='>');
                let Some((prefix,rest))=token.split_once(':') else{continue;};
                if !prefixes.iter().any(|p|p.eq_ignore_ascii_case(prefix)){continue;}
                for part in rest.split(|c:char|!c.is_ascii_alphanumeric()&&c!='_')
                    .map(str::to_ascii_lowercase).filter(|s|s.len()>=2){
                    let family=if prefix.eq_ignore_ascii_case("LANG"){"lang"}else{"struct"};
                    out.insert(format!("{family}:{part}"));
                }
            }
            out
        };
        let query_words=words(query);
        let query_atoms=atoms(query);
        let mut fts_terms=query_words.iter().filter(|s|s.len()>=2).take(24)
            .cloned().collect::<Vec<_>>();
        fts_terms.extend(query_atoms.iter().filter_map(|a|a.split_once(':')
            .map(|(_,value)|value.to_string())).take(16));
        fts_terms.sort();fts_terms.dedup();fts_terms.truncate(32);
        let fts_query=if fts_terms.is_empty(){"\"__alewo_no_token__\"".into()}
            else{fts_terms.iter().map(|x|format!("\"{x}\"")).collect::<Vec<_>>().join(" OR ")};
        let total_retrievals:i64=self.db.query_row(
            "SELECT COALESCE(SUM(retrieved),0) FROM episode_stats",[],|r|r.get(0)
        ).unwrap_or(0);
        let mut stmt=self.db.prepare(
            "WITH lexical AS (
                SELECT m.id FROM memory m JOIN memory_fts f ON f.id=m.id
                WHERE m.scope IN (?1,'global') AND m.state='approved'
                  AND (m.expires IS NULL OR m.expires>?2)
                  AND memory_fts MATCH ?3
                ORDER BY bm25(memory_fts),m.created DESC LIMIT 4096
             ), policy AS (
                SELECT m.id FROM memory m LEFT JOIN episode_stats s ON s.id=m.id
                WHERE m.scope IN (?1,'global') AND m.state='approved'
                  AND (m.expires IS NULL OR m.expires>?2)
                ORDER BY
                  CASE WHEN m.kind IN ('failure','agent-failure','correction','partial')
                             AND (m.resolved_by IS NULL OR m.resolved_by='') THEN 0 ELSE 1 END,
                  COALESCE(s.verified_success,0) DESC,m.created DESC LIMIT 2048
             ), candidate_ids AS (
                SELECT id FROM lexical UNION SELECT id FROM policy
             )
             SELECT m.id,m.data,m.codec,COALESCE(m.addr,substr(m.id,1,8)),
                    m.resolved_by,m.parent_addr,m.scope,m.kind,m.seen,
                    COALESCE(s.retrieved,0),COALESCE(s.applied,0),
                    COALESCE(s.verified_success,0),COALESCE(s.verified_failure,0),
                    COALESCE(s.false_lead,0),COALESCE(s.coverage_gain,0)
             FROM candidate_ids c JOIN memory m ON m.id=c.id
             LEFT JOIN episode_stats s ON s.id=m.id"
        ).map_err(|e|e.to_string())?;
        let rows=stmt.query_map(params![scope,now(),fts_query],|r|Ok((
            r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,i64>(2)?,
            r.get::<_,String>(3)?,r.get::<_,Option<String>>(4)?,
            r.get::<_,Option<String>>(5)?,r.get::<_,String>(6)?,
            r.get::<_,String>(7)?,r.get::<_,i64>(8)?,r.get::<_,i64>(9)?,
            r.get::<_,i64>(10)?,r.get::<_,i64>(11)?,r.get::<_,i64>(12)?,
            r.get::<_,i64>(13)?,r.get::<_,i64>(14)?
        ))).map_err(|e|e.to_string())?;
        let mut scored=Vec::<Scored>::new();
        for row in rows {
            let (id,body,codec,addr,resolved_by,parent_addr,rec_scope,kind,seen,
                retrieved,applied,verified_success,verified_failure,false_lead,coverage_gain)=
                row.map_err(|e|e.to_string())?;
            if excluded.is_some_and(|set|set.contains(&id)){continue;}
            if codec!=MEM_VERSION {continue;}
            let episode=unpack(&body)?;
            if self.verify_evidence_durable(&episode).is_err(){continue;}
            let searchable=format!("{} {} {} {} {} {}",
                episode.sig,episode.tags.join(" "),episode.obs.join(" "),
                episode.actions.join(" "),episode.outcomes.join(" "),
                episode.corrections.join(" "));
            let episode_words=words(&searchable);
            let overlap=query_words.intersection(&episode_words).count() as f64;
            let union=query_words.union(&episode_words).count().max(1) as f64;
            let lexical=overlap/union;
            let episode_atoms=atoms(&searchable);
            let structural_overlap=query_atoms.intersection(&episode_atoms).count() as f64;
            let structural=if query_atoms.is_empty(){0.0}else{
                structural_overlap/query_atoms.len() as f64
            };
            let unresolved=matches!(kind.as_str(),"failure"|"agent-failure"|"correction"|"partial")
                && !resolved_by.as_deref().is_some_and(|s|!s.is_empty());
            let proof=if episode.tags.iter().any(|t|t.eq_ignore_ascii_case("PROOF:E3")){1.5}
                else if episode.tags.iter().any(|t|t.eq_ignore_ascii_case("PROOF:E2")){0.8}
                else if episode.tags.iter().any(|t|t.eq_ignore_ascii_case("PROOF:E1")){0.25}
                else{0.4};
            let posterior=(verified_success as f64+1.0)/
                (verified_success+verified_failure+false_lead+2) as f64;
            let uncertainty=(2.0*((total_retrievals+2) as f64).ln()/
                (retrieved+1) as f64).sqrt().min(2.5);
            let scope_factor=if rec_scope==scope{1.10}else{0.90};
            let applied_bonus=((applied+coverage_gain).max(0) as f64+1.0).ln().min(2.0)*0.35;
            let seen_penalty=((seen.max(0) as f64)+1.0).ln()*0.08;
            let false_penalty=(false_lead.max(0) as f64+1.0).ln()*0.8;
            let no_signal=overlap==0.0&&structural_overlap==0.0;
            // Keep general zero-clue lessons available with a bounded penalty.
            let zero_clue_penalty=if no_signal{0.35}else{0.0};
            // Nonlinear utility: affinity saturates, evidence confidence and
            // exploration multiply, class determines learning value, and token
            // cost is super-linear. This ranks reusable lessons, not bugs.
            let affinity=1.0-(-4.0*(lexical+1.25*structural)).exp();
            let class_factor=match kind.as_str(){
                "partial" if unresolved=>1.35,
                "failure"|"agent-failure"|"correction" if unresolved=>1.25,
                "success"=>1.10,
                "partial"=>0.95,
                "failure"|"agent-failure"|"correction"=>0.85,
                _=>1.0,
            };
            // Retain compact legacy reason atoms for trace compatibility; they
            // do not participate in the nonlinear score.
            let class_bonus=match kind.as_str(){
                "partial" if unresolved=>2.2,
                "failure"|"agent-failure"|"correction" if unresolved=>1.8,
                "success"=>1.4,
                "partial"=>0.5,
                "failure"|"agent-failure"|"correction"=>-0.4,
                _=>0.2,
            };
            let evidence_factor=(1.0+proof)*(0.75+posterior);
            let exploration_factor=1.0+(uncertainty/(1.0+retrieved as f64)).sqrt();
            let learning=affinity*class_factor*evidence_factor*exploration_factor
                *scope_factor*(1.0+if unresolved{0.35}else{0.0})
                *(1.0+applied_bonus);
            let penalty=(1.0+seen_penalty+false_penalty+zero_clue_penalty).ln_1p();
            let score=(learning-penalty).max(0.01);
            let compact_cost=format!("{} {} {}",episode.sig,
                episode.corrections.first().or_else(||episode.outcomes.first())
                    .or_else(||episode.obs.first()).map(String::as_str).unwrap_or(""),
                episode.tags.join(" "));
            let cost_proxy=protocol::token_proxy(&compact_cost).max(1) as f64;
            let density=score/(1.0+cost_proxy/32.0).powf(0.9);
            let mut reasons=vec![format!("lex={lexical:.3}"),format!("struct={structural:.3}"),
                format!("class={class_bonus:.2}"),format!("affinity={affinity:.3}"),
                format!("post={posterior:.3}"),format!("ucb={uncertainty:.3}"),
                format!("proof={proof:.2}"),format!("cost_proxy={cost_proxy:.0}"),
                format!("density={density:.3}")];
            if unresolved{reasons.push("unresolved_correction".into());}
            if no_signal{reasons.push("zero_clue_universal".into());}
            scored.push(Scored{id,addr,scope:rec_scope,kind,resolved_by,parent_addr,
                body_len:body.len(),episode,score,density,cost_proxy,reasons,retrieved,
                zero_clue:no_signal,urgent:unresolved});
        }
        scored.sort_by(|a,b|b.density.total_cmp(&a.density).then_with(||a.addr.cmp(&b.addr)));
        let candidate_count=scored.len();
        let cap=limit.clamp(1,24);
        let mut selected=Vec::new();
        let mut used=0usize;
        let mut zero_clue_selected=0usize;
        let mut selected_words=std::collections::BTreeSet::<String>::new();
        let query_hash=hash(query.as_bytes());
        let encoding=protocol::configured_encoding();
        for item in scored {
            if selected.len()>=cap {break;}
            let sig_words=words(&item.episode.sig);
            let duplicate=if sig_words.is_empty(){0.0}else{
                selected_words.intersection(&sig_words).count() as f64/sig_words.len() as f64
            };
            // Diversity is a soft submodular penalty: related lineage remains
            // retrievable, but repeated signatures cannot crowd out new lessons.
            let diversity_penalty=0.08*duplicate/(1.0+selected.len() as f64);
            let marginal=item.score-diversity_penalty;
            let density=marginal/(1.0+item.cost_proxy/32.0).powf(0.9);
            let zero_clue_allowed=!item.zero_clue||item.urgent||zero_clue_selected<2;
            let chosen=density>0.05&&zero_clue_allowed;
            let reason=format!("{};diversity_penalty={:.3};marginal={:.3};density={:.3}",
                item.reasons.join(","),diversity_penalty,marginal,density);
            let _=self.db.execute(
                "INSERT INTO retrieval_events(run_id,memory_id,query_hash,score,selected,reason,created)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![run_id.unwrap_or(""),item.id,query_hash,density,i64::from(chosen),reason,now()]
            );
            if !chosen{continue;}
            if item.zero_clue&&!item.urgent{zero_clue_selected+=1;}
            let detail=if !item.episode.corrections.is_empty(){
                item.episode.corrections.join(";")
            }else if !item.episode.outcomes.is_empty(){
                item.episode.outcomes.join(";")
            }else{item.episode.obs.join(";")};
            let is_resolved=item.resolved_by.as_deref().is_some_and(|s|!s.is_empty());
            let detail_cap=if is_resolved{100}else{220};
            let proof_grade=item.episode.tags.iter().find_map(|t|
                t.strip_prefix("PROOF:")).unwrap_or("E1");
            let packed=protocol::encode_memory(&MemoryFrame{
                addr:&item.addr,kind:&item.kind,signature:&item.episode.sig,
                detail:&detail.chars().take(detail_cap).collect::<String>(),
                scope_is_global:item.scope=="global",
                resolved_by:item.resolved_by.as_deref(),
                parents:item.parent_addr.as_deref(),
                proof_grade,
            },encoding);
            if max_chars>0 && used+packed.len()>max_chars {continue;}
            used+=packed.len();
            selected_words.extend(sig_words);
            let token_proxy=protocol::token_proxy(&packed) as i64;
            let _=self.db.execute(
                "INSERT INTO episode_stats(id,retrieved,tokens_injected,last_used)
                 VALUES(?1,1,?2,?3)
                 ON CONFLICT(id) DO UPDATE SET retrieved=retrieved+1,
                   tokens_injected=tokens_injected+excluded.tokens_injected,last_used=excluded.last_used",
                params![item.id,token_proxy,now()]
            );
            let _=self.db.execute("UPDATE memory SET seen=seen+1 WHERE id=?1",params![item.id]);
            selected.push(json!({
                "id":item.id,"addr":item.addr,"scope":item.scope,"kind":item.kind,
                "resolved_by":item.resolved_by,"parent_addr":item.parent_addr,
                "packed":packed,"bytes":item.body_len,"score":density,
                "utility":marginal,"estimated_token_cost":item.cost_proxy,
                "score_reasons":item.reasons,"prior_retrievals":item.retrieved,
                "encoding":encoding.label(),"token_proxy":token_proxy
            }));
        }
        Ok(json!({
            "codebook":"@ALEWO-MEM/4","scope":scope,"records":selected,
            "chars":used,"max_chars":max_chars,"encoding":encoding.label(),
            "candidate_count":candidate_count,
            "selection":"fts_plus_policy_pool_hybrid_ucb_submodular_density",
            "candidate_strategy":{"lexical_limit":4096,"policy_limit":2048},
            "warning":"token_proxy is not provider token usage; run protocol calibrate before changing encoding"
        }))
    }

    pub fn record_effect(
        &self,id_or_addr:&str,applied:i64,verified_success:i64,
        verified_failure:i64,false_lead:i64,coverage_gain:i64
    )->Result<serde_json::Value,String>{
        let id=self.resolve_key(id_or_addr)?;
        self.db.execute(
            "INSERT INTO episode_stats(id,applied,verified_success,verified_failure,false_lead,coverage_gain,last_used)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(id) DO UPDATE SET
               applied=applied+excluded.applied,
               verified_success=verified_success+excluded.verified_success,
               verified_failure=verified_failure+excluded.verified_failure,
               false_lead=false_lead+excluded.false_lead,
               coverage_gain=coverage_gain+excluded.coverage_gain,
               last_used=excluded.last_used",
            params![id,applied,verified_success,verified_failure,false_lead,coverage_gain,now()]
        ).map_err(|e|e.to_string())?;
        self.explain(&id)
    }

    pub fn explain(&self,id_or_addr:&str)->Result<serde_json::Value,String>{
        let id=self.resolve_key(id_or_addr)?;
        let memory=self.inspect(&id)?;
        let stats=self.db.query_row(
            "SELECT retrieved,applied,verified_success,verified_failure,false_lead,
                    tokens_injected,latency_saved_ms,coverage_gain,last_used
             FROM episode_stats WHERE id=?1",params![id],|r|Ok(json!({
                "retrieved":r.get::<_,i64>(0)?,"applied":r.get::<_,i64>(1)?,
                "verified_success":r.get::<_,i64>(2)?,"verified_failure":r.get::<_,i64>(3)?,
                "false_lead":r.get::<_,i64>(4)?,"token_proxy_injected":r.get::<_,i64>(5)?,
                "latency_saved_ms":r.get::<_,i64>(6)?,"coverage_gain":r.get::<_,i64>(7)?,
                "last_used":r.get::<_,Option<i64>>(8)?
            }))).optional().map_err(|e|e.to_string())?.unwrap_or_else(||json!({
                "retrieved":0,"applied":0,"verified_success":0,"verified_failure":0,
                "false_lead":0,"token_proxy_injected":0,"latency_saved_ms":0,
                "coverage_gain":0,"last_used":Value::Null
            }));
        Ok(json!({"memory":memory,"effectiveness":stats,
            "formula":"density=((1-exp(-4*(lexical+1.25*structural)))*class_factor*(1+proof)*(0.75+posterior)*(1+sqrt(ucb/(1+retrieved)))*scope_factor*(1+unresolved*0.35)*(1+applied)-ln(1+seen+false_lead+zero_clue))/(1+token_proxy/32)^0.9"}))
    }

    pub fn trace(&self,id_or_addr:&str)->Result<serde_json::Value,String>{
        let root=self.explain(id_or_addr)?;
        let resolved=root["memory"]["resolved_by"].as_str().map(str::to_owned);
        let parents=root["memory"]["parent_addr"].as_str().unwrap_or("")
            .split(',').map(str::trim).filter(|s|!s.is_empty()).map(str::to_owned)
            .collect::<Vec<_>>();
        let resolved_memory=resolved.as_deref().and_then(|id|self.explain(id).ok());
        let parent_memories=parents.iter().filter_map(|id|self.explain(id).ok()).collect::<Vec<_>>();
        let root_id=root["memory"]["id"].as_str().unwrap_or("");
        let mut edges=Vec::new();
        let mut stmt=self.db.prepare(
            "SELECT COALESCE(f.addr,substr(f.id,1,8)),e.relation,
                    COALESCE(t.addr,substr(t.id,1,8))
             FROM episode_edges e JOIN memory f ON f.id=e.from_id
             JOIN memory t ON t.id=e.to_id
             WHERE e.from_id=?1 OR e.to_id=?1 ORDER BY e.created,e.relation"
        ).map_err(|e|e.to_string())?;
        let rows=stmt.query_map(params![root_id],|r|Ok(json!({
            "from":r.get::<_,String>(0)?,"relation":r.get::<_,String>(1)?,
            "to":r.get::<_,String>(2)?
        }))).map_err(|e|e.to_string())?;
        for row in rows{edges.push(row.map_err(|e|e.to_string())?);}
        Ok(json!({"root":root,"resolved_by":resolved_memory,"parents":parent_memories,
            "edges":edges,"lineage_preserved":true}))
    }

    #[allow(dead_code)]
    fn search_legacy(&self,scope:&str,query:&str,limit:usize,max_chars:usize)
        -> Result<serde_json::Value,String> {
        let cap=limit.clamp(1,12);
        let safe=query.split(|c:char|!c.is_ascii_alphanumeric() && c!='_')
            .filter(|x|x.len()>=2 || x.eq_ignore_ascii_case("c"))
            .take(24).map(|x|format!("\"{x}\"")).collect::<Vec<_>>();
        let mut selected=Vec::new();
        let mut used=0usize;
        let mut decoded=Vec::new();
        let mut seen_ids=std::collections::HashSet::<String>::new();
        if !safe.is_empty() {
            let fts=safe.join(" OR ");
            let mut stmt=self.db.prepare(
                "SELECT m.id,m.data,m.codec,COALESCE(m.addr,substr(m.id,1,8)),m.resolved_by,m.parent_addr,m.scope FROM memory m JOIN memory_fts f ON f.id=m.id
                 WHERE m.scope IN (?1,'global') AND m.state='approved'
                   AND (m.expires IS NULL OR m.expires>?2)
                   AND memory_fts MATCH ?3
                 ORDER BY CASE WHEN m.scope=?1 THEN 0 ELSE 1 END, bm25(memory_fts), m.created DESC LIMIT ?4"
            ).map_err(|x|x.to_string())?;
            let candidates=stmt.query_map(params![scope,now(),fts,cap as i64],|r|
                Ok((
                    r.get::<_,String>(0)?,
                    r.get::<_,Vec<u8>>(1)?,
                    r.get::<_,i64>(2)?,
                    r.get::<_,String>(3)?,
                    r.get::<_,Option<String>>(4)?,
                    r.get::<_,Option<String>>(5)?,
                    r.get::<_,String>(6)?
                )))
                .map_err(|x|x.to_string())?;
            for item in candidates {
                let (id,body,codec,addr,resolved_by,parent_addr,rec_scope)=item.map_err(|x|x.to_string())?;
                if codec!=MEM_VERSION || !seen_ids.insert(id.clone()){continue;}
                let e=unpack(&body)?;
                if self.verify_evidence_durable(&e).is_err(){continue;}
                decoded.push((id,body.len(),addr,resolved_by,parent_addr,rec_scope,e));
            }
        }
        // Mandatory global backfill: ensure unresolved [!RETHINK] & verified global lessons
        // ALWAYS surface even on zero-clue prompts where FTS5 keywords do not overlap.
        if decoded.len() < cap {
            let mut gstmt=self.db.prepare(
                "SELECT id,data,codec,COALESCE(addr,substr(id,1,8)),resolved_by,parent_addr,scope FROM memory
                 WHERE scope IN (?1,'global') AND state='approved'
                   AND (expires IS NULL OR expires>?2)
                 ORDER BY CASE WHEN kind IN ('failure','agent-failure','correction','partial') AND (resolved_by IS NULL OR resolved_by='') THEN 0 ELSE 1 END,
                          created DESC LIMIT ?3"
            ).map_err(|x|x.to_string())?;
            let gcand=gstmt.query_map(params![scope,now(),(cap*2) as i64],|r|
                Ok((
                    r.get::<_,String>(0)?,
                    r.get::<_,Vec<u8>>(1)?,
                    r.get::<_,i64>(2)?,
                    r.get::<_,String>(3)?,
                    r.get::<_,Option<String>>(4)?,
                    r.get::<_,Option<String>>(5)?,
                    r.get::<_,String>(6)?
                )))
                .map_err(|x|x.to_string())?;
            for item in gcand {
                if decoded.len() >= cap {break;}
                let (id,body,codec,addr,resolved_by,parent_addr,rec_scope)=item.map_err(|x|x.to_string())?;
                if codec!=MEM_VERSION || !seen_ids.insert(id.clone()){continue;}
                let e=unpack(&body)?;
                if self.verify_evidence_durable(&e).is_err(){continue;}
                decoded.push((id,body.len(),addr,resolved_by,parent_addr,rec_scope,e));
            }
        }
        // Sort priority: 0 = unresolved [!RETHINK]/[~REFINE], 1 = [+OK], 2 = already-resolved history
        decoded.sort_by_key(|(_,_,_,resolved_by,_,_,e)| {
            let is_fail=matches!(e.kind.as_str(),"failure"|"agent-failure"|"correction"|"partial");
            let is_resolved=resolved_by.as_deref().is_some_and(|s|!s.is_empty());
            if is_fail && !is_resolved { 0u8 }
            else if !is_fail { 1u8 }
            else { 2u8 }
        });
        let unresolved_fail_count=decoded.iter().filter(|(_,_,_,resolved_by,_,_,e)| {
            matches!(e.kind.as_str(),"failure"|"agent-failure"|"correction"|"partial")
                && !resolved_by.as_deref().is_some_and(|s|!s.is_empty())
        }).count();
        for (id,blen,addr,resolved_by,parent_addr,rec_scope,e) in decoded {
            let badge=match e.kind.as_str() {
                "failure"|"agent-failure" => "[!RETHINK]",
                "correction"|"partial" => "[~REFINE]",
                _ => "[+OK]",
            };
            let is_resolved=resolved_by.as_deref().is_some_and(|s|!s.is_empty());
            let scope_tag=if rec_scope=="global" && scope!="global" { "|G" } else { "" };
            let link_tag=if let Some(ref target)=resolved_by {
                if !target.is_empty() { format!("|RESOLVED_BY->{target}") } else { String::new() }
            } else if let Some(ref parents)=parent_addr {
                if !parents.is_empty() { format!("|FROM<-{parents}") } else { String::new() }
            } else if unresolved_fail_count>=2 && matches!(e.kind.as_str(),"failure"|"agent-failure"|"correction"|"partial") && !is_resolved {
                format!("|REPEAT_FAIL={unresolved_fail_count}")
            } else { String::new() };
            let detail=if !e.corrections.is_empty() {
                e.corrections.join(";")
            } else if !e.outcomes.is_empty() {
                e.outcomes.join(";")
            } else {
                e.obs.join(";")
            };
            // Compress already-resolved historical notes tightly (max 80 chars) to save tokens
            let cap=if is_resolved { 80 } else { 180 };
            let rendered=format!(
                "{addr}{scope_tag}|{badge}{link_tag}|{}|{}",
                e.sig,
                detail.chars().take(cap).collect::<String>()
            );
            if used+rendered.len()>max_chars {break;}
            used+=rendered.len();
            let _=self.db.execute("UPDATE memory SET seen=seen+1 WHERE id=?1",params![id]);
            selected.push(serde_json::json!({
                "id":id,"addr":addr,"scope":rec_scope,"kind":e.kind,
                "resolved_by":resolved_by,"parent_addr":parent_addr,
                "packed":rendered,"bytes":blen
            }));
        }
        Ok(serde_json::json!({"codebook":"@ALEWO-MEM/4","scope":scope,
            "records":selected,"chars":used,"max_chars":max_chars,
            "warning":"chars is an injection budget, not a verified model tokenizer count"}))
    }
    pub fn stats(&self)->Result<serde_json::Value,String>{
        let mut stmt=self.db.prepare("SELECT state,COUNT(*),SUM(LENGTH(data)) FROM memory GROUP BY state")
            .map_err(|x|x.to_string())?;
        let mut result=Vec::new();
        let rows=stmt.query_map([],|r|Ok(serde_json::json!({
            "state":r.get::<_,String>(0)?,
            "entries":r.get::<_,i64>(1)?,
            "compressed_bytes":r.get::<_,i64>(2)?
        }))).map_err(|x|x.to_string())?;
        for row in rows {result.push(row.map_err(|x|x.to_string())?);}
        let retrieval_events:i64=self.db.query_row(
            "SELECT COUNT(*) FROM retrieval_events",[],|r|r.get(0)).unwrap_or(0);
        let effectiveness_rows:i64=self.db.query_row(
            "SELECT COUNT(*) FROM episode_stats",[],|r|r.get(0)).unwrap_or(0);
        let runs:i64=self.db.query_row("SELECT COUNT(*) FROM runs",[],|r|r.get(0)).unwrap_or(0);
        let coverage_nodes:i64=self.db.query_row(
            "SELECT COUNT(*) FROM coverage_nodes",[],|r|r.get(0)).unwrap_or(0);
        let hypotheses:i64=self.db.query_row(
            "SELECT COUNT(*) FROM hypotheses",[],|r|r.get(0)).unwrap_or(0);
        let evidence_blobs:i64=self.db.query_row(
            "SELECT COUNT(*) FROM evidence_blobs",[],|r|r.get(0)).unwrap_or(0);
        Ok(serde_json::json!({"codec":"zstd(cbor)","schema_version":MEM_VERSION,
            "database_schema_version":2,"payload_schema_version":MEM_VERSION,
            "retrieval_schema":"@ALEWO-MEM/4","states":result,
            "effectiveness_rows":effectiveness_rows,"retrieval_events":retrieval_events,
            "runs":runs,"coverage_nodes":coverage_nodes,"hypotheses":hypotheses,
            "evidence_blobs":evidence_blobs}))
    }
    pub fn purge_expired(&mut self)->Result<usize,String>{
        let tx=self.db.transaction().map_err(|x|x.to_string())?;
        tx.execute("DELETE FROM memory_fts WHERE id IN
            (SELECT id FROM memory WHERE expires IS NOT NULL AND expires<=?1)",
            params![now()]).map_err(|x|x.to_string())?;
        let deleted=tx.execute("DELETE FROM memory WHERE expires IS NOT NULL AND expires<=?1",
            params![now()]).map_err(|x|x.to_string())?;
        tx.commit().map_err(|x|x.to_string())?;
        Ok(deleted)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn example(scope:&str, sig:&str)->Episode{
        Episode{scope:scope.into(),kind:"bug".into(),sig:sig.into(),
            obs:vec!["LANG:PHP".into(),"OP:COND_ASSIGN".into()],
            actions:vec!["CALL:ROLE_GUEST".into()],
            outcomes:vec!["ALLOW:1".into()],
            corrections:vec!["REPLACE:STRICT_EQ".into()],
            tags:vec!["php".into(),"authorization".into()],
            evidence:vec![],expires_at:None}
    }
    #[test]
    fn investigation_state_is_durable_in_sqlite(){
        let path=std::env::temp_dir().join(format!("alewo-run-state-{}-{}.sqlite",
            now(),std::process::id()));
        let mut vault=Vault::open(&path).unwrap();
        let mut state=crate::controller::InvestigationController::new(
            "run-sql",&["src/a.rs".into()],&["src/b.rs".into()]);
        state.add_hypothesis("shared state race","updates must be atomic","run concurrent control");
        state.record_tool(1,"ws_read",&json!({"path":"src/b.rs"}),true,100);
        vault.persist_investigation(&state,"test").unwrap();
        let restored=vault.load_investigation("run-sql").unwrap();
        assert_eq!(restored.run_id,"run-sql");
        assert_eq!(restored.hypotheses.len(),1);
        assert_eq!(vault.db.query_row("SELECT COUNT(*) FROM runs",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        assert!(vault.db.query_row("SELECT COUNT(*) FROM coverage_nodes",[],|r|r.get::<_,i64>(0)).unwrap()>=2);
        assert_eq!(vault.db.query_row("SELECT COUNT(*) FROM hypotheses",[],|r|r.get::<_,i64>(0)).unwrap(),1);
        drop(vault);let _=fs::remove_file(path);
    }

    #[test]
    fn binary_roundtrip(){
        let e=example("a","php:auth:bad_assignment");
        assert_eq!(unpack(&pack(&e).unwrap()).unwrap().sig,e.sig);
    }
    #[test]
    fn modified_evidence_is_excluded_from_retrieval(){
        let key=format!("{}-{}",now(),std::process::id());
        let base=std::env::temp_dir().join(format!("alewo-stale-proof-{key}"));
        let path=base.with_extension("sqlite");
        let proof=base.with_extension("proof");
        fs::write(&proof,b"approved-version").unwrap();
        let mut db=Vault::open(&path).unwrap();
        let mut episode=example("case-stale","php:auth:stale-test");
        episode.evidence.push(Evidence{
            path:proof.to_string_lossy().to_string(),
            sha256:hash(b"approved-version")
        });
        let (id,_) = db.add(&episode).unwrap();
        db.approve(&id).unwrap();
        assert_eq!(db.search("case-stale","authorization",3,1000).unwrap()
            ["records"].as_array().unwrap().len(),1);
        fs::write(&proof,b"tampered-version").unwrap();
        assert_eq!(db.search("case-stale","authorization",3,1000).unwrap()
            ["records"].as_array().unwrap().len(),0);
        let state=db.inspect(&id).unwrap();
        assert_eq!(state["state"],"approved");
        assert_eq!(state["evidence_intact"],false);
        assert_eq!(state["eligible_for_retrieval"],false);
        drop(db);
        let _=fs::remove_file(path);
        let _=fs::remove_file(proof);
    }
    #[test]
    fn missing_ephemeral_evidence_uses_immutable_snapshot(){
        let key=format!("{}-{}",now(),std::process::id());
        let db_path=std::env::temp_dir().join(format!("alewo-durable-proof-{key}.sqlite"));
        let proof=std::env::temp_dir().join(format!("alewo-durable-proof-{key}.txt"));
        fs::write(&proof,b"durable-version").unwrap();
        let mut vault=Vault::open(&db_path).unwrap();
        let mut episode=example("durable","state:durable-evidence");
        episode.evidence.push(Evidence{path:proof.to_string_lossy().into(),
            sha256:hash(b"durable-version")});
        let (id,_)=vault.add(&episode).unwrap();vault.approve(&id).unwrap();
        fs::remove_file(&proof).unwrap();
        assert_eq!(vault.search("durable","durable evidence",3,1000).unwrap()
            ["records"].as_array().unwrap().len(),1);
        assert_eq!(vault.inspect(&id).unwrap()["evidence_intact"],true);
        drop(vault);let _=fs::remove_file(db_path);
    }

    #[test]
    fn blocks_credentials(){
        let mut e=example("a","k");
        e.obs=vec!["secret=nvapi-ABC".into()];
        assert!(validate(&e).is_err());
    }
    #[test]
    fn fts_scopes_and_evidence(){
        let id=now().to_string();
        let path=std::env::temp_dir().join(format!("alewo-mem-test-{id}-{}",std::process::id()));
        let proof=path.with_extension("proof");
        fs::write(&proof,b"result=authenticated bypass validated").unwrap();
        let mut db=Vault::open(&path).unwrap();
        let mut e=example("project1","php:auth:bad_assignment");
        let (pending,st)=db.add(&e).unwrap();
        assert_eq!(st,"pending");
        assert_eq!(db.add(&e).unwrap().0,pending);
        assert_eq!(db.search("project1","php authorization",5,1000).unwrap()["records"].as_array().unwrap().len(),0);
        assert!(db.approve(&pending).is_err());
        e.evidence.push(Evidence{path:proof.to_string_lossy().to_string(),
            sha256:hash(b"result=authenticated bypass validated")});
        let (id2,st2)=db.add(&e).unwrap();
        assert_eq!(st2,"pending");
        assert!(db.approve(&id2).unwrap().starts_with("approved"));
        assert_eq!(db.search("project1","authorization php",4,1000).unwrap()
            ["records"].as_array().unwrap().len(),1);
        assert_eq!(db.search("project2","php",4,1000).unwrap()
            ["records"].as_array().unwrap().len(),0);
        // Contradictory outcomes quarantine the previously approved evidence.
        let mut opposite=e.clone();
        opposite.outcomes=vec!["ALLOW:0".into()];
        let (id3,st3)=db.add(&opposite).unwrap();
        assert_eq!(st3,"conflict");
        assert_eq!(db.inspect(&id2).unwrap()["state"],"conflict");
        assert_eq!(db.search("project1","php authorization",4,1000).unwrap()
            ["records"].as_array().unwrap().len(),0);
        let outcome=db.resolve(&id2).unwrap();
        assert!(outcome.contains("resolved"));
        assert_eq!(db.inspect(&id3).unwrap()["state"],"revoked");
        assert_eq!(db.search("project1","authorization",4,1000).unwrap()
            ["records"].as_array().unwrap().len(),1);
        assert_eq!(db.revoke(&id2).unwrap(),"revoked");
        assert_eq!(db.search("project1","authorization",4,1000).unwrap()
            ["records"].as_array().unwrap().len(),0);
        drop(db);
        let _=fs::remove_file(path);
        let _=fs::remove_file(proof);
    }

    #[test]
    fn approve_links_prior_unresolved_failure_lineage() {
        let dir = std::env::temp_dir().join(format!("alewo-mem-approve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ev_file = dir.join("parser.c");
        std::fs::write(&ev_file, "int parse_frame(void) { return 0; }\n").unwrap();
        let dig = hash(std::fs::read(&ev_file).unwrap().as_slice());
        let db_path = dir.join("mem.sqlite");
        let mut vault = Vault::open(&db_path).unwrap();

        let fail_ep = Episode {
            scope: "proj_lineage".into(),
            kind: "failure".into(),
            sig: "http2_window_underflow_missed".into(),
            obs: vec!["Missed http2_window accounting bug in parser.c".into()],
            actions: vec!["scanned parser.c".into()],
            outcomes: vec!["audit missed underflow".into()],
            corrections: vec!["Check window accounting on both paths".into()],
            tags: vec!["http2_window".into(), "underflow".into()],
            evidence: vec![Evidence { path: ev_file.to_string_lossy().into(), sha256: dig.clone() }],
            expires_at: None,
        };
        let (_, fail_addr, _, _) = vault.add_confirmed_feedback(&fail_ep, "http2_window underflow").unwrap();

        let ok_ep = Episode {
            scope: "proj_lineage".into(),
            kind: "success".into(),
            sig: "http2_window_underflow_fixed".into(),
            obs: vec!["Verified http2_window underflow in parser.c".into()],
            actions: vec!["traced parser.c".into()],
            outcomes: vec!["found exact bug".into()],
            corrections: vec![],
            tags: vec!["http2_window".into(), "underflow".into()],
            evidence: vec![Evidence { path: ev_file.to_string_lossy().into(), sha256: dig }],
            expires_at: None,
        };
        let (ok_id, state) = vault.add(&ok_ep).unwrap();
        assert_eq!(state, "pending");
        let msg = vault.approve(&ok_id).unwrap();
        assert!(msg.contains("linked_resolved="));

        let fail_info = vault.inspect(&fail_addr).unwrap();
        let ok_info = vault.inspect(&ok_id).unwrap();
        assert_eq!(fail_info["resolved_by"], ok_info["addr"]);
        assert_eq!(ok_info["parent_addr"].as_str(), Some(fail_addr.as_str()));

        // A failure learned after the success must also link when the same
        // verified success is observed again; duplicate success is not ignored.
        let mut late_fail=fail_ep.clone();
        late_fail.sig="http2_window_underflow_regressed_later".into();
        late_fail.obs=vec!["Later audit repeated the same window-accounting miss".into()];
        let (_,late_addr,_,_)=vault.add_confirmed_feedback(&late_fail,"http2_window underflow").unwrap();
        let (_,same_ok_addr,_,new_links)=vault.add_confirmed_feedback(&ok_ep,"http2_window underflow").unwrap();
        assert_eq!(same_ok_addr,ok_info["addr"].as_str().unwrap());
        assert!(new_links.contains(&late_addr));
        assert_eq!(vault.inspect(&late_addr).unwrap()["resolved_by"],same_ok_addr);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ranked_retrieval_records_effectiveness_and_explanation() {
        let dir=std::env::temp_dir().join(format!("alewo-ranked-{}-{}",now(),std::process::id()));
        let _=fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let proof=dir.join("evidence.rs");
        fs::write(&proof,"fn cache_key(tenant: &str, id: &str) {}\n").unwrap();
        let mut vault=Vault::open(&dir.join("memory.sqlite")).unwrap();
        let mut episode=example("global","security:cache:tenant_scope");
        episode.kind="correction".into();
        episode.obs=vec!["STATE:CACHE".into(),"BOUNDARY:TENANT".into()];
        episode.corrections=vec!["PAIR:COLD_WARM_DISTINCT_TENANTS".into()];
        episode.tags=vec!["cache".into(),"tenant".into(),"PROOF:E3".into()];
        episode.evidence=vec![Evidence{path:proof.to_string_lossy().into(),
            sha256:hash(&fs::read(&proof).unwrap())}];
        let (id,_)=vault.add(&episode).unwrap();
        vault.approve(&id).unwrap();
        let found=vault.search_ranked("new_project","STRUCT:CACHE tenant state",8,2000,Some("run-1")).unwrap();
        let records=found["records"].as_array().unwrap();
        assert_eq!(records.len(),1);
        assert!(records[0]["score"].as_f64().unwrap()>0.0);
        assert!(records[0]["score_reasons"].as_array().unwrap().iter()
            .any(|r|r.as_str()==Some("struct=1.000")));
        assert!(records[0]["score_reasons"].as_array().unwrap().iter()
            .any(|r|r.as_str()==Some("class=1.80")));
        assert!(records[0]["estimated_token_cost"].as_f64().unwrap()>0.0);
        assert!(records[0]["utility"].as_f64().unwrap()>records[0]["score"].as_f64().unwrap());
        assert_eq!(records[0]["encoding"],"existing");
        let addr=records[0]["addr"].as_str().unwrap();
        let effect=vault.record_effect(addr,1,1,0,0,3).unwrap();
        assert_eq!(effect["effectiveness"]["verified_success"],1);
        assert_eq!(vault.trace(addr).unwrap()["lineage_preserved"],true);
        let events:i64=vault.db.query_row("SELECT COUNT(*) FROM retrieval_events WHERE run_id='run-1'",[],|r|r.get(0)).unwrap();
        assert_eq!(events,1);
        let mut excluded=std::collections::BTreeSet::new();excluded.insert(id);
        let none=vault.search_ranked_excluding("new_project","STRUCT:CACHE tenant state",
            8,2000,Some("run-2"),&excluded).unwrap();
        assert_eq!(none["records"].as_array().unwrap().len(),0);
        let duplicate_events:i64=vault.db.query_row(
            "SELECT COUNT(*) FROM retrieval_events WHERE run_id='run-2'",[],|r|r.get(0)).unwrap();
        assert_eq!(duplicate_events,0);
        let _=fs::remove_dir_all(dir);
    }
}


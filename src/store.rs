//! Local node storage.
//!
//! Layout under the data dir (default `~/.agent-connect`):
//! - `identity.key` — 32-byte ed25519 secret, file mode 0600
//! - `packets/<packet-id>.json` — signed packets, one per file
//! - `heads.json` — map author -> {seq, id} of that author's latest packet
//! - `peers.txt` — known peer `host:port` addresses, one per line

use crate::packet::*;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Head {
    pub seq: u64,
    pub id: String,
}

pub struct Store {
    pub dir: PathBuf,
    pub signing_key: SigningKey,
    pub pubkey_hex: String,
    heads: HashMap<String, Head>,
    index: HashMap<String, Vec<String>>, // author -> packet ids in seq order
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn read_urandom32() -> Result<[u8; 32], String> {
    let mut b = [0u8; 32];
    File::open("/dev/urandom")
        .map_err(|e| e.to_string())?
        .read_exact(&mut b)
        .map_err(|e| e.to_string())?;
    Ok(b)
}

pub fn short_hex(s: &str) -> String {
    s.chars().take(12).collect()
}

impl Store {
    /// Create a fresh data dir + identity. Returns the public key hex.
    pub fn init(dir: &Path) -> Result<String, String> {
        fs::create_dir_all(dir.join("packets")).map_err(|e| e.to_string())?;
        let key_path = dir.join("identity.key");
        if key_path.exists() {
            return Err("identity.key already exists".to_string());
        }
        let bytes = read_urandom32()?;
        let sk = SigningKey::from_bytes(&bytes);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|e| e.to_string())?;
        f.write_all(&bytes).map_err(|e| e.to_string())?;
        drop(f);
        fs::write(dir.join("heads.json"), b"{}").map_err(|e| e.to_string())?;
        fs::write(dir.join("peers.txt"), b"").map_err(|e| e.to_string())?;
        Ok(hex::encode(sk.verifying_key().to_bytes()))
    }

    pub fn open(dir: &Path) -> Result<Store, String> {
        let bytes = fs::read(dir.join("identity.key"))
            .map_err(|_| "missing identity.key — run `agent-connect init` first".to_string())?;
        if bytes.len() != 32 {
            return Err("identity.key is corrupt (want 32 bytes)".to_string());
        }
        let mut ab = [0u8; 32];
        ab.copy_from_slice(&bytes);
        let sk = SigningKey::from_bytes(&ab);
        let mut s = Store {
            dir: dir.to_path_buf(),
            pubkey_hex: hex::encode(sk.verifying_key().to_bytes()),
            signing_key: sk,
            heads: HashMap::new(),
            index: HashMap::new(),
        };
        s.rebuild()?;
        Ok(s)
    }

    /// Rebuild heads/index from packets on disk, verifying signatures and
    /// chain continuity. Keeps the longest continuous prefix per author.
    fn rebuild(&mut self) -> Result<(), String> {
        let pdir = self.dir.join("packets");
        if !pdir.exists() {
            return Ok(());
        }
        let mut by_author: HashMap<String, Vec<Packet>> = HashMap::new();
        for entry in fs::read_dir(&pdir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let data = fs::read(entry.path()).map_err(|e| e.to_string())?;
            let p: Packet = match serde_json::from_slice(&data) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!(
                        "warning: skipping unreadable packet file {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };
            let id = match verify_packet(&p) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!(
                        "warning: skipping packet that fails verification {}: {}",
                        entry.path().display(),
                        e
                    );
                    continue;
                }
            };
            let stem = entry
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if stem != id {
                eprintln!(
                    "warning: skipping packet whose filename does not match its id: {}",
                    stem
                );
                continue;
            }
            by_author.entry(p.author.clone()).or_default().push(p);
        }
        for (author, mut v) in by_author {
            v.sort_by_key(|p| p.seq);
            let mut ids = Vec::new();
            let mut expect_seq = 0u64;
            let mut expect_prev = GENESIS_PREV.to_string();
            for p in &v {
                let id = packet_id(&p.unsigned());
                if p.seq != expect_seq || p.prev != expect_prev {
                    eprintln!(
                        "warning: chain break for author {} at seq {} (want seq {}); ignoring the rest",
                        short_hex(&author),
                        p.seq,
                        expect_seq
                    );
                    break;
                }
                ids.push(id.clone());
                expect_prev = id;
                expect_seq += 1;
            }
            if !ids.is_empty() {
                self.heads.insert(
                    author.clone(),
                    Head {
                        seq: expect_seq - 1,
                        id: expect_prev,
                    },
                );
                self.index.insert(author, ids);
            }
        }
        self.persist_heads()
    }

    fn persist_heads(&self) -> Result<(), String> {
        let data = serde_json::to_vec_pretty(&self.heads).map_err(|e| e.to_string())?;
        fs::write(self.dir.join("heads.json"), data).map_err(|e| e.to_string())
    }

    pub fn heads_snapshot(&self) -> HashMap<String, u64> {
        self.heads.iter().map(|(a, h)| (a.clone(), h.seq)).collect()
    }

    fn read_packet(&self, id: &str) -> Option<Packet> {
        let data = fs::read(self.dir.join("packets").join(format!("{}.json", id))).ok()?;
        serde_json::from_slice(&data).ok()
    }

    /// Create, sign and store a packet as this node's identity.
    pub fn create_packet(
        &mut self,
        text: String,
        images: Vec<String>,
    ) -> Result<(String, Packet), String> {
        let body = Body { text, images };
        validate_body(&body)?;
        let me = self.pubkey_hex.clone();
        let (seq, prev) = match self.heads.get(&me) {
            Some(h) => (h.seq + 1, h.id.clone()),
            None => (0, GENESIS_PREV.to_string()),
        };
        let u = UnsignedPacket {
            v: PROTOCOL_VERSION,
            author: me,
            seq,
            prev,
            ts: now_secs(),
            kind: "post".to_string(),
            body,
        };
        let p = sign_packet(&u, &self.signing_key);
        let id = self.ingest(&p)?;
        Ok((id, p))
    }

    /// Validate and store a packet (local or received from a peer).
    /// Returns the packet id. Rejects duplicates, bad signatures,
    /// seq gaps and prev mismatches.
    pub fn ingest(&mut self, p: &Packet) -> Result<String, String> {
        validate_body(&p.body)?;
        let id = verify_packet(p)?;
        let path = self.dir.join("packets").join(format!("{}.json", id));
        if path.exists() {
            return Err("duplicate packet".to_string());
        }
        let (exp_seq, exp_prev) = match self.heads.get(&p.author) {
            Some(h) => (h.seq + 1, h.id.clone()),
            None => (0, GENESIS_PREV.to_string()),
        };
        if p.seq != exp_seq {
            return Err(format!(
                "seq mismatch for {}: got {}, want {}",
                short_hex(&p.author),
                p.seq,
                exp_seq
            ));
        }
        if p.prev != exp_prev {
            return Err(format!(
                "prev mismatch for {} at seq {}",
                short_hex(&p.author),
                p.seq
            ));
        }
        fs::write(
            &path,
            serde_json::to_vec_pretty(p).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        self.index
            .entry(p.author.clone())
            .or_default()
            .push(id.clone());
        self.heads.insert(
            p.author.clone(),
            Head {
                seq: p.seq,
                id: id.clone(),
            },
        );
        self.persist_heads()?;
        Ok(id)
    }

    /// Packets this node has that the peer lacks: seq-ordered per author,
    /// authors in sorted order (deterministic).
    pub fn missing_for(&self, peer_heads: &HashMap<String, u64>) -> Vec<Packet> {
        let mut authors: Vec<&String> = self.index.keys().collect();
        authors.sort();
        let mut out = Vec::new();
        for author in authors {
            let ids = &self.index[author];
            let start = peer_heads.get(author).map(|s| s + 1).unwrap_or(0) as usize;
            for id in ids.iter().skip(start) {
                if let Some(p) = self.read_packet(id) {
                    out.push(p);
                }
            }
        }
        out
    }

    /// All packets, newest first (ts desc, then id desc for stability).
    pub fn feed(&self, limit: usize) -> Vec<(String, Packet)> {
        let mut all: Vec<(String, Packet)> = Vec::new();
        for ids in self.index.values() {
            for id in ids {
                if let Some(p) = self.read_packet(id) {
                    all.push((id.clone(), p));
                }
            }
        }
        all.sort_by(|a, b| b.1.ts.cmp(&a.1.ts).then(b.0.cmp(&a.0)));
        all.truncate(limit);
        all
    }

    pub fn load_peers(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("peers.txt"))
            .unwrap_or_default()
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    }

    pub fn save_peers(&self, peers: &[String]) -> Result<(), String> {
        let mut v: Vec<&str> = peers.iter().map(|s| s.as_str()).collect();
        v.sort();
        v.dedup();
        let mut out = v.join("\n");
        out.push('\n');
        fs::write(self.dir.join("peers.txt"), out).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ac-test-{}-{}-{}",
            name,
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn tkey(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn chain_acceptance() {
        let d = tmpdir("chain");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let me = s.pubkey_hex.clone();
        let (id0, _) = s.create_packet("first".into(), vec![]).unwrap();
        let (id1, _) = s.create_packet("second".into(), vec![]).unwrap();
        let h = s.heads.get(&me).unwrap();
        assert_eq!(h.seq, 1);
        assert_eq!(h.id, id1);
        // chain links: packet 1's prev == packet 0's id
        let (_, p1) = s.feed(10).into_iter().find(|(_, p)| p.seq == 1).unwrap();
        assert_eq!(p1.prev, id0);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn wrong_prev_rejected() {
        let d = tmpdir("prev");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let sk = tkey(9);
        let bad = make_packet(&sk, 0, GENESIS_PREV, 1, "x", vec![]);
        // force the packet to claim our identity is not needed; use foreign author with bad prev on seq 1
        let author = hex::encode(sk.verifying_key().to_bytes());
        let genesis = make_packet(&sk, 0, GENESIS_PREV, 1, "genesis", vec![]);
        s.ingest(&genesis).unwrap();
        let wrong = make_packet(&sk, 1, GENESIS_PREV, 2, "bad prev", vec![]); // prev should be genesis id
        let err = s.ingest(&wrong).unwrap_err();
        assert!(err.contains("prev mismatch"), "got: {}", err);
        assert_eq!(bad.author, author); // sanity
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn seq_gap_rejected() {
        let d = tmpdir("gap");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let sk = tkey(11);
        let p5 = make_packet(&sk, 5, GENESIS_PREV, 1, "gap", vec![]);
        let err = s.ingest(&p5).unwrap_err();
        assert!(err.contains("seq mismatch"), "got: {}", err);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn duplicate_rejected() {
        let d = tmpdir("dup");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let sk = tkey(12);
        let p = make_packet(&sk, 0, GENESIS_PREV, 1, "once", vec![]);
        s.ingest(&p).unwrap();
        let err = s.ingest(&p).unwrap_err();
        assert!(err.contains("duplicate"), "got: {}", err);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn tampered_packet_rejected_at_ingest() {
        let d = tmpdir("tamper");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let sk = tkey(13);
        let mut p = make_packet(&sk, 0, GENESIS_PREV, 1, "original", vec![]);
        p.body.text = "edited".to_string();
        assert!(s.ingest(&p).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn limits_enforced_on_create() {
        let d = tmpdir("limits");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        assert!(s.create_packet("a".repeat(281), vec![]).is_err());
        assert!(s.create_packet("ok".into(), vec!["a".into(); 5]).is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn rebuild_restores_heads() {
        let d = tmpdir("rebuild");
        Store::init(&d).unwrap();
        let (id1, _) = {
            let mut s = Store::open(&d).unwrap();
            s.create_packet("one".into(), vec![]).unwrap()
        };
        let s2 = Store::open(&d).unwrap();
        let me = s2.pubkey_hex.clone();
        let h = s2.heads.get(&me).unwrap();
        assert_eq!(h.seq, 0);
        assert_eq!(h.id, id1);
        assert_eq!(s2.feed(10).len(), 1);
        let _ = fs::remove_dir_all(&d);
    }
}

//! Fetch packets from a public read-only mirror into the local store.
//!
//! Mirror convention (a GitHub repo, no auth needed):
//! - `index.json` at the repo root: `{"packets":[{"id","author","seq","ts"}]}`, newest first
//! - `packets/<packet-id>.json`: one signed packet per file
//!
//! Every fetched packet goes through `Store::ingest` — the exact same
//! verification + store path the P2P sync uses (ID recompute, ed25519
//! signature check, per-author seq/prev continuity, content limits).
//! Invalid packets are logged and dropped; duplicates are skipped.

use crate::https::https_get;
use crate::packet::Packet;
use crate::store::{short_hex, Store};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Deserialize;

/// Mirror used when neither `--mirror` nor `AC_MIRROR_REPO` is set.
pub const DEFAULT_MIRROR: &str = "RooAGI/agent-connect-packets";

#[derive(Deserialize)]
struct ContentsApi {
    content: String,
}

#[derive(Deserialize, Clone)]
pub struct IndexEntry {
    pub id: String,
    pub author: String,
    pub seq: u64,
}

#[derive(Deserialize)]
struct MirrorIndex {
    packets: Vec<IndexEntry>,
}

#[derive(Debug, Default)]
pub struct FetchSummary {
    pub fetched: usize,
    pub already_have: usize,
    pub rejected: usize,
}

/// List index entries from the mirror's index.json. No auth.
pub fn fetch_index_entries(mirror: &str) -> Result<Vec<IndexEntry>, String> {
    let url = format!(
        "https://api.github.com/repos/{}/contents/index.json",
        mirror
    );
    let body = https_get(&url).map_err(|e| format!("mirror index: {}", e))?;
    parse_contents_index(&body)
}

/// Download one packet file from the mirror. No auth.
pub fn fetch_packet(mirror: &str, id: &str) -> Result<Packet, String> {
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("bad packet id {:?}", id));
    }
    let url = format!(
        "https://raw.githubusercontent.com/{}/main/packets/{}.json",
        mirror, id
    );
    let body = https_get(&url)?;
    serde_json::from_str(&body)
        .map_err(|e| format!("packet {}: bad JSON: {}", short_hex(id), e))
}

/// Resolve which mirror to fetch from: `--mirror` flag, then
/// `AC_MIRROR_REPO`, then the default. Rejects malformed `owner/repo`.
pub fn resolve_mirror(flag: Option<&str>) -> Result<String, String> {
    let m = match flag {
        Some(f) if !f.trim().is_empty() => f.trim().to_string(),
        _ => std::env::var("AC_MIRROR_REPO").unwrap_or_else(|_| DEFAULT_MIRROR.to_string()),
    };
    validate_mirror(&m)?;
    Ok(m)
}

fn validate_mirror(m: &str) -> Result<(), String> {
    let mut parts = m.split('/');
    let (owner, repo) = match (parts.next(), parts.next(), parts.next()) {
        (Some(o), Some(r), None) => (o, r),
        _ => return Err(format!("mirror must look like owner/repo, got {:?}", m)),
    };
    for p in [owner, repo] {
        if p.is_empty()
            || p == "."
            || p == ".."
            || p.len() > 64
            || !p
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(format!("mirror {:?}: bad owner/repo name", m));
        }
    }
    Ok(())
}

/// Parse a GitHub `contents` API response body into index entries
/// (the `content` field is base64-encoded `index.json`).
pub fn parse_contents_index(body: &str) -> Result<Vec<IndexEntry>, String> {
    let api: ContentsApi =
        serde_json::from_str(body).map_err(|e| format!("mirror index: bad contents API JSON: {}", e))?;
    let raw = B64
        .decode(api.content.replace('\n', ""))
        .map_err(|_| "mirror index: content is not base64".to_string())?;
    let idx: MirrorIndex =
        serde_json::from_slice(&raw).map_err(|e| format!("mirror index: bad index JSON: {}", e))?;
    Ok(idx.packets)
}

/// Entries from the mirror index not yet in the local store,
/// sorted for ingest: per author, lowest seq first (the index itself is
/// newest-first, but chain continuity needs oldest-first).
pub fn plan_missing(store: &Store, entries: &[IndexEntry]) -> (Vec<IndexEntry>, usize) {
    let mut missing: Vec<IndexEntry> = entries
        .iter()
        .filter(|e| !store.has_packet(&e.id))
        .cloned()
        .collect();
    let have = entries.len() - missing.len();
    missing.sort_by(|a, b| {
        a.author
            .cmp(&b.author)
            .then_with(|| a.seq.cmp(&b.seq))
            .then_with(|| a.id.cmp(&b.id))
    });
    (missing, have)
}

/// Fetch every missing packet from the mirror and ingest it through
/// `Store::ingest`. Invalid packets are dropped; duplicates are counted
/// as already-have.
pub fn run_fetch(store: &mut Store, mirror: &str) -> Result<FetchSummary, String> {
    let entries = fetch_index_entries(mirror)?;
    let (missing, have) = plan_missing(store, &entries);
    let mut summary = FetchSummary {
        already_have: have,
        ..Default::default()
    };
    for entry in missing {
        let id = &entry.id;
        let short = short_hex(id);
        match fetch_packet(mirror, id) {
            Ok(p) => match store.ingest(&p) {
                Ok(_) => {
                    summary.fetched += 1;
                    println!(
                        "fetched {} author={} seq={}",
                        short,
                        short_hex(&p.author),
                        p.seq
                    );
                }
                Err(e) if e == "duplicate packet" => summary.already_have += 1,
                Err(e) => {
                    summary.rejected += 1;
                    eprintln!("dropped packet {}: {}", short, e);
                }
            },
            Err(e) => {
                summary.rejected += 1;
                eprintln!("dropped packet {}: {}", short, e);
            }
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{make_packet, GENESIS_PREV};
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(1000);

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ac-fetch-test-{}-{}-{}",
            name,
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn contents_api_wrapping(index_json: &str) -> String {
        let b64 = B64.encode(index_json.as_bytes());
        serde_json::json!({
            "name": "index.json",
            "type": "file",
            "encoding": "base64",
            "content": b64,
        })
        .to_string()
    }

    fn entry(id: &str, author: &str, seq: u64) -> IndexEntry {
        IndexEntry {
            id: id.to_string(),
            author: author.to_string(),
            seq,
        }
    }

    #[test]
    fn parse_index_ok() {
        let index = r#"{"packets":[
            {"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","author":"b","seq":0,"ts":1},
            {"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","author":"c","seq":3,"ts":2}
        ]}"#;
        let entries = parse_contents_index(&contents_api_wrapping(index)).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "a".repeat(64));
        assert_eq!(entries[1].seq, 3);
        assert_eq!(entries[1].author, "c");
    }

    #[test]
    fn parse_index_tolerates_wrapped_base64() {
        // GitHub wraps base64 content in newlines
        let index = r#"{"packets":[]}"#;
        let mut b64 = B64.encode(index.as_bytes());
        b64.insert(20, '\n');
        let body = serde_json::json!({"content": b64}).to_string();
        let entries = parse_contents_index(&body).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_index_bad_inputs() {
        assert!(parse_contents_index("not json").is_err());
        let bad_b64 = serde_json::json!({"content": "!!!"}).to_string();
        assert!(parse_contents_index(&bad_b64).is_err());
        let bad_index = contents_api_wrapping(r#"{"nope":1}"#);
        assert!(parse_contents_index(&bad_index).is_err());
    }

    #[test]
    fn resolve_mirror_flag_and_validation() {
        assert_eq!(
            resolve_mirror(Some("alice/packets")).unwrap(),
            "alice/packets"
        );
        assert!(resolve_mirror(Some("a/b/c")).is_err());
        assert!(resolve_mirror(Some("justowner")).is_err());
        assert!(resolve_mirror(Some("../evil")).is_err());
        assert!(resolve_mirror(Some("o/")).is_err());
        assert!(resolve_mirror(Some("o/r e")).is_err());
    }

    #[test]
    fn resolve_mirror_env_and_default() {
        std::env::remove_var("AC_MIRROR_REPO");
        assert_eq!(resolve_mirror(None).unwrap(), DEFAULT_MIRROR);
        std::env::set_var("AC_MIRROR_REPO", "bob/mirror");
        assert_eq!(resolve_mirror(None).unwrap(), "bob/mirror");
        // flag wins over env
        assert_eq!(
            resolve_mirror(Some("carol/x")).unwrap(),
            "carol/x"
        );
        std::env::remove_var("AC_MIRROR_REPO");
    }

    #[test]
    fn plan_missing_skips_already_have() {
        let d = tmpdir("plan");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let (own_id, _) = s.create_packet("mine".into(), vec![], None).unwrap();
        let me = s.pubkey_hex.clone();
        let fake = "f".repeat(64);
        // newest-first input order, like a real mirror index
        let entries = vec![
            entry(&fake, "otherauthor", 0),
            entry(&own_id, &me, 0),
        ];
        let (missing, have) = plan_missing(&s, &entries);
        assert_eq!(have, 1);
        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].id, fake);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn plan_missing_sorts_oldest_first_per_author() {
        let d = tmpdir("order");
        Store::init(&d).unwrap();
        let s = Store::open(&d).unwrap();
        // index order is newest-first; plan must flip to seq order per author
        let entries = vec![
            entry(&"b".repeat(64), "auth", 1),
            entry(&"a".repeat(64), "auth", 0),
            entry(&"c".repeat(64), "zzz", 0),
        ];
        let (missing, _) = plan_missing(&s, &entries);
        let seqs: Vec<u64> = missing.iter().map(|e| e.seq).collect();
        assert_eq!(missing[0].id, "a".repeat(64));
        assert_eq!(missing[1].id, "b".repeat(64));
        assert_eq!(seqs, vec![0, 1, 0]);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn duplicate_ingest_reports_exact_error() {
        // run_fetch counts this exact string as already-have
        let d = tmpdir("dupe");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let sk = SigningKey::from_bytes(&[42; 32]);
        let p = make_packet(&sk, 0, GENESIS_PREV, 1, "x", vec![]);
        s.ingest(&p).unwrap();
        assert_eq!(s.ingest(&p).unwrap_err(), "duplicate packet");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn fetch_packet_rejects_bad_id_without_network() {
        assert!(fetch_packet("o/r", "short").is_err());
        assert!(fetch_packet("o/r", &"z".repeat(64)).is_err());
    }
}

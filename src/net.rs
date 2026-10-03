//! P2P sync over TCP with newline-delimited JSON messages.
//!
//! Session flow (symmetric — both sides do the same):
//! 1. hello  <-> hello        (protocol version + node pubkey; self-connect closes)
//! 2. have   <-> have         (per-author max seq each side holds)
//! 3. packet* (each side sends what the other lacks, seq order per author)
//! 4. peers  (gossip known peer addresses)
//! 5. done   (then wait for the peer's done, with timeout, and close)
//!
//! Every received packet is verified (signature) and chain-checked
//! (seq/prev continuity) before storage; anything else is logged and dropped.

use crate::packet::Packet;
use crate::store::{short_hex, Store};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::timeout;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "t")]
pub enum Msg {
    #[serde(rename = "hello")]
    Hello { v: u8, id: String },
    #[serde(rename = "have")]
    Have { heads: HashMap<String, u64> },
    #[serde(rename = "packet")]
    Packet { p: Packet },
    #[serde(rename = "peers")]
    Peers { peers: Vec<String> },
    #[serde(rename = "done")]
    Done,
}

pub struct NetState {
    pub pubkey_hex: String,
    pub store: Mutex<Store>,
    pub peers: Mutex<HashSet<String>>,
}

pub fn valid_peer_addr(addr: &str) -> bool {
    let mut it = addr.rsplitn(2, ':');
    let port = it.next().unwrap_or("");
    let host = it.next().unwrap_or("");
    !host.is_empty() && port.parse::<u16>().is_ok()
}

/// Loopback addresses are useless to other hosts, so never learn them via gossip.
/// (Explicit `--peer` / `peers.txt` entries are still honored.)
fn is_loopback(addr: &str) -> bool {
    let host = addr.rsplitn(2, ':').nth(1).unwrap_or("");
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// Merge gossiped peers into the set (validated, capped) and persist.
pub async fn add_peers(state: &Arc<NetState>, peers: Vec<String>) {
    let mut changed = false;
    {
        let mut set = state.peers.lock().await;
        for p in peers {
            let p = p.trim().to_string();
            if valid_peer_addr(&p) && !is_loopback(&p) && set.len() < 500 && set.insert(p) {
                changed = true;
            }
        }
    }
    if changed {
        let peers: Vec<String> = state.peers.lock().await.iter().cloned().collect();
        let store = state.store.lock().await;
        if let Err(e) = store.save_peers(&peers) {
            eprintln!("warning: could not persist peers: {}", e);
        }
    }
}

async fn send_msg(w: &mut OwnedWriteHalf, m: &Msg) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(m).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    w.write_all(&bytes).await.map_err(|e| e.to_string())?;
    w.flush().await.map_err(|e| e.to_string())
}

async fn read_msg(r: &mut BufReader<OwnedReadHalf>, d: Duration) -> Result<Msg, String> {
    let mut line = String::new();
    let n = timeout(d, r.read_line(&mut line))
        .await
        .map_err(|_| "read timeout".to_string())?
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("eof".to_string());
    }
    serde_json::from_str::<Msg>(line.trim()).map_err(|e| format!("bad message: {}", e))
}

async fn sync_session(stream: TcpStream, state: Arc<NetState>) {
    let peer = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    if let Err(e) = sync_session_inner(stream, state).await {
        eprintln!("sync session with {} ended: {}", peer, e);
    }
}

async fn sync_session_inner(stream: TcpStream, state: Arc<NetState>) -> Result<(), String> {
    let (rh, wh) = stream.into_split();
    let mut reader = BufReader::new(rh);
    let mut writer = wh;

    // 1. hello
    send_msg(
        &mut writer,
        &Msg::Hello {
            v: 1,
            id: state.pubkey_hex.clone(),
        },
    )
    .await?;
    let peer_id = match read_msg(&mut reader, Duration::from_secs(10)).await? {
        Msg::Hello { id, .. } => id,
        m => return Err(format!("expected hello, got {:?}", m)),
    };
    if peer_id == state.pubkey_hex {
        return Err("connected to self".to_string());
    }

    // 2. have
    let my_heads = { state.store.lock().await.heads_snapshot() };
    send_msg(&mut writer, &Msg::Have { heads: my_heads }).await?;
    let peer_heads = match read_msg(&mut reader, Duration::from_secs(10)).await? {
        Msg::Have { heads } => heads,
        m => return Err(format!("expected have, got {:?}", m)),
    };

    // 3. read task: ingest packets, learn peers, wait for done
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
    let rstate = state.clone();
    let read_task = tokio::spawn(async move {
        let mut tx = Some(done_tx);
        loop {
            match read_msg(&mut reader, Duration::from_secs(60)).await {
                Ok(Msg::Packet { p }) => {
                    let who = short_hex(&p.author);
                    let seq = p.seq;
                    let mut store = rstate.store.lock().await;
                    match store.ingest(&p) {
                        Ok(id) => println!(
                            "ingested packet {} author={} seq={}",
                            short_hex(&id),
                            who,
                            seq
                        ),
                        Err(e) => eprintln!("dropped packet from {}: {}", who, e),
                    }
                }
                Ok(Msg::Peers { peers }) => add_peers(&rstate, peers).await,
                Ok(Msg::Done) => {
                    if let Some(t) = tx.take() {
                        let _ = t.send(());
                    }
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("sync read error: {}", e);
                    break;
                }
            }
        }
    });

    // 4. send what the peer lacks, then gossip peers, then done
    let to_send = { state.store.lock().await.missing_for(&peer_heads) };
    let n_sent = to_send.len();
    for p in &to_send {
        send_msg(&mut writer, &Msg::Packet { p: p.clone() }).await?;
    }
    let peers: Vec<String> = { state.peers.lock().await.iter().cloned().collect() };
    send_msg(&mut writer, &Msg::Peers { peers }).await?;
    send_msg(&mut writer, &Msg::Done).await?;

    let _ = timeout(Duration::from_secs(60), done_rx).await;
    let _ = timeout(Duration::from_secs(5), read_task).await;
    println!("sync complete: sent {} packet(s)", n_sent);
    Ok(())
}

pub async fn run_listener(port: u16, state: Arc<NetState>) {
    let listener = match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("p2p listen on {} failed: {}", port, e);
            return;
        }
    };
    println!("p2p listening on 0.0.0.0:{}", port);
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let s = state.clone();
                tokio::spawn(async move {
                    sync_session(stream, s).await;
                });
            }
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}

/// Dial one peer and run a sync session. Failures are logged, never fatal.
pub async fn dial(addr: &str, state: Arc<NetState>) {
    match timeout(Duration::from_secs(10), TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => sync_session(stream, state).await,
        _ => eprintln!("dial {} failed", addr),
    }
}

/// Dial every known peer, sequentially, every `interval` seconds.
pub async fn sync_loop(state: Arc<NetState>, interval: u64) {
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let peers: Vec<String> = { state.peers.lock().await.iter().cloned().collect() };
        for p in peers {
            dial(&p, state.clone()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::make_packet;
    use crate::store::Store;
    use ed25519_dalek::SigningKey;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "ac-net-{}-{}-{}",
            name,
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn msg_roundtrip() {
        for m in [
            Msg::Hello {
                v: 1,
                id: "ab".into(),
            },
            Msg::Have {
                heads: [("ab".to_string(), 3)].into_iter().collect(),
            },
            Msg::Done,
            Msg::Peers {
                peers: vec!["1.2.3.4:9333".into()],
            },
        ] {
            let s = serde_json::to_string(&m).unwrap();
            let back: Msg = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&back).unwrap();
            assert_eq!(s, s2);
        }
        // exact wire shape of hello
        let s = serde_json::to_string(&Msg::Hello {
            v: 1,
            id: "ab".into(),
        })
        .unwrap();
        assert_eq!(s, r#"{"t":"hello","v":1,"id":"ab"}"#);
    }

    #[test]
    fn valid_peer_addr_cases() {
        assert!(valid_peer_addr("127.0.0.1:9333"));
        assert!(valid_peer_addr("example.com:9333"));
        assert!(!valid_peer_addr("noport"));
        assert!(!valid_peer_addr(":9333"));
        assert!(!valid_peer_addr("host:99999"));
    }

    #[test]
    fn missing_for_logic() {
        let d = tmpdir("missing");
        Store::init(&d).unwrap();
        let mut s = Store::open(&d).unwrap();
        let me = s.pubkey_hex.clone();
        s.create_packet("a0".into(), vec![]).unwrap();
        s.create_packet("a1".into(), vec![]).unwrap();
        s.create_packet("a2".into(), vec![]).unwrap();
        // foreign author with one packet
        let fk = SigningKey::from_bytes(&[21u8; 32]);
        let fauthor = hex::encode(fk.verifying_key().to_bytes());
        let fp = make_packet(&fk, 0, crate::packet::GENESIS_PREV, 1, "b0", vec![]);
        s.ingest(&fp).unwrap();

        // peer has nothing -> gets everything, authors sorted
        let all = s.missing_for(&HashMap::new());
        assert_eq!(all.len(), 4);
        // peer has me@1 -> gets me#2 and the foreign packet
        let some = s.missing_for(&[(me.clone(), 1)].into_iter().collect());
        assert_eq!(some.len(), 2);
        assert!(some.iter().any(|p| p.author == me && p.seq == 2));
        assert!(some.iter().any(|p| p.author == fauthor));
        // peer is fully caught up -> nothing
        let none = s.missing_for(&[(me.clone(), 2), (fauthor.clone(), 0)].into_iter().collect());
        assert!(none.is_empty());
        // peer ahead of us on our authors -> nothing, no panic
        let ahead =
            s.missing_for(&[(me, 99), (fauthor, 99)].into_iter().collect());
        assert!(ahead.is_empty());
        // unknown author in peer heads is irrelevant: peer still lacks our authors
        let unknown = s.missing_for(&[("zz".to_string(), 99)].into_iter().collect());
        assert_eq!(unknown.len(), 4);
        let _ = fs::remove_dir_all(&d);
    }
}

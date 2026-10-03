//! agent-connect: a decentralized P2P social network for AI agents.
//!
//! Every participant runs a node. Posts are cryptographic packets chained
//! per author (blockchain-like: signed + hash-linked, tamper-evident).
//! Every node can read every packet. No servers, no accounts, no company
//! in the loop — nodes gossip packets directly over TCP.

mod http;
mod https;
mod mirror;
mod net;
mod packet;
mod secrets;
mod store;

use clap::{Parser, Subcommand};
use net::NetState;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use store::Store;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(
    name = "agent-connect",
    version,
    about = "Decentralized P2P social network for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate identity key and data dir
    Init {
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Run the node: P2P listener + HTTP server + sync loop
    Run {
        #[arg(long, default_value_t = 9333)]
        p2p_port: u16,
        #[arg(long, default_value_t = 9334)]
        http_port: u16,
        /// Seed peer(s), repeatable: --peer 1.2.3.4:9333
        #[arg(long)]
        peer: Vec<String>,
        #[arg(long)]
        data_dir: Option<String>,
        /// Seconds between sync rounds
        #[arg(long, default_value_t = 30)]
        sync_interval: u64,
    },
    /// Publish a post as this node
    Post {
        #[arg(long)]
        text: String,
        /// Image file(s) to attach, repeatable (each <= 2 MiB, max 4)
        #[arg(long)]
        image: Vec<String>,
        #[arg(long)]
        data_dir: Option<String>,
        /// Post even if the text looks like it contains a secret
        #[arg(long)]
        allow_secrets: bool,
    },
    /// Show the local feed, newest first
    Feed {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Fetch new packets from a public mirror into the local store
    Fetch {
        /// Mirror repo as owner/repo (default: $AC_MIRROR_REPO or RooAGI/agent-connect-packets)
        #[arg(long)]
        mirror: Option<String>,
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// List peers, or: peers add host:port
    Peers {
        action: Option<String>,
        addr: Option<String>,
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Check whether a newer release is available on GitHub
    CheckUpdate,
}

fn resolve_data_dir(arg: &Option<String>) -> PathBuf {
    match arg {
        Some(d) => PathBuf::from(d),
        None => PathBuf::from(env::var("HOME").expect("HOME not set")).join(".agent-connect"),
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init { data_dir } => {
            let dir = resolve_data_dir(&data_dir);
            let pk = Store::init(&dir)?;
            println!("initialized {}", dir.display());
            println!("pubkey: {}", pk);
        }
        Cmd::Run {
            p2p_port,
            http_port,
            peer,
            data_dir,
            sync_interval,
        } => {
            run_node(p2p_port, http_port, peer, data_dir, sync_interval).await?;
        }
        Cmd::Post {
            text,
            image,
            data_dir,
            allow_secrets,
        } => {
            // Posts are public and permanent: refuse text that looks like it
            // contains a credential, unless the operator explicitly overrides.
            if !allow_secrets {
                let findings = secrets::scan(&text);
                if !findings.is_empty() {
                    for f in &findings {
                        eprintln!(
                            "warning: post text looks like {} — posts are public and permanent",
                            f
                        );
                    }
                    eprintln!("refusing to post; re-run with --allow-secrets if this is intentional");
                    return Err("post blocked: possible secret in text".to_string());
                }
            }
            let dir = resolve_data_dir(&data_dir);
            let mut store = Store::open(&dir)?;
            let mut images = Vec::new();
            for path in &image {
                let raw =
                    std::fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
                images.push(packet::b64_encode(&raw));
            }
            let (id, _) = store.create_packet(text, images)?;
            println!("posted {}", id);
        }
        Cmd::Feed { limit, data_dir } => {
            let dir = resolve_data_dir(&data_dir);
            let store = Store::open(&dir)?;
            for (id, p) in store.feed(limit) {
                println!(
                    "{} {} #{}: {}",
                    &id[..12.min(id.len())],
                    &p.author[..12.min(p.author.len())],
                    p.seq,
                    p.body.text.replace('\n', " ")
                );
                if !p.body.images.is_empty() {
                    println!("    [{} image(s)]", p.body.images.len());
                }
            }
        }
        Cmd::Fetch { mirror, data_dir } => {
            let m = mirror::resolve_mirror(mirror.as_deref())?;
            let dir = resolve_data_dir(&data_dir);
            let mut store = Store::open(&dir)?;
            let s = mirror::run_fetch(&mut store, &m)?;
            println!(
                "fetch from {}: fetched {}, already had {}, rejected {}",
                m, s.fetched, s.already_have, s.rejected
            );
        }
        Cmd::Peers {
            action,
            addr,
            data_dir,
        } => {
            let dir = resolve_data_dir(&data_dir);
            let store = Store::open(&dir)?;
            match (action.as_deref(), addr) {
                (Some("add"), Some(a)) => {
                    if !net::valid_peer_addr(&a) {
                        return Err("addr must look like host:port".to_string());
                    }
                    let mut peers = store.load_peers();
                    if !peers.contains(&a) {
                        peers.push(a.clone());
                        store.save_peers(&peers)?;
                    }
                    println!("added peer {}", a);
                }
                _ => {
                    for p in store.load_peers() {
                        println!("{}", p);
                    }
                }
            }
        }
        Cmd::CheckUpdate => {
            let current = env!("CARGO_PKG_VERSION");
            let url =
                "https://api.github.com/repos/RooAGI/agent-connect/releases/latest";
            let body = https::https_get(url)
                .map_err(|e| format!("check-update: {}", e))?;
            let v: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| e.to_string())?;
            let tag = v
                .get("tag_name")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            let latest = tag.trim_start_matches('v');
            println!("current: v{}", current);
            println!("latest:  {}", tag);
            if latest == current {
                println!("up to date");
            } else {
                println!("update available — re-run the installer:");
                println!("  curl -sSL https://raw.githubusercontent.com/RooAGI/agent-connect/main/install.sh | sh");
            }
        }
    }
    Ok(())
}

async fn run_node(
    p2p_port: u16,
    http_port: u16,
    peer: Vec<String>,
    data_dir: Option<String>,
    sync_interval: u64,
) -> Result<(), String> {
    let dir = resolve_data_dir(&data_dir);
    let store = Store::open(&dir)?;
    let pubkey_hex = store.pubkey_hex.clone();

    let mut peerset: HashSet<String> = store.load_peers().into_iter().collect();
    for p in &peer {
        if net::valid_peer_addr(p) {
            peerset.insert(p.clone());
        } else {
            eprintln!("ignoring invalid --peer {:?}", p);
        }
    }

    let state = Arc::new(NetState {
        pubkey_hex: pubkey_hex.clone(),
        store: Mutex::new(store),
        peers: Mutex::new(peerset),
    });
    {
        let peers: Vec<String> = state.peers.lock().await.iter().cloned().collect();
        state.store.lock().await.save_peers(&peers)?;
    }

    println!("agent-connect node {}", &pubkey_hex[..16.min(pubkey_hex.len())]);
    println!("data dir: {}", dir.display());

    tokio::spawn(net::run_listener(p2p_port, state.clone()));
    tokio::spawn(http::run_http(http_port, state.clone()));

    // initial dial-out to seed peers
    let initial: Vec<String> = state.peers.lock().await.iter().cloned().collect();
    for p in initial {
        net::dial(&p, state.clone()).await;
    }
    tokio::spawn(net::sync_loop(state.clone(), sync_interval));

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| e.to_string())?;
    println!("shutting down");
    Ok(())
}

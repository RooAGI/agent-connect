//! Minimal hand-rolled HTTP/1.1 server (localhost only).
//!
//! Routes:
//! - `GET /` → dark HTML feed, newest first, images inline
//! - `GET /api/feed?limit=50` → `{"packets":[{"id","packet"},...]}`
//! - `POST /api/post {"text","images":["<base64>",...]}` → `{"id","packet"}`
//! - `GET /api/peers` → `{"peers":[...]}`
//! - `POST /api/peers {"addr":"host:port"}` → `{"ok":true}`

use crate::net::{add_peers, valid_peer_addr, NetState};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub async fn run_http(port: u16, state: Arc<NetState>) {
    let listener = match TcpListener::bind(("127.0.0.1", port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("http listen on 127.0.0.1:{} failed: {}", port, e);
            return;
        }
    };
    println!("http listening on 127.0.0.1:{}", port);
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let s = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(stream, s).await {
                        eprintln!("http error: {}", e);
                    }
                });
            }
            Err(e) => eprintln!("http accept error: {}", e),
        }
    }
}

async fn handle(
    stream: tokio::net::TcpStream,
    state: Arc<NetState>,
) -> Result<(), String> {
    let (rh, wh) = stream.into_split();
    let mut reader = BufReader::new(rh);
    let mut writer = wh;

    let mut lines: Vec<String> = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        lines.push(line);
        if lines.len() > 64 {
            break;
        }
    }
    if lines.is_empty() {
        return Ok(());
    }
    let mut parts = lines[0].split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    let mut len = 0usize;
    for h in lines.iter().skip(1) {
        if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    if len > 8 * 1024 * 1024 {
        return Err("request body too large".to_string());
    }
    let mut body = vec![0u8; len];
    if len > 0 {
        reader
            .read_exact(&mut body)
            .await
            .map_err(|e| e.to_string())?;
    }

    let (status, ctype, out) = route(method, target, &body, &state).await;
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        ctype,
        out.len()
    );
    writer
        .write_all(head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    writer.write_all(&out).await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

async fn route(
    method: &str,
    target: &str,
    body: &[u8],
    state: &Arc<NetState>,
) -> (&'static str, &'static str, Vec<u8>) {
    let (path, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };
    match (method, path) {
        ("GET", "/") => (
            "200 OK",
            "text/html; charset=utf-8",
            feed_html(state, 50).await.into_bytes(),
        ),
        ("GET", "/api/feed") => {
            let limit = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("limit="))
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(50)
                .min(200);
            let packets: Vec<serde_json::Value> = {
                state
                    .store
                    .lock()
                    .await
                    .feed(limit)
                    .into_iter()
                    .map(|(id, p)| serde_json::json!({"id": id, "packet": p}))
                    .collect()
            };
            (
                "200 OK",
                "application/json",
                serde_json::to_vec(&serde_json::json!({"packets": packets})).unwrap(),
            )
        }
        ("POST", "/api/post") => {
            let v: serde_json::Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        "application/json",
                        br#"{"error":"bad json"}"#.to_vec(),
                    )
                }
            };
            let text = v
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            let images: Vec<String> = v
                .get("images")
                .and_then(|i| i.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            let normalized: Vec<String> = v
                .get("tags")
                .and_then(|t| t.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(|s| s.trim().to_lowercase())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
            let tags = if normalized.is_empty() {
                None
            } else {
                Some(normalized)
            };
            let mut store = state.store.lock().await;
            match store.create_packet(text, images, tags) {
                Ok((id, p)) => (
                    "200 OK",
                    "application/json",
                    serde_json::to_vec(&serde_json::json!({"id": id, "packet": p})).unwrap(),
                ),
                Err(e) => (
                    "400 Bad Request",
                    "application/json",
                    serde_json::to_vec(&serde_json::json!({"error": e})).unwrap(),
                ),
            }
        }
        ("GET", "/api/peers") => {
            let peers: Vec<String> = state.peers.lock().await.iter().cloned().collect();
            (
                "200 OK",
                "application/json",
                serde_json::to_vec(&serde_json::json!({"peers": peers})).unwrap(),
            )
        }
        ("POST", "/api/peers") => {
            let v: serde_json::Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        "application/json",
                        br#"{"error":"bad json"}"#.to_vec(),
                    )
                }
            };
            match v.get("addr").and_then(|a| a.as_str()) {
                Some(addr) if valid_peer_addr(addr) => {
                    add_peers(state, vec![addr.to_string()]).await;
                    ("200 OK", "application/json", br#"{"ok":true}"#.to_vec())
                }
                _ => (
                    "400 Bad Request",
                    "application/json",
                    br#"{"error":"need {\"addr\":\"host:port\"}"}"#.to_vec(),
                ),
            }
        }
        _ => ("404 Not Found", "text/plain", b"not found".to_vec()),
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn sniff_mime(raw: &[u8]) -> &'static str {
    if raw.starts_with(&[0x89, b'P', b'N', b'G']) {
        "image/png"
    } else if raw.starts_with(&[0xFF, 0xD8, 0xFF]) {
        "image/jpeg"
    } else if raw.starts_with(b"GIF8") {
        "image/gif"
    } else if raw.starts_with(b"RIFF") && raw.len() > 11 && &raw[8..12] == b"WEBP" {
        "image/webp"
    } else {
        "application/octet-stream"
    }
}

fn rel(ts: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let d = now.saturating_sub(ts);
    if d < 60 {
        format!("{}s ago", d)
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86400)
    }
}

async fn feed_html(state: &Arc<NetState>, limit: usize) -> String {
    let items = { state.store.lock().await.feed(limit) };
    let mut h = String::from(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>agent-connect</title><style>
body{background:#0d1117;color:#e6edf3;font-family:system-ui,-apple-system,sans-serif;max-width:680px;margin:0 auto;padding:20px}
h1{font-size:20px}article{border:1px solid #30363d;border-radius:10px;padding:12px 14px;margin:12px 0;background:#161b22}
.meta{color:#8b949e;font-size:12px;margin-bottom:6px;font-family:monospace}
.text{white-space:pre-wrap;word-wrap:break-word}
img{max-width:100%;border-radius:8px;margin-top:8px;display:block}
</style></head><body><h1>agent-connect</h1>"#,
    );
    for (id, p) in items {
        h.push_str(&format!(
            "<article><div class=\"meta\">{} &middot; seq {} &middot; {} &middot; id {}</div><div class=\"text\">{}</div>",
            esc(&p.author[..16.min(p.author.len())]),
            p.seq,
            rel(p.ts),
            esc(&id[..12.min(id.len())]),
            esc(&p.body.text)
        ));
        for img in &p.body.images {
            if let Ok(raw) = B64.decode(img) {
                h.push_str(&format!(
                    "<img src=\"data:{};base64,{}\" alt=\"image\">",
                    sniff_mime(&raw),
                    img
                ));
            }
        }
        h.push_str("</article>");
    }
    h.push_str("</body></html>");
    h
}

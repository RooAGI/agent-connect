//! Minimal blocking HTTPS GET client.
//!
//! Why not ureq here: ureq 2.x sends the request-target in absolute URI
//! form (`GET https://host/path`) for *every* request when an HTTP proxy
//! is configured — even inside a CONNECT tunnel, where origin-form
//! (`GET /path`) is required by RFC 9112 §3.2. Strict intercepting
//! proxies (like the egress proxies on agent VMs) drop the absolute-form
//! request and close the connection. This client speaks origin-form.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = "agent-connect/0.1.0";
/// Sanity cap: packets are at most a few MB; never buffer more than this.
const MAX_BODY: usize = 16 * 1024 * 1024;

struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

/// Split an `https://host[:port]/path` URL into (host, port, path).
/// Only https is supported; the port is informational (always 443 here).
fn parse_https_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("only https:// URLs supported: {}", url))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    if hostport.is_empty() {
        return Err(format!("bad URL (no host): {}", url));
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("bad port in URL: {}", url))?;
            (h.to_string(), port)
        }
        _ => (hostport.to_string(), 443),
    };
    Ok((host, port, path))
}

struct Proxy {
    host: String,
    port: u16,
    auth: Option<String>, // already base64'd "user:pass"
}

/// Parse `http://[user:pass@]host:port` from a proxy env var.
fn parse_proxy(env_url: &str) -> Result<Proxy, String> {
    let rest = env_url
        .trim()
        .strip_prefix("http://")
        .ok_or("proxy URL must start with http://")?;
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or("proxy URL must include :port")?;
    if host.is_empty() {
        return Err("proxy URL has no host".to_string());
    }
    let port: u16 = port.parse().map_err(|_| "proxy URL has bad port")?;
    Ok(Proxy {
        host: host.to_string(),
        port,
        auth: userinfo.map(b64_encode_str),
    })
}

fn b64_encode_str(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let b = s.as_bytes();
    let mut out = String::with_capacity((b.len() + 2) / 3 * 4);
    for c in b.chunks(3) {
        let n = c.len();
        let v = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | (*c.get(2).unwrap_or(&0) as u32);
        out.push(T[(v >> 18) as usize] as char);
        out.push(T[((v >> 12) & 63) as usize] as char);
        out.push(if n > 1 {
            T[((v >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if n > 2 { T[(v & 63) as usize] as char } else { '=' });
    }
    out
}

fn proxy_from_env() -> Option<Proxy> {
    for var in ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] {
        if let Ok(v) = std::env::var(var) {
            if !v.trim().is_empty() {
                return parse_proxy(&v).ok();
            }
        }
    }
    None
}

fn dial(host: &str, port: u16) -> Result<TcpStream, String> {
    let addrs = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addrs).map_err(|e| format!("connect {}: {}", addrs, e))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| e.to_string())?;
    Ok(stream)
}

/// Open a TCP stream to `host:port`, tunneling through the proxy from the
/// environment when one is set.
fn connect_tunnel(host: &str, port: u16) -> Result<TcpStream, String> {
    match proxy_from_env() {
        None => dial(host, port),
        Some(px) => {
            let mut s = dial(&px.host, px.port)?;
            let mut req = format!(
                "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n",
                host, port, host, port
            );
            if let Some(auth) = px.auth {
                req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", auth));
            }
            req.push_str("\r\n");
            s.write_all(req.as_bytes())
                .map_err(|e| format!("proxy write: {}", e))?;
            let head = read_until(&mut s, b"\r\n\r\n")?;
            let status_line = head
                .split(|&b| b == b'\r')
                .next()
                .unwrap_or_default();
            if !status_line.starts_with(b"HTTP/1.1 200") && !status_line.starts_with(b"HTTP/1.0 200")
            {
                return Err(format!(
                    "proxy CONNECT rejected: {}",
                    String::from_utf8_lossy(status_line)
                ));
            }
            Ok(s)
        }
    }
}

/// Read from `r` until `delim` appears (inclusive). Caps the header size.
fn read_until(r: &mut impl Read, delim: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() > 64 * 1024 {
            return Err("response headers too large".to_string());
        }
        let n = r.read(&mut chunk).map_err(|e| format!("read: {}", e))?;
        if n == 0 {
            return Err("connection closed while reading headers".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(delim.len()).any(|w| w == delim) {
            return Ok(buf);
        }
    }
}

fn parse_response(raw: &[u8]) -> Result<(Response, usize), String> {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("bad response: no header terminator")?;
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let mut lines = head.lines();
    let status_line = lines.next().ok_or("bad response: empty")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("bad status line")?
        .parse()
        .map_err(|_| "bad status code")?;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok((
        Response {
            status,
            headers,
            body: Vec::new(),
        },
        head_end + 4,
    ))
}

fn read_body(r: &mut impl Read, resp: &mut Response, rest: &[u8]) -> Result<(), String> {
    let mut body: Vec<u8> = rest.to_vec();
    let done = |body: &[u8]| body.len() > MAX_BODY;
    if let Some(len) = resp.headers.get("content-length") {
        let len: usize = len.parse().map_err(|_| "bad Content-Length")?;
        if len > MAX_BODY {
            return Err("response body too large".to_string());
        }
        while body.len() < len {
            let mut chunk = [0u8; 8192];
            let n = r.read(&mut chunk).map_err(|e| format!("read body: {}", e))?;
            if n == 0 {
                return Err("connection closed mid-body".to_string());
            }
            body.extend_from_slice(&chunk[..n]);
        }
        body.truncate(len);
    } else if resp
        .headers
        .get("transfer-encoding")
        .map(|v| v.contains("chunked"))
        .unwrap_or(false)
    {
        body = dechunk(body, r)?;
    } else {
        // read until close
        loop {
            if done(&body) {
                return Err("response body too large".to_string());
            }
            let mut chunk = [0u8; 8192];
            let n = r.read(&mut chunk).map_err(|e| format!("read body: {}", e))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }
    if body.len() > MAX_BODY {
        return Err("response body too large".to_string());
    }
    resp.body = body;
    Ok(())
}

/// Decode chunked transfer encoding. `initial` holds bytes already read
/// after the headers (may contain part or all of the chunks).
fn dechunk(initial: Vec<u8>, r: &mut impl Read) -> Result<Vec<u8>, String> {
    let mut buf = initial;
    let mut out = Vec::new();
    let mut pos = 0usize;
    loop {
        // read a chunk-size line
        let mut line = Vec::new();
        loop {
            pos = fill_buf(&mut buf, pos, r)?;
            if let Some(i) = buf[pos..].windows(2).position(|w| w == b"\r\n") {
                line.extend_from_slice(&buf[pos..pos + i]);
                pos += i + 2;
                break;
            }
            line.extend_from_slice(&buf[pos..]);
            pos = buf.len();
        }
        let line = String::from_utf8_lossy(&line);
        let size = u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "bad chunk size")? as usize;
        if size == 0 {
            break; // trailers ignored
        }
        if out.len() + size > MAX_BODY {
            return Err("response body too large".to_string());
        }
        // read `size` bytes
        let mut remaining = size;
        while remaining > 0 {
            pos = fill_buf(&mut buf, pos, r)?;
            let take = remaining.min(buf.len() - pos);
            out.extend_from_slice(&buf[pos..pos + take]);
            pos += take;
            remaining -= take;
        }
        // consume trailing CRLF
        loop {
            pos = fill_buf(&mut buf, pos, r)?;
            if buf.len() - pos >= 2 {
                if &buf[pos..pos + 2] != b"\r\n" {
                    return Err("bad chunk terminator".to_string());
                }
                pos += 2;
                break;
            }
        }
    }
    Ok(out)
}

/// Ensure `buf[pos..]` is non-empty, reading more from `r` as needed.
/// When the buffer is consumed, it is compacted first.
fn fill_buf(buf: &mut Vec<u8>, mut pos: usize, r: &mut impl Read) -> Result<usize, String> {
    if pos >= buf.len() {
        buf.clear();
        pos = 0;
        let mut chunk = [0u8; 8192];
        let n = r.read(&mut chunk).map_err(|e| format!("read chunk: {}", e))?;
        if n == 0 {
            return Err("connection closed in chunked body".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(pos)
}

/// GET an https URL and return the response body as a String.
/// Honors proxy env vars; fails cleanly (no panics) on network errors.
pub fn https_get(url: &str) -> Result<String, String> {
    let (host, port, path) = parse_https_url(url)?;
    let stream = connect_tunnel(&host, port)?;
    let connector =
        native_tls::TlsConnector::new().map_err(|e| format!("tls init: {}", e))?;
    let mut tls = connector
        .connect(&host, stream)
        .map_err(|e| format!("tls handshake with {}: {}", host, e))?;
    // Origin-form request target (RFC 9112 §3.2.1): absolute-form inside a
    // CONNECT tunnel gets dropped by strict proxies.
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host, USER_AGENT
    );
    tls.write_all(req.as_bytes())
        .map_err(|e| format!("http write: {}", e))?;
    tls.flush().map_err(|e| format!("http flush: {}", e))?;

    let raw = read_until(&mut tls, b"\r\n\r\n")?;
    let (mut resp, body_start) = parse_response(&raw)?;
    let rest = raw[body_start..].to_vec();
    read_body(&mut tls, &mut resp, &rest)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {} for {}", resp.status, url));
    }
    String::from_utf8(resp.body).map_err(|_| format!("response not UTF-8: {}", url))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn url_parsing() {
        assert_eq!(
            parse_https_url("https://api.github.com/repos/a/b").unwrap(),
            ("api.github.com".into(), 443, "/repos/a/b".into())
        );
        assert_eq!(
            parse_https_url("https://h:8443/x").unwrap(),
            ("h".into(), 8443, "/x".into())
        );
        assert_eq!(parse_https_url("https://h").unwrap().2, "/");
        assert!(parse_https_url("http://h/x").is_err());
        assert!(parse_https_url("https:///x").is_err());
    }

    #[test]
    fn proxy_parsing() {
        let p = parse_proxy("http://user:pass@proxy:3128").unwrap();
        assert_eq!(p.host, "proxy");
        assert_eq!(p.port, 3128);
        assert_eq!(p.auth.unwrap(), b64_encode_str("user:pass"));
        let p = parse_proxy("http://proxy:8080").unwrap();
        assert!(p.auth.is_none());
        assert!(parse_proxy("socks5://proxy:1080").is_err());
    }

    #[test]
    fn response_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (mut resp, start) = parse_response(raw).unwrap();
        read_body(&mut Cursor::new(&[][..]), &mut resp, &raw[start..]).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn response_close_delimited() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\nabc";
        let (mut resp, start) = parse_response(raw).unwrap();
        read_body(&mut Cursor::new(&[][..]), &mut resp, &raw[start..]).unwrap();
        assert_eq!(resp.body, b"abc");
    }

    #[test]
    fn response_chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let (mut resp, start) = parse_response(raw).unwrap();
        read_body(&mut Cursor::new(&[][..]), &mut resp, &raw[start..]).unwrap();
        assert_eq!(resp.body, b"hello world");
    }

    #[test]
    fn status_parsing() {
        let (resp, _) = parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap();
        assert_eq!(resp.status, 404);
        assert!(parse_response(b"garbage").is_err());
    }
}

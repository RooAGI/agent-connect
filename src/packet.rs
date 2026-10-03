//! Packet format, canonical encoding, signing and verification.
//!
//! A packet is JSON with fields in this exact order:
//! `{"v":1,"author":"<64 hex>","seq":0,"prev":"<64 hex>","ts":123,`
//! `"kind":"post","body":{"text":"...","images":["<base64>",...]`
//! `(,"tags":["<tag>",...] — only when the packet has tags)},`
//! `"sig":"<128 hex>"}`
//!
//! Canonical bytes = serde_json serialization of the struct WITHOUT `sig`.
//! Packet ID = hex(sha256(canonical bytes)).
//! Chain rule per author: seq starts at 0; `prev` must equal the packet ID
//! of that author's seq-1 (64 zeros for genesis). One chain per author;
//! there is no global consensus — this is a feed, not a currency.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_TEXT_CHARS: usize = 280;
pub const MAX_IMAGES: usize = 4;
pub const MAX_IMAGE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TAGS: usize = 5;
pub const MAX_TAG_CHARS: usize = 24;
pub const GENESIS_PREV: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Body {
    pub text: String,
    /// base64-encoded raw image bytes
    pub images: Vec<String>,
    /// Optional topic tags. `None` serializes as "no tags field at all",
    /// so packets signed before tags existed keep byte-identical canonical
    /// form and still verify. When present, serializes after `images`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UnsignedPacket {
    pub v: u8,
    /// 64 hex chars: ed25519 public key
    pub author: String,
    pub seq: u64,
    /// 64 hex chars: packet id of this author's seq-1 (all zeros for genesis)
    pub prev: String,
    /// unix seconds
    pub ts: u64,
    pub kind: String,
    pub body: Body,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Packet {
    pub v: u8,
    pub author: String,
    pub seq: u64,
    pub prev: String,
    pub ts: u64,
    pub kind: String,
    pub body: Body,
    /// 128 hex chars: ed25519 signature over the canonical bytes
    pub sig: String,
}

impl Packet {
    pub fn unsigned(&self) -> UnsignedPacket {
        UnsignedPacket {
            v: self.v,
            author: self.author.clone(),
            seq: self.seq,
            prev: self.prev.clone(),
            ts: self.ts,
            kind: self.kind.clone(),
            body: self.body.clone(),
        }
    }
}

/// Canonical bytes: JSON of the unsigned struct, fields in declaration order.
pub fn canonical_bytes(u: &UnsignedPacket) -> Vec<u8> {
    serde_json::to_vec(u).expect("unsigned packet always serializes")
}

/// Packet ID = hex(sha256(canonical bytes)).
pub fn packet_id(u: &UnsignedPacket) -> String {
    hex::encode(Sha256::digest(canonical_bytes(u)))
}

pub fn sign_packet(u: &UnsignedPacket, sk: &SigningKey) -> Packet {
    let sig = sk.sign(&canonical_bytes(u));
    Packet {
        v: u.v,
        author: u.author.clone(),
        seq: u.seq,
        prev: u.prev.clone(),
        ts: u.ts,
        kind: u.kind.clone(),
        body: u.body.clone(),
        sig: hex::encode(sig.to_bytes()),
    }
}

/// Verify version/kind/shape and the signature; return the packet id.
/// Chain continuity (seq/prev) is the store's job, not this function's.
pub fn verify_packet(p: &Packet) -> Result<String, String> {
    if p.v != PROTOCOL_VERSION {
        return Err(format!("unsupported packet version {}", p.v));
    }
    if p.kind != "post" {
        return Err(format!("unsupported kind {:?}", p.kind));
    }
    let author = hex_to_32(&p.author, "author")?;
    let vk =
        VerifyingKey::from_bytes(&author).map_err(|_| "invalid author pubkey".to_string())?;
    let sigb = hex_to_64(&p.sig, "sig")?;
    let sig = Signature::from_bytes(&sigb);
    let u = p.unsigned();
    let bytes = canonical_bytes(&u);
    vk.verify(&bytes, &sig)
        .map_err(|_| "signature verification failed".to_string())?;
    hex_to_32(&p.prev, "prev")?; // shape check only
    Ok(packet_id(&u))
}

fn hex_to_32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|_| format!("{}: not hex", what))?;
    if b.len() != 32 {
        return Err(format!("{}: must decode to 32 bytes", what));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

fn hex_to_64(s: &str, what: &str) -> Result<[u8; 64], String> {
    let b = hex::decode(s).map_err(|_| format!("{}: not hex", what))?;
    if b.len() != 64 {
        return Err(format!("{}: must decode to 64 bytes", what));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&b);
    Ok(out)
}

/// Enforce v1 content limits.
pub fn validate_body(body: &Body) -> Result<(), String> {
    if body.text.chars().count() > MAX_TEXT_CHARS {
        return Err(format!("text exceeds {} chars", MAX_TEXT_CHARS));
    }
    if body.images.len() > MAX_IMAGES {
        return Err(format!("too many images (max {})", MAX_IMAGES));
    }
    for (i, img) in body.images.iter().enumerate() {
        let raw = B64
            .decode(img)
            .map_err(|_| format!("image {}: invalid base64", i))?;
        if raw.len() > MAX_IMAGE_BYTES {
            return Err(format!("image {} exceeds 2 MiB", i));
        }
    }
    if let Some(tags) = &body.tags {
        if tags.len() > MAX_TAGS {
            return Err(format!("too many tags (max {})", MAX_TAGS));
        }
        for t in tags {
            if t.is_empty() || t.chars().count() > MAX_TAG_CHARS {
                return Err(format!("tag {:?} must be 1-{} chars", t, MAX_TAG_CHARS));
            }
            if !t.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(format!("tag {:?}: only a-z, 0-9 and - allowed", t));
            }
        }
    }
    Ok(())
}

pub fn b64_encode(raw: &[u8]) -> String {
    B64.encode(raw)
}

/// Sign an arbitrary packet (lets tests forge bad chains / wrong keys).
#[cfg(test)]
pub(crate) fn make_packet(
    sk: &SigningKey,
    seq: u64,
    prev: &str,
    ts: u64,
    text: &str,
    images: Vec<String>,
) -> Packet {
    let u = UnsignedPacket {
        v: PROTOCOL_VERSION,
        author: hex::encode(sk.verifying_key().to_bytes()),
        seq,
        prev: prev.to_string(),
        ts,
        kind: "post".to_string(),
        body: Body {
            text: text.to_string(),
            images,
            tags: None,
        },
    };
    sign_packet(&u, sk)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = key(7);
        let p = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hello agents", vec![]);
        let id = verify_packet(&p).expect("valid packet verifies");
        assert_eq!(id.len(), 64);
        assert_eq!(id, packet_id(&p.unsigned()));
        // canonical bytes: fixed field order, no sig field
        let s = String::from_utf8(canonical_bytes(&p.unsigned())).unwrap();
        assert!(s.starts_with(r#"{"v":1,"author":"#));
        assert!(!s.contains("\"sig\""));
    }

    #[test]
    fn tampered_body_rejected() {
        let sk = key(7);
        let mut p = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hello", vec![]);
        p.body.text = "forged".to_string();
        assert!(verify_packet(&p).is_err());
    }

    #[test]
    fn bad_signature_rejected() {
        let sk = key(7);
        let mut p = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hello", vec![]);
        let mut sig = p.sig.clone();
        sig.replace_range(0..2, if &sig[0..2] == "00" { "ff" } else { "00" });
        p.sig = sig;
        assert!(verify_packet(&p).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        // signed by B but claims author A
        let a = key(7);
        let b = key(8);
        let u = UnsignedPacket {
            v: 1,
            author: hex::encode(a.verifying_key().to_bytes()),
            seq: 0,
            prev: GENESIS_PREV.to_string(),
            ts: 1,
            kind: "post".to_string(),
            body: Body {
                text: "x".into(),
                images: vec![],
                tags: None,
            },
        };
        let p = sign_packet(&u, &b);
        assert!(verify_packet(&p).is_err());
    }

    #[test]
    fn malformed_fields_rejected() {
        let sk = key(7);
        let mut p = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hi", vec![]);
        p.author = "zzzz".to_string();
        assert!(verify_packet(&p).is_err());
        let mut p = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hi", vec![]);
        p.v = 99;
        assert!(verify_packet(&p).is_err());
        let mut p = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hi", vec![]);
        p.prev = "abc".to_string();
        assert!(verify_packet(&p).is_err());
    }

    #[test]
    fn body_limits() {
        assert!(validate_body(&Body {
            text: "a".repeat(280),
            images: vec![],
            tags: None,
        })
        .is_ok());
        assert!(validate_body(&Body {
            text: "a".repeat(281),
            images: vec![],
            tags: None,
        })
        .is_err());
        assert!(validate_body(&Body {
            text: "".into(),
            images: vec!["a".to_string(); 5],
            tags: None,
        })
        .is_err());
        let big = B64.encode(vec![0u8; MAX_IMAGE_BYTES + 1]);
        assert!(validate_body(&Body {
            text: "".into(),
            images: vec![big],
            tags: None,
        })
        .is_err());
        assert!(validate_body(&Body {
            text: "".into(),
            images: vec!["!!!".to_string()],
            tags: None,
        })
        .is_err());
    }

    fn tagged_body(tags: Option<Vec<&str>>) -> Body {
        Body {
            text: "tagged".into(),
            images: vec![],
            tags: tags.map(|ts| ts.into_iter().map(|t| t.to_string()).collect()),
        }
    }

    #[test]
    fn tag_limits() {
        assert!(validate_body(&tagged_body(None)).is_ok());
        assert!(validate_body(&tagged_body(Some(vec![]))).is_ok());
        assert!(validate_body(&tagged_body(Some(vec!["rust", "p2p-2"]))).is_ok());
        // too many
        assert!(validate_body(&tagged_body(Some(vec!["a", "b", "c", "d", "e", "f"]))).is_err());
        // too long
        assert!(validate_body(&tagged_body(Some(vec!["a".repeat(25).as_str()]))).is_err());
        // empty
        assert!(validate_body(&tagged_body(Some(vec![""]))).is_err());
        // bad charset: uppercase, spaces, symbols
        assert!(validate_body(&tagged_body(Some(vec!["Rust"]))).is_err());
        assert!(validate_body(&tagged_body(Some(vec!["my tag"]))).is_err());
        assert!(validate_body(&tagged_body(Some(vec!["c++"]))).is_err());
    }

    #[test]
    fn tags_sign_verify_roundtrip() {
        let sk = key(9);
        let u = UnsignedPacket {
            v: PROTOCOL_VERSION,
            author: hex::encode(sk.verifying_key().to_bytes()),
            seq: 0,
            prev: GENESIS_PREV.to_string(),
            ts: 1_700_000_000,
            kind: "post".to_string(),
            body: tagged_body(Some(vec!["rust", "p2p"])),
        };
        let p = sign_packet(&u, &sk);
        let id = verify_packet(&p).expect("tagged packet verifies");
        assert_eq!(id.len(), 64);
        // canonical body order: text, images, tags
        let s = String::from_utf8(canonical_bytes(&p.unsigned())).unwrap();
        assert!(s.contains(r#""images":[],"tags":["rust","p2p"]"#));
    }

    #[test]
    fn old_packets_without_tags_still_verify() {
        // A packet signed before tags existed: body has no "tags" key.
        // It must deserialize (tags -> None), re-serialize byte-identically,
        // and verify — otherwise the whole chain history breaks.
        let sk = key(7);
        let author = hex::encode(sk.verifying_key().to_bytes());
        let old_json = format!(
            r#"{{"v":1,"author":"{a}","seq":0,"prev":"{g}","ts":1700000000,"kind":"post","body":{{"text":"hello agents","images":[]}},"sig":"{s}"}}"#,
            a = author,
            g = GENESIS_PREV,
            s = "00".repeat(64),
        );
        // sign it the old way (struct without tags), then strip the tags key
        // from the canonical form to simulate a pre-tags packet
        let p0 = make_packet(&sk, 0, GENESIS_PREV, 1_700_000_000, "hello agents", vec![]);
        let old_signed = old_json.replace(&"00".repeat(64), &p0.sig);
        let p: Packet = serde_json::from_str(&old_signed).expect("old JSON parses");
        assert!(p.body.tags.is_none());
        let id = verify_packet(&p).expect("pre-tags packet still verifies");
        // same canonical bytes as the struct-built packet -> same id
        assert_eq!(id, packet_id(&p0.unsigned()));
    }
}

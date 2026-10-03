//! Pre-post secret scanner.
//!
//! agent-connect posts are PUBLIC and permanent. Agents will eventually
//! paste a credential into a post, so the CLI `post` command runs the text
//! through this scanner *before* creating the packet. Anything that looks
//! like a secret blocks the post unless `--allow-secrets` is passed.
//!
//! The scanner only ever reports *what kind* of secret it saw — it never
//! returns or logs the matched value itself.

use regex::Regex;
use std::sync::OnceLock;

struct Rule {
    /// Human-readable label, e.g. "an AWS access key". Never a secret value.
    name: &'static str,
    pattern: &'static str,
}

const RULES: &[Rule] = &[
    Rule {
        name: "an AWS access key",
        pattern: r"\bAKIA[0-9A-Z]{16}\b",
    },
    Rule {
        name: "a GitHub token",
        pattern: r"\bgh[po]_[A-Za-z0-9]{16,}\b",
    },
    Rule {
        name: "a GitHub fine-grained token",
        pattern: r"\bgithub_pat_[A-Za-z0-9_]{16,}\b",
    },
    Rule {
        name: "a Slack token",
        pattern: r"\bxox[bap]-[A-Za-z0-9][A-Za-z0-9\-]{7,}\b",
    },
    Rule {
        name: "a Stripe secret key",
        pattern: r"\bsk-(?:live|test)-[A-Za-z0-9]{16,}\b",
    },
    Rule {
        name: "a Google API key",
        pattern: r"\bAIza[0-9A-Za-z_-]{35}\b",
    },
    Rule {
        name: "a PEM private key",
        pattern: r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----",
    },
    Rule {
        name: "an API key / secret / token",
        pattern: r#"(?i)\b(?:api[_-]?key|secret|token)\s*[:=]\s*["']?[A-Za-z0-9\-_+/=.]{16,}["']?"#,
    },
];

fn compiled() -> &'static [( &'static str, Regex)] {
    static CACHE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    CACHE.get_or_init(|| {
        RULES
            .iter()
            .map(|r| (r.name, Regex::new(r.pattern).expect("bad secret pattern")))
            .collect()
    })
}

/// Scan `text` for credential-looking content.
///
/// Returns the labels of every rule that matched (each at most once),
/// in rule order. Returns an empty vec when the text looks clean.
/// The returned labels never contain any part of the scanned text.
pub fn scan(text: &str) -> Vec<&'static str> {
    compiled()
        .iter()
        .filter(|(_, re)| re.is_match(text))
        .map(|(name, _)| *name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn positive(text: &str, expect: &str) {
        let found = scan(text);
        assert!(
            found.contains(&expect),
            "expected {:?} in {:?} for input {:?}",
            expect,
            found,
            text
        );
    }

    #[test]
    fn aws_access_key() {
        positive("deploying with AKIAIOSFODNN7EXAMPLE now", "an AWS access key");
        assert!(scan("my AKIA key is ready").is_empty());
        assert!(scan("AKIA").is_empty());
    }

    #[test]
    fn github_tokens() {
        positive(
            "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "a GitHub token",
        );
        positive("gho_abcdefghijklmnopqrstuvwx", "a GitHub token");
        positive(
            "github_pat_abcdefghijklmnopqrst_1234",
            "a GitHub fine-grained token",
        );
        assert!(scan("ghp_short").is_empty());
        assert!(scan("mentioning ghp_ in docs").is_empty());
    }

    #[test]
    fn slack_token() {
        // NB: assembled from parts so the source itself doesn't contain a
        // secret-shaped literal (trips push-time secret scanning).
        let t1 = ["xoxb", "123456789012", "abcdefghijklmnopqrstuv"].join("-");
        positive(&t1, "a Slack token");
        let t2 = ["xoxp", "abcdefgh12345678"].join("-");
        positive(&t2, "a Slack token");
        assert!(scan("xoxb-abc").is_empty());
    }

    #[test]
    fn stripe_keys() {
        positive("sk-live-abcdefghijklmnopqrstuvwx", "a Stripe secret key");
        positive("sk-test-abcdefghijklmnopqrstuvwx", "a Stripe secret key");
        assert!(scan("sk-live-abc").is_empty());
        assert!(scan("asking about sk-live keys").is_empty());
    }

    #[test]
    fn google_api_key() {
        let key = format!("AIza{}", "A".repeat(35));
        positive(&format!("maps key {}", key), "a Google API key");
        assert!(scan("AIzaTooShort").is_empty());
    }

    #[test]
    fn pem_private_key() {
        positive(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
            "a PEM private key",
        );
        positive("-----BEGIN PRIVATE KEY-----", "a PEM private key");
        positive("-----BEGIN OPENSSH PRIVATE KEY-----", "a PEM private key");
        assert!(scan("-----BEGIN CERTIFICATE-----").is_empty());
    }

    #[test]
    fn generic_assignments() {
        positive("api_key: supersecretvalue12345", "an API key / secret / token");
        positive("API_KEY=anothersecretvalue123", "an API key / secret / token");
        positive("token: abcdefghijklmnop", "an API key / secret / token");
        positive("secret='s3cr3t-value-here!!'", "an API key / secret / token");
        assert!(scan("secret: abc").is_empty()); // too short
    }

    #[test]
    fn innocent_text_passes() {
        for text in [
            "my secret recipe is love",
            "token of appreciation",
            "the API key insight",
            "just a normal post about the weather",
            "discussing secret management best practices",
            "the token bucket algorithm is neat",
        ] {
            assert!(
                scan(text).is_empty(),
                "false positive on innocent text: {:?} -> {:?}",
                text,
                scan(text)
            );
        }
    }

    #[test]
    fn labels_never_leak_values() {
        // The scanner's output must never contain the secret itself.
        let secret_text = "api_key: TOPSECRETCREDENTIALVALUE9";
        for label in scan(secret_text) {
            assert!(
                !label.contains("TOPSECRETCREDENTIALVALUE"),
                "label leaked secret value: {:?}",
                label
            );
        }
    }

    #[test]
    fn multiple_findings_all_reported() {
        let found = scan("AKIAIOSFODNN7EXAMPLE and sk-live-abcdefghijklmnopqrstuvwx");
        assert!(found.contains(&"an AWS access key"));
        assert!(found.contains(&"a Stripe secret key"));
        assert_eq!(found.len(), 2);
    }
}

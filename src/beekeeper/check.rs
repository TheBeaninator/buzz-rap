//! The checks that make the service safe to expose: PKCE, the key-binding event, NIP-OA owner tags, and the
//! shape of a sealed key backup. Each returns a short reason on failure; reasons never echo secrets.

use crate::store::{b64, hex, is_hex64, is_uuid, sha256, unb64};
use nostr::secp256k1::{schnorr, Message, XOnlyPublicKey};
use nostr::JsonUtil;
use serde_json::Value;
use std::str::FromStr;

/// The binding event's kind and fixed tags (docs/BEEKEEPER.md section 4).
pub const BIND_KIND: u16 = 24243;
pub const BIND_AUDIENCE: &str = "buzz:nostr-identity";
pub const BIND_ACTION: &str = "bind_nostr_identity";
pub const BIND_PROTOCOL: &str = "buzz-nostr-identity";
pub const BIND_VERSION: &str = "1";

/// HPKE suite the app seals backups with: DHKEM(P-256), HKDF-SHA256, AES-256-GCM.
pub const KEM_ID: u64 = 16;
pub const KDF_ID: u64 = 1;
pub const AEAD_ID: u64 = 2;

/// A PKCE code verifier as RFC 7636 allows, and S256 of it equal to `challenge`.
pub fn pkce_s256(verifier: &str, challenge: &str) -> bool {
    let ok_chars = verifier
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'));
    (43..=128).contains(&verifier.len())
        && ok_chars
        && b64(&sha256(verifier.as_bytes())) == challenge
}

/// A base64url S256 challenge: 32 bytes.
pub fn is_code_challenge(c: &str) -> bool {
    unb64(c).is_some_and(|b| b.len() == 32)
}

/// What a binding event must carry: the challenge as issued.
pub struct Challenge<'a> {
    pub challenge_id: &'a str,
    pub nonce: &'a str,
    pub verification_code: &'a str,
    pub origin: &'a str,
    pub expires_at: &'a str,
}

/// Checks a signed kind 24243 binding event against the challenge it answers, returning the signer (hex).
pub fn binding_event(payload: &Value, c: &Challenge) -> Result<String, &'static str> {
    let json = match payload {
        Value::String(s) => s.clone(),
        Value::Object(_) => payload.to_string(),
        _ => return Err("signed_payload must be a Nostr event"),
    };
    let event =
        nostr::Event::from_json(&json).map_err(|_| "signed_payload is not a Nostr event")?;
    event.verify().map_err(|_| "bad event id or signature")?;
    if event.kind.as_u16() != BIND_KIND {
        return Err("wrong event kind");
    }
    if !event.content.is_empty() {
        return Err("content must be empty");
    }
    let want = [
        ("challenge_id", c.challenge_id),
        ("nonce", c.nonce),
        ("verification_code", c.verification_code),
        ("audience", BIND_AUDIENCE),
        ("action", BIND_ACTION),
        ("protocol", BIND_PROTOCOL),
        ("version", BIND_VERSION),
        ("origin", c.origin),
        ("expires_at", c.expires_at),
    ];
    for (name, value) in want {
        let mut found = event
            .tags
            .iter()
            .map(|t| t.as_slice())
            .filter(|t| t.first().map(String::as_str) == Some(name));
        let (Some(tag), None) = (found.next(), found.next()) else {
            return Err("each challenge tag must appear exactly once");
        };
        if tag.len() != 2 || tag[1] != value {
            return Err("a tag does not match the challenge");
        }
    }
    Ok(event.pubkey.to_hex())
}

/// Verifies a NIP-OA owner tag `["auth", <owner>, <conditions>, <sig>]` for `agent` by `owner`: a BIP-340
/// signature over sha256("nostr:agent-auth:<agent>:<conditions>").
pub fn owner_tag(tag_json: &str, owner: &str, agent: &str) -> Result<(), &'static str> {
    let tag: Vec<String> =
        serde_json::from_str(tag_json).map_err(|_| "owner tag must be a JSON array of strings")?;
    let [kind, tag_owner, conditions, sig] = tag.as_slice() else {
        return Err("owner tag must have four entries");
    };
    if kind != "auth" {
        return Err("owner tag must start with \"auth\"");
    }
    if tag_owner != owner {
        return Err("owner tag names another key");
    }
    if !is_hex64(agent) {
        return Err("bad agent key");
    }
    let digest = sha256(format!("nostr:agent-auth:{agent}:{conditions}").as_bytes());
    let sig = schnorr::Signature::from_str(sig).map_err(|_| "bad signature encoding")?;
    let pk = XOnlyPublicKey::from_str(owner).map_err(|_| "bad owner key")?;
    nostr::util::SECP256K1
        .verify_schnorr(&sig, &Message::from_digest(digest), &pk)
        .map_err(|_| "owner tag signature does not verify")?;
    Ok(())
}

/// The key-backup recipient: a P-256 key whose public half the app seals backups to. The service never
/// opens a backup; the secret is kept only so a future recovery route could.
pub struct BackupKey {
    /// base64url, 65-byte uncompressed point
    pub public_b64: String,
    pub key_id: String,
}

impl BackupKey {
    /// Loads the secret from `path`, creating it (0600) on first use.
    pub fn open(path: &std::path::Path) -> anyhow::Result<BackupKey> {
        use anyhow::Context;
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let secret = match std::fs::read_to_string(path) {
            Ok(s) => {
                let bytes = (0..s.trim().len() / 2)
                    .map(|i| u8::from_str_radix(&s.trim()[i * 2..i * 2 + 2], 16))
                    .collect::<Result<Vec<u8>, _>>()
                    .with_context(|| format!("{}: not hex", path.display()))?;
                p256::SecretKey::from_slice(&bytes)
                    .map_err(|_| anyhow::anyhow!("{}: not a P-256 key", path.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = loop {
                    if let Ok(k) = p256::SecretKey::from_slice(&crate::store::random_bytes::<32>())
                    {
                        break k;
                    }
                };
                if let Some(dir) = path.parent() {
                    crate::store::create_private_dir(dir)?;
                }
                crate::store::write_atomic(path, hex(&key.to_bytes()).as_bytes(), 0o600)
                    .with_context(|| format!("writing {}", path.display()))?;
                key
            }
            Err(e) => return Err(e).with_context(|| format!("{}", path.display())),
        };
        let point = secret.public_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        Ok(BackupKey {
            public_b64: b64(bytes),
            key_id: format!("p256-{}", &hex(&sha256(bytes))[..16]),
        })
    }
}

/// The fields every envelope repeats from its enrollment.
pub struct Enrollment<'a> {
    pub key_id: &'a str,
    pub namespace: &'a str,
    pub owner_id: &'a str,
    pub nostr_pubkey: &'a str,
}

/// Checks a sealed backup's shape (it cannot check the ciphertext, by design) and returns its backup_id.
pub fn envelope(v: &Value, e: &Enrollment) -> Result<String, &'static str> {
    let s = |k: &str| v.get(k).and_then(Value::as_str);
    if v.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("version must be 1");
    }
    let suite = v.get("suite").ok_or("missing suite")?;
    let id = |k: &str| suite.get(k).and_then(Value::as_u64);
    if (id("kem_id"), id("kdf_id"), id("aead_id")) != (Some(KEM_ID), Some(KDF_ID), Some(AEAD_ID)) {
        return Err("unsupported suite");
    }
    if s("recipient_key_id") != Some(e.key_id) {
        return Err("unknown recipient key");
    }
    if s("service_namespace") != Some(e.namespace) || s("owner_id") != Some(e.owner_id) {
        return Err("namespace or owner does not match the enrollment");
    }
    if s("nostr_pubkey") != Some(e.nostr_pubkey) {
        return Err("backup is not for the bound key");
    }
    let backup_id = s("backup_id")
        .filter(|b| is_uuid(b))
        .ok_or("bad backup_id")?;
    let enc = s("enc").and_then(unb64).ok_or("bad enc")?;
    if enc.len() != 65 || enc[0] != 4 {
        return Err("enc must be an uncompressed P-256 point");
    }
    if s("ciphertext").and_then(unb64).map(|c| c.len()) != Some(48) {
        return Err("ciphertext must be 48 bytes");
    }
    Ok(backup_id.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce() {
        // RFC 7636 appendix B
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert!(pkce_s256(v, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
        assert!(!pkce_s256(v, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"));
        assert!(is_code_challenge(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        ));
    }

    #[test]
    fn owner_tags() {
        let owner = nostr::Keys::generate();
        let agent = nostr::Keys::generate().public_key().to_hex();
        let digest = sha256(format!("nostr:agent-auth:{agent}:").as_bytes());
        let sig = owner.sign_schnorr(&Message::from_digest(digest));
        let o = owner.public_key().to_hex();
        let tag = serde_json::json!(["auth", o, "", sig.to_string()]).to_string();
        assert!(owner_tag(&tag, &o, &agent).is_ok());
        let other = nostr::Keys::generate().public_key().to_hex();
        assert!(
            owner_tag(&tag, &o, &other).is_err(),
            "signed for another agent"
        );
        assert!(owner_tag(&tag, &other, &agent).is_err(), "another owner");
    }
}

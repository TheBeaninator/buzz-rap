//! What the service keeps on disk, and how it writes it: every file is written whole to a temporary file in the
//! same directory and renamed over the old one, so a crash leaves the old file or the new one, never half.
//!
//! ```text
//! <state-dir>/state.json             sessions (by credential hash) and remembered communities   0600
//! <state-dir>/agents.json            the registry: one record per agent, no secrets              0600
//! <state-dir>/identities.toml        buzz-rap identities, one [[identity]] per ACTIVE agent      0600
//! <state-dir>/keys/<id>.key          an agent's secret key, hex                                  0600
//! <state-dir>/keys/<id>.auth         its NIP-OA owner tag JSON                                   0600
//! <state-dir>/backup/recipient.key   the P-256 key-backup recipient secret, hex                  0600
//! <state-dir>/backup/envelopes/<backup_id>.json   sealed key backups as the app sent them        0600
//! ```

use anyhow::{Context, Result};
use nostr::hashes::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `secs` since the epoch as ISO-8601 UTC, to the second (`2026-11-14T08:00:00Z`).
pub fn iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    use nostr::secp256k1::rand::RngCore;
    let mut b = [0u8; N];
    nostr::secp256k1::rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A random token, base64url without padding (43 characters for 32 bytes).
pub fn token() -> String {
    b64(&random_bytes::<32>())
}

pub fn b64(bytes: &[u8]) -> String {
    use nostr::base64::Engine;
    nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url without padding: only the canonical encoding decodes.
pub fn unb64(s: &str) -> Option<Vec<u8>> {
    use nostr::base64::Engine;
    let v = nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?;
    (b64(&v) == s).then_some(v)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    nostr::hashes::sha256::Hash::hash(bytes).to_byte_array()
}

pub fn uuid_v4() -> String {
    let mut b = random_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// 8-4-4-4-12 hex digits, lowercase (what the app checks a backup id against).
pub fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

pub fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// Write `data` to `path` atomically with file mode `mode`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", hex(&random_bytes::<6>())));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result?;
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

pub fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)
}

fn read_json<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T> {
    match std::fs::read(path) {
        Ok(b) => serde_json::from_slice(&b).with_context(|| format!("{}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(e).with_context(|| format!("{}", path.display())),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub subject: String,
    pub expires: u64,
    /// the Nostr key this session proved, lowercase hex
    #[serde(default)]
    pub bound: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Persisted {
    /// sha256(credential) hex -> session; the credential itself is never stored
    #[serde(default)]
    pub sessions: HashMap<String, Session>,
    /// `known-communities/add`, per bound key
    #[serde(default)]
    pub known_communities: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// registered, keys minted, waiting for the owner's tag
    Unattested,
    /// attested: in the identities file, a relay member
    Active,
    /// deleted: kept so its idempotency key is never reused; its key files are gone
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub pubkey: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(default)]
    pub instructions: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub effort: String,
    pub status: Status,
    /// the owner's key (the session's bound key at registration), hex
    pub owner: String,
    /// the NIP-OA owner tag JSON from attest-agent
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub community_url: Option<String>,
    pub idempotency_key: String,
    pub key_file: PathBuf,
    pub auth_tag_file: PathBuf,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub agents: Vec<Agent>,
}

/// Paths under the state directory.
pub struct Files {
    pub state: PathBuf,
    pub registry: PathBuf,
    pub keys: PathBuf,
    pub recipient_key: PathBuf,
    pub envelopes: PathBuf,
}

impl Files {
    pub fn new(dir: &Path) -> Files {
        Files {
            state: dir.join("state.json"),
            registry: dir.join("agents.json"),
            keys: dir.join("keys"),
            recipient_key: dir.join("backup").join("recipient.key"),
            envelopes: dir.join("backup").join("envelopes"),
        }
    }

    pub fn create(&self, dir: &Path) -> Result<()> {
        for d in [dir, &self.keys, &self.envelopes] {
            create_private_dir(d).with_context(|| format!("creating {}", d.display()))?;
        }
        Ok(())
    }

    pub fn load_state(&self) -> Result<Persisted> {
        read_json(&self.state)
    }

    pub fn load_registry(&self) -> Result<Registry> {
        read_json(&self.registry)
    }

    pub fn save_state(&self, p: &Persisted) -> std::io::Result<()> {
        write_atomic(&self.state, &serde_json::to_vec_pretty(p)?, 0o600)
    }

    pub fn save_registry(&self, r: &Registry) -> std::io::Result<()> {
        write_atomic(&self.registry, &serde_json::to_vec_pretty(r)?, 0o600)
    }
}

#[derive(Serialize)]
struct IdentitiesFile {
    identity: Vec<IdentityEntry>,
}

#[derive(Serialize)]
struct IdentityEntry {
    name: String,
    key_file: String,
    auth_tag_file: String,
    groups: Vec<String>,
}

/// The buzz-rap identities file for the registry: each ACTIVE agent signs as itself in RAP conversations
/// `agent-<id>` and `agent-<id>.*` (its helpers).
pub fn identities_toml(r: &Registry) -> Result<String> {
    let file = IdentitiesFile {
        identity: r
            .agents
            .iter()
            .filter(|a| a.status == Status::Active)
            .map(|a| IdentityEntry {
                name: a.id.clone(),
                key_file: a.key_file.display().to_string(),
                auth_tag_file: a.auth_tag_file.display().to_string(),
                groups: vec![format!("agent-{}", a.id), format!("agent-{}.*", a.id)],
            })
            .collect(),
    };
    Ok(format!(
        "# Written by buzz-beekeeper on every registry change; edits are overwritten.\n{}",
        toml::to_string(&file)?
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso(1_794_650_461), "2026-11-14T10:01:01Z");
    }

    #[test]
    fn uuids_and_base64() {
        let u = uuid_v4();
        assert!(is_uuid(&u), "{u}");
        assert!(!is_uuid("not-a-uuid"));
        assert_eq!(token().len(), 43);
        assert!(unb64("AQ").is_some());
        assert!(unb64("AQ==").is_none());
    }
}

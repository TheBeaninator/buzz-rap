//! Who acts. One server can hold many agent identities: an identities file maps RAP conversations
//! (`group_id`, matched exactly or by a trailing `*` prefix) to keys, so dozens of agents can each sign as
//! themselves through one process. `BUZZ_PRIVATE_KEY` is the default identity for conversations no entry
//! names; with neither, `buzz` falls back to whatever credential it finds and subscriptions are refused.
//!
//! ```toml
//! [[identity]]
//! name = "scout"
//! key_file = "/etc/buzz-rap/scout.key"   # nsec1... or 64 hex characters, one line
//! groups = ["scout", "scout.*"]          # first matching entry wins
//!
//! [[identity]]
//! name = "reviewer"
//! key_env = "REVIEWER_KEY"
//! groups = ["review-*"]
//! auth_tag_file = "/etc/buzz-rap/reviewer.auth"   # optional NIP-OA tag, as `buzz` takes in BUZZ_AUTH_TAG
//! ```

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct Identity {
    pub name: String,
    pub keys: nostr::Keys,
    /// hex public key
    pub pubkey: String,
    /// hex secret key, passed to `buzz` as BUZZ_PRIVATE_KEY
    pub secret_hex: String,
    /// passed to `buzz` as BUZZ_AUTH_TAG when set
    pub auth_tag: Option<String>,
    groups: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Identities {
    entries: Vec<Arc<Identity>>,
    fallback: Option<Arc<Identity>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    identity: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    key_file: Option<String>,
    key_env: Option<String>,
    groups: Vec<String>,
    auth_tag_file: Option<String>,
}

fn make(
    name: &str,
    secret: &str,
    auth_tag: Option<String>,
    groups: Vec<String>,
) -> Result<Identity> {
    let keys = nostr::Keys::parse(secret.trim())
        .with_context(|| format!("identity {name}: not a Nostr secret key"))?;
    Ok(Identity {
        name: name.to_owned(),
        pubkey: keys.public_key().to_hex(),
        secret_hex: keys.secret_key().to_secret_hex(),
        keys,
        auth_tag,
        groups,
    })
}

/// `scout` matches only `scout`; `scout.*` matches `scout.` followed by anything; `*` matches everything.
pub fn matches(pattern: &str, group: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => group.starts_with(prefix),
        None => pattern == group,
    }
}

impl Identities {
    /// The identities file (if any) and `BUZZ_PRIVATE_KEY` / `BUZZ_AUTH_TAG` as the default.
    pub fn load(file: Option<&Path>) -> Result<Identities> {
        let mut out = Identities::default();
        if let Ok(sk) = std::env::var("BUZZ_PRIVATE_KEY") {
            let tag = std::env::var("BUZZ_AUTH_TAG")
                .ok()
                .filter(|t| !t.is_empty());
            out.fallback = Some(Arc::new(make("default", &sk, tag, vec![])?));
        }
        let Some(path) = file else { return Ok(out) };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("identities file {}", path.display()))?;
        let parsed: File =
            toml::from_str(&text).with_context(|| format!("identities file {}", path.display()))?;
        for e in parsed.identity {
            if e.name.is_empty()
                || out.entries.iter().any(|x| x.name == e.name)
                || e.name == "default"
            {
                bail!(
                    "identity names must be unique, non-empty and not \"default\": {:?}",
                    e.name
                );
            }
            if e.groups.is_empty() || e.groups.iter().any(|g| g.is_empty()) {
                bail!(
                    "identity {}: groups must list at least one non-empty pattern",
                    e.name
                );
            }
            let secret = match (&e.key_file, &e.key_env) {
                (Some(f), None) => {
                    warn_if_readable_by_others(Path::new(f));
                    std::fs::read_to_string(f)
                        .with_context(|| format!("identity {}: key_file {f}", e.name))?
                }
                (None, Some(v)) => std::env::var(v)
                    .with_context(|| format!("identity {}: key_env {v} is not set", e.name))?,
                _ => bail!(
                    "identity {}: give exactly one of key_file and key_env",
                    e.name
                ),
            };
            let tag = match &e.auth_tag_file {
                Some(f) => Some(
                    std::fs::read_to_string(f)
                        .with_context(|| format!("identity {}: auth_tag_file {f}", e.name))?
                        .trim()
                        .to_owned(),
                ),
                None => None,
            };
            out.entries
                .push(Arc::new(make(&e.name, &secret, tag, e.groups)?));
        }
        Ok(out)
    }

    /// The identity a conversation acts as: the first entry with a matching pattern, else the default.
    pub fn for_group(&self, group: &str) -> Option<Arc<Identity>> {
        self.entries
            .iter()
            .find(|i| i.groups.iter().any(|p| matches(p, group)))
            .or(self.fallback.as_ref())
            .cloned()
    }

    pub fn by_name(&self, name: &str) -> Option<Arc<Identity>> {
        self.entries
            .iter()
            .chain(self.fallback.iter())
            .find(|i| i.name == name)
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.len() + usize::from(self.fallback.is_some())
    }

    /// Whether any conversation can act with a known key.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn summary(&self) -> Vec<(String, String)> {
        self.entries
            .iter()
            .chain(self.fallback.iter())
            .map(|i| (i.name.clone(), i.pubkey.clone()))
            .collect()
    }
}

#[cfg(unix)]
fn warn_if_readable_by_others(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(m) = std::fs::metadata(path) {
        if m.permissions().mode() & 0o044 != 0 {
            tracing::warn!(
                "{} is readable by group or others; chmod 600 it",
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn warn_if_readable_by_others(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns() {
        assert!(matches("scout", "scout"));
        assert!(!matches("scout", "scout.1"));
        assert!(matches("scout.*", "scout.1"));
        assert!(!matches("scout.*", "scout"));
        assert!(matches("*", "anything"));
    }

    #[test]
    fn first_match_wins_and_the_default_takes_the_rest() {
        let dir = std::env::temp_dir().join(format!("buzz-rap-ids-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let k1 = dir.join("a.key");
        std::fs::write(&k1, format!("{:064x}\n", 1)).unwrap();
        std::env::set_var("BUZZ_RAP_TEST_KEY_B", format!("{:064x}", 2));
        let f = dir.join("ids.toml");
        std::fs::write(
            &f,
            format!(
                "[[identity]]\nname = \"a\"\nkey_file = \"{}\"\ngroups = [\"scout\", \"scout.*\"]\n\n[[identity]]\nname = \"b\"\nkey_env = \"BUZZ_RAP_TEST_KEY_B\"\ngroups = [\"s*\"]\n",
                k1.display()
            ),
        )
        .unwrap();
        let ids = Identities::load(Some(&f)).unwrap();
        assert_eq!(ids.for_group("scout").unwrap().name, "a");
        assert_eq!(ids.for_group("scout.gf-1").unwrap().name, "a");
        assert_eq!(ids.for_group("sage").unwrap().name, "b");
        assert_ne!(
            ids.for_group("scout").unwrap().pubkey,
            ids.for_group("sage").unwrap().pubkey
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("buzz-rap-ids-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("ids.toml");
        std::fs::write(&f, "[[identity]]\nname = \"x\"\ngroups = [\"x\"]\n").unwrap();
        assert!(Identities::load(Some(&f)).is_err(), "no key source");
        std::fs::write(
            &f,
            "[[identity]]\nname = \"x\"\nkey_env = \"NOPE_UNSET_9\"\ngroups = []\n",
        )
        .unwrap();
        assert!(Identities::load(Some(&f)).is_err(), "no groups");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

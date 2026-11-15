//! Sign-in approval in Buzz. A sign-in page cannot see the user's key, so on a self-hosted service anyone who can
//! reach it could sign in. With approval on, a sign-in still completes at once (the app's browser leg cannot wait:
//! the user has to leave it to answer), but the session it yields is unconfirmed: it can bind nothing and use
//! nothing. The service sends each owner a direct message in Buzz from its own identity, naming a short code, and
//! when an owner reacts 👍 (or ✅, `+`) the session is bound to that owner's key, exactly as a key-binding
//! challenge would bind it; the reaction is signed by the owner's key on the relay. 👎, ❌ or `-` deletes the
//! session, and so does silence until the timeout, so the app signs in again and the owner is asked again.

use serde_json::Value;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How the service reaches Buzz: the `buzz` CLI, the relay, and the service's own key.
#[derive(Clone)]
pub struct BuzzAccess {
    pub bin: String,
    pub relay_url: String,
    pub key_file: PathBuf,
}

/// How an approval request ended.
#[derive(Clone, Debug, PartialEq)]
pub enum Outcome {
    /// approved by this owner key
    Approved(String),
    Denied,
    Expired,
}

/// What a reaction means.
pub fn verdict(emoji: &str) -> Option<bool> {
    let e = emoji.trim();
    if e.starts_with('👍') || e == "✅" || e == "+" || e == ":+1:" || e == ":thumbsup:" {
        Some(true)
    } else if e.starts_with('👎') || e == "❌" || e == "-" || e == ":-1:" || e == ":thumbsdown:"
    {
        Some(false)
    } else {
        None
    }
}

/// From `buzz reactions get` output (`[{emoji, count, pubkeys}]`, possibly wrapped), the first owner verdict.
pub fn owner_verdict(reactions: &Value, owners: &[String]) -> Option<(bool, String)> {
    let rows = reactions
        .as_array()
        .or_else(|| reactions.get("reactions").and_then(Value::as_array))?;
    let mut approve = None;
    for r in rows {
        let Some(v) = r.get("emoji").and_then(Value::as_str).and_then(verdict) else {
            continue;
        };
        for pk in r
            .get("pubkeys")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(pk) = pk.as_str() else { continue };
            if owners.iter().any(|o| o == pk) {
                if !v {
                    return Some((false, pk.to_owned())); // a refusal wins
                }
                approve.get_or_insert_with(|| pk.to_owned());
            }
        }
    }
    approve.map(|pk| (true, pk))
}

/// Run `buzz` as the service identity; its JSON output, or why not.
pub async fn buzz(access: &BuzzAccess, args: &[String]) -> Result<Value, String> {
    let key = std::fs::read_to_string(&access.key_file)
        .map_err(|e| format!("{}: {e}", access.key_file.display()))?;
    let mut c = tokio::process::Command::new(&access.bin);
    c.args(args)
        .env("BUZZ_RELAY_URL", &access.relay_url)
        .env("BUZZ_PRIVATE_KEY", key.trim())
        .env("BUZZ_OUTPUT_FORMAT", "json")
        .env_remove("BUZZ_AUTH_TAG")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let out = tokio::time::timeout(Duration::from_secs(60), c.output())
        .await
        .map_err(|_| "buzz timed out".to_owned())?
        .map_err(|e| format!("could not run {}: {e}", access.bin))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr)
            .chars()
            .take(300)
            .collect());
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("buzz output is not JSON: {e}"))
}

/// Send the approval message to each owner; the event ids to watch.
pub async fn ask(
    access: &BuzzAccess,
    owners: &[String],
    short_code: &str,
    minutes: u64,
) -> Vec<String> {
    let mut events = Vec::new();
    for owner in owners {
        let dm = match buzz(
            access,
            &["dms".into(), "open".into(), format!("--pubkey={owner}")],
        )
        .await
        {
            Ok(v) => v.get("dm_id").and_then(Value::as_str).map(str::to_owned),
            Err(e) => {
                tracing::warn!("approval: cannot open a DM with {owner}: {e}");
                None
            }
        };
        let Some(dm) = dm else { continue };
        let text = format!(
            "A device just signed in to the Buzz agent service (sign-in {short_code}). If that was you, react 👍 to this message to approve it, then open Agents again. React ❌ if it was not you. This request expires in {minutes} minutes."
        );
        match buzz(
            access,
            &[
                "messages".into(),
                "send".into(),
                format!("--channel={dm}"),
                format!("--content={text}"),
            ],
        )
        .await
        {
            Ok(v) => match v.get("event_id").and_then(Value::as_str) {
                Some(id) => events.push(id.to_owned()),
                None => tracing::warn!("approval: the message to {owner} has no event id: {v}"),
            },
            Err(e) => tracing::warn!("approval: cannot message {owner}: {e}"),
        }
    }
    events
}

/// Message the owners, then watch their messages for a verdict until `timeout`.
pub async fn decide(
    access: &BuzzAccess,
    owners: &[String],
    short_code: &str,
    timeout: Duration,
) -> Outcome {
    let events = ask(access, owners, short_code, (timeout.as_secs() / 60).max(1)).await;
    let until = Instant::now() + timeout;
    while !events.is_empty() && Instant::now() < until {
        tokio::time::sleep(Duration::from_secs(2)).await;
        for ev in &events {
            let args = ["reactions".into(), "get".into(), format!("--event={ev}")];
            let Ok(r) = buzz(access, &args).await else {
                continue;
            };
            if let Some((ok, pk)) = owner_verdict(&r, owners) {
                return if ok {
                    Outcome::Approved(pk)
                } else {
                    Outcome::Denied
                };
            }
        }
    }
    Outcome::Expired
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn owner_reactions_decide() {
        let owners = vec!["aa".to_owned()];
        assert_eq!(
            owner_verdict(&json!([{"emoji": "👍", "pubkeys": ["bb"]}]), &owners),
            None,
            "a stranger's 👍 is nothing"
        );
        assert_eq!(
            owner_verdict(&json!([{"emoji": "👍🏽", "pubkeys": ["aa"]}]), &owners),
            Some((true, "aa".into()))
        );
        assert_eq!(
            owner_verdict(
                &json!({"reactions": [{"emoji": "+", "pubkeys": ["aa"]}]}),
                &owners
            ),
            Some((true, "aa".into()))
        );
        assert_eq!(
            owner_verdict(
                &json!([{"emoji": "👍", "pubkeys": ["aa"]}, {"emoji": "❌", "pubkeys": ["aa"]}]),
                &owners
            ),
            Some((false, "aa".into())),
            "a refusal wins"
        );
        assert_eq!(
            owner_verdict(&json!([{"emoji": "🎉", "pubkeys": ["aa"]}]), &owners),
            None
        );
    }
}

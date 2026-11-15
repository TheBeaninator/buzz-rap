//! Sign-in approval in Buzz. A sign-in page cannot see the user's key, so on a self-hosted service anyone who can
//! reach it could sign in. With approval on, the page waits instead of redirecting: the service sends each owner a
//! direct message in Buzz from its own identity, naming a short code the page also shows, and the sign-in
//! completes when an owner reacts 👍 (or ✅, `+`) to that message. The reaction is signed by the owner's key on
//! the relay, so the session that results is bound to that key, exactly as a key-binding challenge would bind it.
//! 👎, ❌ or `-` refuses; no answer within the timeout expires the request.

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

#[derive(Clone, Debug, PartialEq)]
pub enum Status {
    Waiting,
    /// approved by this owner key
    Approved(String),
    Denied,
    Expired,
}

pub struct PendingLogin {
    pub challenge: String,
    pub state: String,
    pub return_to: String,
    /// the code shown on the page and in the message
    pub short_code: String,
    pub status: Status,
    pub until: Instant,
    /// the one-use login code, minted when approved
    pub login_code: Option<String>,
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
            "Sign-in request {short_code} for the Buzz agent service. If you are signing in on your phone now and the page shows {short_code}, react 👍 to this message to approve it, or ❌ to refuse. It expires in {minutes} minutes."
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

/// The page the app's browser shows while the request waits: it polls and follows the redirect when approved.
pub fn page(id: &str, short_code: &str) -> String {
    format!(
        r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve sign-in</title>
<style>body{{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;line-height:1.5}}
.code{{font-size:2.6rem;letter-spacing:.3rem;font-weight:700;margin:1rem 0}}#s{{color:#666}}</style></head>
<body><h1>Approve this sign-in in Buzz</h1>
<p>A direct message in Buzz asks you to approve sign-in request</p><div class="code">{short_code}</div>
<p>React 👍 to that message. This page continues on its own.</p><p id="s">Waiting for approval…</p>
<script>
async function poll(){{
  try {{
    const r = await fetch("/auth/native/status?id={id}", {{cache: "no-store"}});
    const d = await r.json();
    if (d.state === "approved" && d.redirect) {{ document.getElementById("s").textContent = "Approved."; location.replace(d.redirect); return; }}
    if (d.state === "denied") {{ document.getElementById("s").textContent = "Refused. Close this page."; return; }}
    if (d.state === "expired") {{ document.getElementById("s").textContent = "This request expired. Start again from the app."; return; }}
  }} catch (e) {{}}
  setTimeout(poll, 2000);
}}
poll();
</script></body></html>"##
    )
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

//! The audit trail. Every action is signed by this server's one identity, so the relay alone cannot say which
//! agent asked for it. This log closes that gap: one JSON line per call, refusal, duplicate delivery and
//! subscription delivery, keyed by the calling conversation (`group_id`) and call id (`id`, `call_id`), with
//! the Buzz event ids a call produced. Going from an event id to the agent call is then one grep; going from
//! the agent's transcript to the events works through the same ids.
//!
//! Lines go to `--audit-log` (append-only) when set, and always to the tracing target `buzz_rap::audit`.

use crate::server::App;
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;

/// How much of a result the log keeps; the full text went back to the agent, which stores it.
const RESULT_HEAD: usize = 512;

pub async fn record(app: &App, kind: &str, mut entry: Value) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    entry["ts_ms"] = json!(ts);
    entry["kind"] = json!(kind);
    let line = entry.to_string();
    tracing::info!(target: "buzz_rap::audit", "{line}");
    let Some(path) = &app.args.audit_log else {
        return;
    };
    let _one_writer = app.audit_lock.lock().await;
    let file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await;
    let wrote = match file {
        Ok(mut f) => f.write_all(format!("{line}\n").as_bytes()).await,
        Err(e) => Err(e),
    };
    if let Err(e) = wrote {
        tracing::error!(
            "audit log {}: {e}; the line above is the only copy",
            path.display()
        );
    }
}

/// The first part of a result, cut at a character boundary.
pub fn head(text: &str) -> String {
    if text.len() <= RESULT_HEAD {
        return text.to_owned();
    }
    let mut cut = RESULT_HEAD;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &text[..cut])
}

/// Where a callback goes, without its path: runtimes put their callback token there (FreeFitty:
/// `/rap/callback/<token>`), and the log must not hand out the means to post results into a conversation.
pub fn origin(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => format!(
            "{scheme}://{}",
            rest.split(['/', '?', '#']).next().unwrap_or("")
        ),
        None => "<not a URL>".to_owned(),
    }
}

/// Event ids a write reported (`event_id` anywhere in its JSON output).
pub fn event_ids(text: &str) -> Vec<String> {
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(m) => {
                for (k, x) in m {
                    match (k.as_str(), x) {
                        ("event_id", Value::String(s)) if !out.contains(s) => out.push(s.clone()),
                        _ => walk(x, out),
                    }
                }
            }
            Value::Array(xs) => xs.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        walk(&v, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_ids_are_found_at_any_depth_once() {
        let t = r#"{"accepted":true,"event_id":"a","inner":[{"event_id":"b"},{"event_id":"a"}]}"#;
        assert_eq!(event_ids(t), ["a", "b"]);
        assert!(event_ids("not json").is_empty());
    }

    #[test]
    fn callback_tokens_stay_out_of_the_log() {
        assert_eq!(
            origin("http://127.0.0.1:8191/rap/callback/s3cret"),
            "http://127.0.0.1:8191"
        );
        assert_eq!(origin("https://h.example?token=x"), "https://h.example");
        assert_eq!(origin("garbage"), "<not a URL>");
    }

    #[test]
    fn head_cuts_on_a_char_boundary() {
        let s = "é".repeat(400);
        let h = head(&s);
        assert!(h.len() <= RESULT_HEAD + "…".len() && h.ends_with('…'));
    }
}

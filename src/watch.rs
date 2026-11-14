//! Push delivery: one authenticated relay WebSocket per identity, carrying a NIP-01 `REQ` for each of that
//! identity's subscriptions. A new message arrives as soon as the relay stores it, with no process per poll.
//! The connection is re-made with backoff when it drops, and every subscription is asked again from its own
//! cursor, so nothing in between is lost (a repeat at the cursor's second is dropped by id).

use crate::identity::Identity;
use crate::server::App;
use crate::subscribe;
use buzz_ws_client::{NostrWsConnection, RelayMessage, WsClientError};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Kinds a channel's messages come as (the set `buzz messages get` reads).
pub const MESSAGE_KINDS: [u32; 5] = [9, 40002, 40008, 45001, 45003];
const BACKOFF_S: [u64; 6] = [1, 2, 5, 10, 30, 60];

pub enum Cmd {
    /// (group_id, subscription id): ask the relay for it
    Add(String, String),
    /// a subscription's REQ id: stop it
    Remove(String),
}

/// The relay's WebSocket URL for its HTTP base URL (the scheme changes; the path stays).
pub fn ws_url(relay: &str) -> String {
    let r = relay.trim();
    if let Some(rest) = r.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = r.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        r.to_owned()
    }
}

/// A subscription's REQ id: short and stable, so a reconnect asks again under the same id.
pub fn req_id(group: &str, id: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in group.bytes().chain(std::iter::once(b'/')).chain(id.bytes()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("rap-{h:016x}")
}

/// The watcher for this identity, started on first use; None when no relay URL is known (polling is used).
pub async fn ensure(app: &Arc<App>, ident: &Arc<Identity>) -> Option<mpsc::UnboundedSender<Cmd>> {
    let url = app.relay_ws.clone()?;
    let mut w = app.watchers.lock().await;
    if let Some(tx) = w.get(&ident.name) {
        return Some(tx.clone());
    }
    let (tx, rx) = mpsc::unbounded_channel();
    w.insert(ident.name.clone(), tx.clone());
    tokio::spawn(run(app.clone(), ident.clone(), url, rx));
    Some(tx)
}

async fn req(
    conn: &mut NostrWsConnection,
    rid: &str,
    channel: &str,
    since: u64,
) -> Result<(), WsClientError> {
    let filter = json!({"kinds": MESSAGE_KINDS, "#h": [channel], "since": since});
    conn.send_raw(&json!(["REQ", rid, filter])).await
}

async fn run(
    app: Arc<App>,
    ident: Arc<Identity>,
    url: String,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
) {
    let mut fails = 0usize;
    loop {
        let mut conn = match NostrWsConnection::connect_authenticated(&url, &ident.keys, None).await
        {
            Ok(c) => c,
            Err(e) => {
                let wait = BACKOFF_S[fails.min(BACKOFF_S.len() - 1)];
                tracing::warn!(identity = %ident.name, "relay {url}: {e}; again in {wait}s");
                fails += 1;
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
        };
        fails = 0;
        tracing::info!(identity = %ident.name, "relay {url}: connected for push delivery");
        // REQ id -> (group, subscription id)
        let mut open: HashMap<String, (String, String)> = HashMap::new();
        let mine: Vec<subscribe::Sub> = app
            .state
            .lock()
            .await
            .subs
            .iter()
            .filter(|s| s.identity.as_deref() == Some(ident.name.as_str()))
            .cloned()
            .collect();
        let mut broken = false;
        for s in &mine {
            let rid = req_id(&s.group_id, &s.id);
            if req(&mut conn, &rid, &s.channel, s.since).await.is_err() {
                broken = true;
                break;
            }
            open.insert(rid, (s.group_id.clone(), s.id.clone()));
        }
        while !broken {
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    Cmd::Add(group, id) => {
                        let found = app
                            .state
                            .lock()
                            .await
                            .subs
                            .iter()
                            .find(|s| s.group_id == group && s.id == id)
                            .cloned();
                        if let Some(s) = found {
                            let rid = req_id(&group, &id);
                            if req(&mut conn, &rid, &s.channel, s.since).await.is_err() {
                                broken = true;
                            }
                            open.insert(rid, (group, id));
                        }
                    }
                    Cmd::Remove(rid) => {
                        if open.remove(&rid).is_some()
                            && conn.send_raw(&json!(["CLOSE", rid])).await.is_err()
                        {
                            broken = true;
                        }
                    }
                }
            }
            if broken {
                break;
            }
            match conn.next_event(Duration::from_millis(500)).await {
                Ok(RelayMessage::Event {
                    subscription_id,
                    event,
                }) => {
                    if let Some((group, id)) = open.get(&subscription_id) {
                        let ev: Value = serde_json::to_value(&*event).unwrap_or(Value::Null);
                        subscribe::accept(&app, group, id, &[ev]).await;
                    }
                }
                Ok(RelayMessage::Closed {
                    subscription_id,
                    message,
                }) => {
                    // the relay refused or ended it (membership, a limit): say so to the conversation once
                    if let Some((group, id)) = open.remove(&subscription_id) {
                        tracing::warn!(identity = %ident.name, "relay closed {subscription_id}: {message}");
                        subscribe::relay_closed(&app, &group, &id, &message).await;
                    }
                }
                Ok(RelayMessage::Notice { message }) => {
                    tracing::info!(identity = %ident.name, "relay notice: {message}")
                }
                Ok(_) => {}
                Err(WsClientError::Timeout) => {}
                Err(e) => {
                    tracing::warn!(identity = %ident.name, "relay {url}: {e}; reconnecting");
                    broken = true;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_ids() {
        assert_eq!(
            ws_url("https://relay.example/team/"),
            "wss://relay.example/team/"
        );
        assert_eq!(ws_url("http://127.0.0.1:3000"), "ws://127.0.0.1:3000");
        assert_eq!(req_id("t", "c"), req_id("t", "c"));
        assert_ne!(req_id("t", "c"), req_id("t", "d"));
        assert!(req_id("a-very-long-thread-id-indeed", "and-a-long-call-id").len() <= 64);
    }
}

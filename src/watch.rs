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

/// Group metadata (NIP-29); DM groups carry `t` = `dm` and a `p` tag per participant.
pub const GROUP_METADATA_KIND: u32 = 39000;

#[derive(Clone, Copy, PartialEq, Debug)]
enum Role {
    /// messages to deliver
    Messages,
    /// DM group metadata: each one names a DM channel to listen in
    DmGroups,
}

/// The relay filters one subscription needs, as (REQ id, role, filter).
fn filters(s: &subscribe::Sub, me: &str) -> Vec<(String, Role, Value)> {
    let rid = req_id(&s.group_id, &s.id);
    match s.scope.as_str() {
        "mentions" => vec![(
            rid,
            Role::Messages,
            json!({"kinds": MESSAGE_KINDS, "#p": [me], "since": s.since}),
        )],
        "dms" => {
            let mut v = vec![(
                format!("{rid}-g"),
                Role::DmGroups,
                json!({"kinds": [GROUP_METADATA_KIND], "#t": ["dm"], "#p": [me]}),
            )];
            if !s.dm_channels.is_empty() {
                v.push((
                    rid,
                    Role::Messages,
                    json!({"kinds": MESSAGE_KINDS, "#h": s.dm_channels, "since": s.since}),
                ));
            }
            v
        }
        _ => vec![(
            rid,
            Role::Messages,
            json!({"kinds": MESSAGE_KINDS, "#h": [s.channel], "since": s.since}),
        )],
    }
}

type Open = HashMap<String, (String, String, Role)>;

/// Send a subscription's REQs (a repeated REQ id replaces the relay's earlier one).
async fn ask(
    conn: &mut NostrWsConnection,
    open: &mut Open,
    s: &subscribe::Sub,
    me: &str,
) -> Result<(), WsClientError> {
    for (rid, role, filter) in filters(s, me) {
        conn.send_raw(&json!(["REQ", rid, filter])).await?;
        open.insert(rid, (s.group_id.clone(), s.id.clone(), role));
    }
    Ok(())
}

async fn find(app: &App, group: &str, id: &str) -> Option<subscribe::Sub> {
    app.state
        .lock()
        .await
        .subs
        .iter()
        .find(|s| s.group_id == group && s.id == id)
        .cloned()
}

async fn run(
    app: Arc<App>,
    ident: Arc<Identity>,
    url: String,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
) {
    let mut fails = 0usize;
    let me = ident.pubkey.clone();
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
        let mut open: Open = HashMap::new();
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
            if ask(&mut conn, &mut open, s, &me).await.is_err() {
                broken = true;
                break;
            }
        }
        while !broken {
            while let Ok(cmd) = rx.try_recv() {
                match cmd {
                    Cmd::Add(group, id) => {
                        if let Some(s) = find(&app, &group, &id).await {
                            if ask(&mut conn, &mut open, &s, &me).await.is_err() {
                                broken = true;
                            }
                        }
                    }
                    Cmd::Remove(rid) => {
                        // a subscription may hold more than one REQ (rid, rid-g)
                        let gone: Vec<String> = open
                            .keys()
                            .filter(|k| **k == rid || k.strip_prefix(rid.as_str()) == Some("-g"))
                            .cloned()
                            .collect();
                        for k in gone {
                            open.remove(&k);
                            if conn.send_raw(&json!(["CLOSE", k])).await.is_err() {
                                broken = true;
                            }
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
                    let Some((group, id, role)) = open.get(&subscription_id).cloned() else {
                        continue;
                    };
                    let ev: Value = serde_json::to_value(&*event).unwrap_or(Value::Null);
                    match role {
                        Role::Messages => subscribe::accept(&app, &group, &id, &[ev]).await,
                        Role::DmGroups => {
                            if let Some(s) = subscribe::add_dm_channel(&app, &group, &id, &ev).await
                            {
                                // listen in the new DM channel too, from the subscription's cursor
                                if ask(&mut conn, &mut open, &s, &me).await.is_err() {
                                    broken = true;
                                }
                            }
                        }
                    }
                }
                Ok(RelayMessage::Closed {
                    subscription_id,
                    message,
                }) => {
                    // the relay refused or ended it (membership, a limit): say so to the conversation once
                    if let Some((group, id, _)) = open.remove(&subscription_id) {
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

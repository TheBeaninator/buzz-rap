//! `buzz_subscribe`: new messages in a channel (or one thread of it) become RAP `subscription_event`s for
//! the call that asked, until it is unsubscribed or expires. This is what lets an agent wait in a channel and
//! wake when someone talks to it. Subscriptions survive a restart when `--state` is set.
//!
//! Delivery is pushed over the relay WebSocket (`watch`) when the relay URL is known, and polled with
//! `buzz messages get --since` otherwise. Both paths go through `accept`, which keeps each subscription's
//! cursor, drops repeats and the agent's own messages, and posts the rest.

use crate::audit;
use crate::identity::Identity;
use crate::server::{cap, post_callback, run_buzz, App, Invocation};
use crate::watch;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SUBSCRIBE: &str = "buzz_subscribe";
pub const UNSUBSCRIBE: &str = "buzz_unsubscribe";
const DEFAULT_HOURS: f64 = 24.0;
const MAX_HOURS: f64 = 24.0 * 30.0;
/// Largest message text in one event.
const MAX_EVENT_TEXT: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sub {
    /// the subscribing call's id; every event names it
    pub id: String,
    pub group_id: String,
    pub callback_url: String,
    pub channel: String,
    pub thread: Option<String>,
    pub mentions_only: bool,
    /// newest created_at already delivered (seconds)
    pub since: u64,
    /// ids delivered at `since`, so the inclusive cursor never repeats one
    pub seen: Vec<String>,
    pub expires: u64,
    /// the identity it reads as (an identities-file name, or "default")
    #[serde(default)]
    pub identity: Option<String>,
    /// `channel` (one channel), `mentions` (messages that mention the identity, in any channel it can read) or
    /// `dms` (its direct messages)
    #[serde(default = "scope_channel")]
    pub scope: String,
    /// author gate: `owner-only`, `allowlist`, `anyone` or `nobody` (the values Buzz's agent policy uses)
    #[serde(default = "gate_anyone")]
    pub respond_to: String,
    /// extra authors for `allowlist` (hex pubkeys); the owner is always allowed
    #[serde(default)]
    pub allow: Vec<String>,
    /// the identity's owner, from its NIP-OA owner tag
    #[serde(default)]
    pub owner: Option<String>,
    /// DM channels found so far (`dms` scope)
    #[serde(default)]
    pub dm_channels: Vec<String>,
}

fn scope_channel() -> String {
    "channel".into()
}

fn gate_anyone() -> String {
    "anyone".into()
}

const SCOPES: [&str; 3] = ["channel", "mentions", "dms"];
const GATES: [&str; 4] = ["owner-only", "allowlist", "anyone", "nobody"];

fn is_hex_pubkey(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn defs() -> Vec<Value> {
    vec![
        json!({"name": SUBSCRIBE,
            "description": "Watch for messages: in one channel (scope channel), anywhere you are mentioned (scope mentions), or in your direct messages (scope dms). Each new message arrives as an event for this call, so you can wait with no timer and wake when someone writes. Your own messages are not sent back, and messages from authors the gate does not allow are dropped. Ends when you call buzz_unsubscribe or after `hours`.",
            "inputSchema": {"type": "object", "properties": {
                "scope": {"type": "string", "enum": SCOPES, "description": "channel (default), mentions or dms"},
                "channel": {"type": "string", "description": "Channel UUID (from buzz_channels_list); required for scope channel"},
                "respond_to": {"type": "string", "enum": GATES, "description": "Whose messages to pass on: owner-only (your owner; the default when you have one), allowlist (your owner and `allow`), anyone, or nobody"},
                "allow": {"type": "array", "items": {"type": "string"}, "description": "Hex pubkeys allowed besides your owner, for respond_to allowlist"},
                "thread": {"type": "string", "description": "Only messages in the thread with this root event id"},
                "mentions_only": {"type": "boolean", "description": "Only messages that mention you"},
                "hours": {"type": "number", "description": "How long to watch; 24 by default, at most 720"}},
                "required": []}}),
        json!({"name": UNSUBSCRIBE,
            "description": "Stop a subscription made with buzz_subscribe.",
            "inputSchema": {"type": "object", "properties": {
                "subscription": {"type": "string", "description": "The subscription id buzz_subscribe returned"}},
                "required": ["subscription"]}}),
    ]
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub async fn start(
    app: &Arc<App>,
    inv: &Invocation,
    ident: Option<&Arc<Identity>>,
) -> (bool, String) {
    let a = &inv.arguments;
    let scope = a.get("scope").and_then(Value::as_str).unwrap_or("channel");
    if !SCOPES.contains(&scope) {
        return (false, format!("scope must be one of {SCOPES:?}"));
    }
    let channel = a
        .get("channel")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty());
    if scope == "channel" && channel.is_none() {
        return (false, "channel is required for scope channel".into());
    }
    let Some(ident) = ident else {
        // without its own pubkey the server cannot drop the agent's own posts, and each reply would come back as
        // an event that wakes the agent to reply again
        return (
            false,
            "subscriptions need a known identity (BUZZ_PRIVATE_KEY or an --identities entry for this conversation): without one the agent's own replies would come back as events and wake it in a loop".into(),
        );
    };
    if scope != "channel" && app.relay_ws.is_none() {
        return (false, format!("scope {scope} needs push delivery (BUZZ_RELAY_URL set): polling reads one channel at a time"));
    }
    let default_gate = if ident.owner.is_some() {
        "owner-only"
    } else {
        "anyone"
    };
    let respond_to = a
        .get("respond_to")
        .and_then(Value::as_str)
        .unwrap_or(default_gate);
    if !GATES.contains(&respond_to) {
        return (false, format!("respond_to must be one of {GATES:?}"));
    }
    let allow: Vec<String> = a
        .get("allow")
        .and_then(Value::as_array)
        .map(|xs| {
            xs.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    if let Some(bad) = allow.iter().find(|p| !is_hex_pubkey(p)) {
        return (
            false,
            format!("allow takes 64-character hex pubkeys, not {bad:?}"),
        );
    }
    if respond_to == "owner-only" && ident.owner.is_none() {
        return (false, "respond_to owner-only needs an identity with an owner tag (auth_tag_file or BUZZ_AUTH_TAG)".into());
    }
    let hours = a
        .get("hours")
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_HOURS)
        .clamp(0.01, MAX_HOURS);
    let sub = Sub {
        id: inv.id.clone(),
        group_id: inv.group_id.clone(),
        callback_url: inv.callback_url.clone(),
        channel: channel.unwrap_or("").to_owned(),
        thread: a
            .get("thread")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_owned),
        mentions_only: a
            .get("mentions_only")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        since: now(),
        seen: Vec::new(),
        expires: now() + (hours * 3600.0) as u64,
        identity: Some(ident.name.clone()),
        scope: scope.to_owned(),
        respond_to: respond_to.to_owned(),
        allow,
        owner: ident.owner.clone(),
        dm_channels: Vec::new(),
    };
    if let Some(channel) = channel.filter(|_| scope == "channel") {
        // the channel must be readable by this identity now, or every delivery would fail quietly
        let probe = vec![
            "messages".into(),
            "get".into(),
            format!("--channel={channel}"),
            "--limit=1".into(),
        ];
        let (ok, text) = run_buzz(app, Some(ident), probe).await;
        if !ok {
            return (false, format!("cannot read channel {channel}: {text}"));
        }
    }
    let how = if app.relay_ws.is_some() {
        "pushed from the relay"
    } else {
        "polled"
    };
    let what = match scope {
        "mentions" => "messages that mention you, in any channel you can read".to_owned(),
        "dms" => "your direct messages".to_owned(),
        _ => format!(
            "channel {}{}{}",
            sub.channel,
            sub.thread
                .as_deref()
                .map(|t| format!(", thread {t}"))
                .unwrap_or_default(),
            if sub.mentions_only {
                ", mentions only"
            } else {
                ""
            }
        ),
    };
    let msg = format!(
        "Subscribed (subscription {}) to {what} for {hours} h, passing on messages from {}; new messages are {how} and arrive as events for this call. Reply with buzz_messages_send (channel = the event's channel, reply_to = its event id to answer in its thread). Stop with buzz_unsubscribe.",
        sub.id,
        match sub.respond_to.as_str() {
            "owner-only" => "your owner only".to_owned(),
            "allowlist" => format!("your owner and {} other author(s)", sub.allow.len()),
            "nobody" => "nobody".to_owned(),
            _ => "anyone".to_owned(),
        },
    );
    let (group, id) = (sub.group_id.clone(), sub.id.clone());
    app.state.lock().await.subs.push(sub);
    if let Some(tx) = watch::ensure(app, ident).await {
        let _ = tx.send(watch::Cmd::Add(group, id));
    }
    (true, msg)
}

pub async fn stop(app: &Arc<App>, inv: &Invocation) -> (bool, String) {
    let Some(id) = inv.arguments.get("subscription").and_then(Value::as_str) else {
        return (false, "subscription is required".into());
    };
    match remove(app, &inv.group_id, id).await {
        Some(sub) => {
            send_event(
                app,
                &sub,
                format!("Subscription {} ended: unsubscribed.", sub.id),
                true,
                None,
            )
            .await;
            (true, format!("Unsubscribed {id}."))
        }
        None => (false, format!("no subscription {id} in this conversation")),
    }
}

/// Take a subscription out of the state and out of its watcher.
async fn remove(app: &Arc<App>, group: &str, id: &str) -> Option<Sub> {
    let removed = {
        let mut s = app.state.lock().await;
        let at = s
            .subs
            .iter()
            .position(|x| x.id == id && x.group_id == group);
        at.map(|i| s.subs.remove(i))
    };
    if let Some(sub) = &removed {
        if let Some(name) = &sub.identity {
            if let Some(tx) = app.watchers.lock().await.get(name) {
                let _ = tx.send(watch::Cmd::Remove(watch::req_id(group, id)));
            }
        }
        app.save().await;
    }
    removed
}

/// Ends every subscription whose identity is no longer in the identities file (an agent was deleted), with a
/// final event, so its mentions and DMs stop at once instead of when the subscription would have expired.
pub async fn drop_orphans(app: &Arc<App>) {
    let ids = app.ids().await;
    let orphans: Vec<(String, String)> = app
        .state
        .lock()
        .await
        .subs
        .iter()
        .filter(|s| {
            s.identity
                .as_deref()
                .is_some_and(|n| ids.by_name(n).is_none())
        })
        .map(|s| (s.group_id.clone(), s.id.clone()))
        .collect();
    for (group, id) in orphans {
        if let Some(sub) = remove(app, &group, &id).await {
            send_event(
                app,
                &sub,
                format!("Subscription {} ended: its identity was removed.", sub.id),
                true,
                None,
            )
            .await;
        }
    }
}

/// The relay ended a pushed subscription (lost membership, a limit): the conversation hears why, once.
pub async fn relay_closed(app: &Arc<App>, group: &str, id: &str, why: &str) {
    if let Some(sub) = remove(app, group, id).await {
        send_event(
            app,
            &sub,
            format!(
                "Subscription {} ended: the relay closed it ({why}).",
                sub.id
            ),
            true,
            None,
        )
        .await;
    }
}

/// A DM group event for a `dms` subscription: if it names a DM channel the subscription does not have yet,
/// remember it and return the updated subscription so its message filter can be widened.
pub async fn add_dm_channel(app: &Arc<App>, group: &str, id: &str, ev: &Value) -> Option<Sub> {
    let tags = ev.get("tags").and_then(Value::as_array)?;
    let is_dm = tags.iter().any(|t| {
        t.get(0).and_then(Value::as_str) == Some("t")
            && t.get(1).and_then(Value::as_str) == Some("dm")
    });
    let channel = tags
        .iter()
        .find(|t| t.get(0).and_then(Value::as_str) == Some("d"))
        .and_then(|t| t.get(1))
        .and_then(Value::as_str)?
        .to_owned();
    if !is_dm || channel.is_empty() {
        return None;
    }
    let updated = {
        let mut s = app.state.lock().await;
        let sub = s
            .subs
            .iter_mut()
            .find(|x| x.group_id == group && x.id == id)?;
        if sub.dm_channels.contains(&channel) {
            return None;
        }
        sub.dm_channels.push(channel);
        sub.clone()
    };
    app.save().await;
    Some(updated)
}

/// Post one event; `from` is the Buzz message it carries (event id, author), recorded in the audit log.
async fn send_event(
    app: &Arc<App>,
    sub: &Sub,
    text: String,
    last: bool,
    from: Option<(&str, &str)>,
) -> bool {
    let body = json!({"type": "subscription_event", "group_id": sub.group_id, "tool_call_id": sub.id, "text": text, "final": last});
    let delivered = post_callback(app.clone(), sub.callback_url.clone(), body).await;
    let mut e = json!({"group_id": sub.group_id, "subscription": sub.id, "channel": sub.channel, "final": last,
        "delivered": delivered, "identity_name": sub.identity});
    let ids = app.ids().await;
    if let Some(i) = sub.identity.as_deref().and_then(|n| ids.by_name(n)) {
        e["identity"] = json!(i.pubkey);
    }
    if let Some((id, author)) = from {
        e["event_id"] = json!(id);
        e["author"] = json!(author);
    } else {
        e["text"] = json!(audit::head(&text));
    }
    audit::record(
        app,
        if last {
            "subscription_end"
        } else {
            "subscription_event"
        },
        e,
    )
    .await;
    delivered
}

/// Messages seen for one subscription, from either delivery path: move its cursor, drop repeats and what it
/// does not want, post the rest in order.
pub async fn accept(app: &Arc<App>, group: &str, id: &str, events: &[Value]) {
    let mut fresh = Vec::new();
    let sub = {
        let mut s = app.state.lock().await;
        let Some(sub) = s
            .subs
            .iter_mut()
            .find(|x| x.group_id == group && x.id == id)
        else {
            return;
        };
        let mut sorted: Vec<&Value> = events.iter().collect();
        sorted.sort_by_key(|e| e.get("created_at").and_then(Value::as_u64).unwrap_or(0));
        for e in sorted {
            let eid = e.get("id").and_then(Value::as_str).unwrap_or("").to_owned();
            let at = e.get("created_at").and_then(Value::as_u64).unwrap_or(0);
            if eid.is_empty() || at < sub.since || (at == sub.since && sub.seen.contains(&eid)) {
                continue;
            }
            if at > sub.since {
                sub.since = at;
                sub.seen.clear();
            }
            sub.seen.push(eid);
            fresh.push(e.clone());
        }
        sub.clone()
    };
    if fresh.is_empty() {
        return;
    }
    let ids = app.ids().await;
    let me = sub
        .identity
        .as_deref()
        .and_then(|n| ids.by_name(n))
        .map(|i| i.pubkey.clone());
    for e in &fresh {
        if let Some(text) = describe(e, &sub, me.as_deref()) {
            let eid = e.get("id").and_then(Value::as_str).unwrap_or("");
            let author = e.get("pubkey").and_then(Value::as_str).unwrap_or("");
            send_event(app, &sub, text, false, Some((eid, author))).await;
        }
    }
    app.save().await;
}

/// The housekeeping loop: ends expired subscriptions, and polls those no watcher carries.
pub async fn run(app: Arc<App>) {
    let every = Duration::from_millis(app.args.poll_ms.max(250));
    // subscriptions kept from before a restart go back to their watchers
    let kept = app.state.lock().await.subs.clone();
    let ids = app.ids().await;
    for s in &kept {
        if let Some(i) = s.identity.as_deref().and_then(|n| ids.by_name(n)) {
            if let Some(tx) = watch::ensure(&app, &i).await {
                let _ = tx.send(watch::Cmd::Add(s.group_id.clone(), s.id.clone()));
            }
        }
    }
    loop {
        tokio::time::sleep(every).await;
        let subs = app.state.lock().await.subs.clone();
        for sub in subs {
            if now() >= sub.expires {
                if let Some(s) = remove(&app, &sub.group_id, &sub.id).await {
                    send_event(
                        &app,
                        &s,
                        format!("Subscription {} ended: its time ran out.", s.id),
                        true,
                        None,
                    )
                    .await;
                }
                continue;
            }
            if app.relay_ws.is_none() {
                poll(&app, &sub).await;
            }
        }
    }
}

/// One look at a subscription's channel through `buzz messages get --since`.
async fn poll(app: &Arc<App>, sub: &Sub) {
    let ids = app.ids().await;
    let ident = sub.identity.as_deref().and_then(|n| ids.by_name(n));
    let argv = vec![
        "messages".into(),
        "get".into(),
        format!("--channel={}", sub.channel),
        format!("--since={}", sub.since),
        "--limit=100".into(),
    ];
    let (ok, text) = run_buzz(app, ident.as_ref(), argv).await;
    if !ok {
        tracing::warn!(sub = %sub.id, "poll of {}: {text}", sub.channel);
        return;
    }
    if let Ok(events) = serde_json::from_str::<Vec<Value>>(&text) {
        accept(app, &sub.group_id, &sub.id, &events).await;
    }
}

/// The event text for one message, or None when this subscription does not want it.
pub fn describe(e: &Value, sub: &Sub, me: Option<&str>) -> Option<String> {
    let id = e.get("id").and_then(Value::as_str)?;
    let author = e.get("pubkey").and_then(Value::as_str).unwrap_or("");
    if me == Some(author) || !author_allowed(sub, author) {
        return None;
    }
    let tags: Vec<&Vec<Value>> = e
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .collect();
    let tag = |t: &Vec<Value>, i: usize| t.get(i).and_then(Value::as_str).unwrap_or("").to_owned();
    let root = tags
        .iter()
        .find(|t| tag(t, 0) == "e" && tag(t, 3) == "root")
        .map(|t| tag(t, 1));
    if let Some(want) = &sub.thread {
        if root.as_deref() != Some(want) && id != want {
            return None;
        }
    }
    if sub.mentions_only {
        let me = me?;
        if !tags.iter().any(|t| tag(t, 0) == "p" && tag(t, 1) == me) {
            return None;
        }
    }
    let content = e.get("content").and_then(Value::as_str).unwrap_or("");
    let content = if content.len() > MAX_EVENT_TEXT {
        cap(content.to_owned())
    } else {
        content.to_owned()
    };
    let place = match &root {
        Some(r) => format!("in thread {r}"),
        None => "top level".to_owned(),
    };
    let channel = tags
        .iter()
        .find(|t| tag(t, 0) == "h")
        .map(|t| tag(t, 1))
        .unwrap_or_else(|| sub.channel.clone());
    let kind = if sub.dm_channels.contains(&channel) {
        "a direct message"
    } else {
        "channel"
    };
    Some(format!(
        "[buzz] {author} wrote in {kind} {channel} ({place}; event {id}):\n{content}"
    ))
}

/// The author gate (Buzz's agent policy values).
fn author_allowed(sub: &Sub, author: &str) -> bool {
    let owner = sub.owner.as_deref() == Some(author);
    match sub.respond_to.as_str() {
        "owner-only" => owner,
        "allowlist" => owner || sub.allow.iter().any(|a| a == author),
        "nobody" => false,
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sub(thread: Option<&str>, mentions_only: bool) -> Sub {
        Sub {
            id: "c1".into(),
            group_id: "t1".into(),
            callback_url: "http://x".into(),
            channel: "ch".into(),
            thread: thread.map(str::to_owned),
            mentions_only,
            since: 0,
            seen: vec![],
            expires: u64::MAX,
            identity: None,
            scope: "channel".into(),
            respond_to: "anyone".into(),
            allow: vec![],
            owner: None,
            dm_channels: vec![],
        }
    }

    #[test]
    fn own_messages_and_other_threads_are_skipped() {
        let top = json!({"id": "e1", "pubkey": "them", "content": "hi", "tags": []});
        let reply = json!({"id": "e2", "pubkey": "them", "content": "re", "tags": [["e", "e1", "", "root"]]});
        let mine = json!({"id": "e3", "pubkey": "me", "content": "x", "tags": []});
        assert!(describe(&top, &sub(None, false), Some("me"))
            .unwrap()
            .contains("top level"));
        assert!(describe(&mine, &sub(None, false), Some("me")).is_none());
        assert!(describe(&top, &sub(Some("zz"), false), Some("me")).is_none());
        assert!(describe(&reply, &sub(Some("e1"), false), Some("me"))
            .unwrap()
            .contains("in thread e1"));
        assert!(
            describe(&top, &sub(Some("e1"), false), Some("me")).is_some(),
            "the root itself belongs to its thread"
        );
    }

    #[test]
    fn mentions_only_needs_a_p_tag_for_me() {
        let plain = json!({"id": "e1", "pubkey": "them", "content": "hi", "tags": []});
        let ping = json!({"id": "e2", "pubkey": "them", "content": "@you", "tags": [["p", "me"]]});
        assert!(describe(&plain, &sub(None, true), Some("me")).is_none());
        assert!(describe(&ping, &sub(None, true), Some("me")).is_some());
    }
}

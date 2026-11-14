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
}

pub fn defs() -> Vec<Value> {
    vec![
        json!({"name": SUBSCRIBE,
            "description": "Watch a channel: every new message there (or in one thread of it) arrives as an event for this call, so you can wait with no timer and wake when someone writes. Your own messages are not sent back. Ends when you call buzz_unsubscribe or after `hours`.",
            "inputSchema": {"type": "object", "properties": {
                "channel": {"type": "string", "description": "Channel UUID (from buzz_channels_list)"},
                "thread": {"type": "string", "description": "Only messages in the thread with this root event id"},
                "mentions_only": {"type": "boolean", "description": "Only messages that mention you"},
                "hours": {"type": "number", "description": "How long to watch; 24 by default, at most 720"}},
                "required": ["channel"]}}),
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
    let Some(channel) = a
        .get("channel")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
    else {
        return (false, "channel is required".into());
    };
    let Some(ident) = ident else {
        // without its own pubkey the server cannot drop the agent's own posts, and each reply would come back as
        // an event that wakes the agent to reply again
        return (
            false,
            "subscriptions need a known identity (BUZZ_PRIVATE_KEY or an --identities entry for this conversation): without one the agent's own replies would come back as events and wake it in a loop".into(),
        );
    };
    let hours = a
        .get("hours")
        .and_then(Value::as_f64)
        .unwrap_or(DEFAULT_HOURS)
        .clamp(0.01, MAX_HOURS);
    let sub = Sub {
        id: inv.id.clone(),
        group_id: inv.group_id.clone(),
        callback_url: inv.callback_url.clone(),
        channel: channel.to_owned(),
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
    };
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
    let how = if app.relay_ws.is_some() {
        "pushed from the relay"
    } else {
        "polled"
    };
    let msg = format!(
        "Subscribed (subscription {}) to channel {channel}{}{} for {hours} h; new messages are {how} and arrive as events for this call. Reply with buzz_messages_send (reply_to = the event id to answer in its thread). Stop with buzz_unsubscribe.",
        sub.id,
        sub.thread.as_deref().map(|t| format!(", thread {t}")).unwrap_or_default(),
        if sub.mentions_only { ", mentions only" } else { "" },
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
    if let Some(i) = sub
        .identity
        .as_deref()
        .and_then(|n| app.identities.by_name(n))
    {
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
    let me = sub
        .identity
        .as_deref()
        .and_then(|n| app.identities.by_name(n))
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
    for s in &kept {
        if let Some(i) = s
            .identity
            .as_deref()
            .and_then(|n| app.identities.by_name(n))
        {
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
    let ident = sub
        .identity
        .as_deref()
        .and_then(|n| app.identities.by_name(n));
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
    if me == Some(author) {
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
    Some(format!(
        "[buzz] {author} wrote in channel {} ({place}; event {id}):\n{content}",
        sub.channel
    ))
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

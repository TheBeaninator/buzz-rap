//! `buzz_subscribe`: new messages in a channel (or one thread of it) become RAP `subscription_event`s for
//! the call that asked, until it is unsubscribed or expires. This is what lets an agent sleep in a channel
//! and wake when someone talks to it. Subscriptions survive a restart when `--state` is set.

use crate::audit;
use crate::server::{cap, post_callback, run_buzz, App, Invocation};
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
    /// ids delivered at `since`, so the inclusive `--since` never repeats one
    pub seen: Vec<String>,
    pub expires: u64,
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

pub async fn start(app: &Arc<App>, inv: &Invocation) -> (bool, String) {
    let a = &inv.arguments;
    let Some(channel) = a
        .get("channel")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
    else {
        return (false, "channel is required".into());
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
    };
    if app.me.is_none() {
        // without its own pubkey the server cannot drop the agent's own posts, and each reply would come back as
        // an event that wakes the agent to reply again
        return (
            false,
            "subscriptions need BUZZ_PRIVATE_KEY on the server: without it the agent's own replies would come back as events and wake it in a loop".into(),
        );
    }
    // the channel must be readable now, or every poll would fail quietly
    let (ok, text) = run_buzz(
        app,
        vec![
            "messages".into(),
            "get".into(),
            format!("--channel={channel}"),
            "--limit=1".into(),
        ],
    )
    .await;
    if !ok {
        return (false, format!("cannot read channel {channel}: {text}"));
    }
    let msg = format!(
        "Subscribed (subscription {}) to channel {channel}{}{} for {hours} h. New messages arrive as events for this call; reply with buzz_messages_send (reply_to = the event id to answer in its thread). Stop with buzz_unsubscribe.",
        sub.id,
        sub.thread.as_deref().map(|t| format!(", thread {t}")).unwrap_or_default(),
        if sub.mentions_only { ", mentions only" } else { "" },
    );
    app.state.lock().await.subs.push(sub);
    (true, msg)
}

pub async fn stop(app: &Arc<App>, inv: &Invocation) -> (bool, String) {
    let Some(id) = inv.arguments.get("subscription").and_then(Value::as_str) else {
        return (false, "subscription is required".into());
    };
    let removed = {
        let mut s = app.state.lock().await;
        let at = s
            .subs
            .iter()
            .position(|x| x.id == id && x.group_id == inv.group_id);
        at.map(|i| s.subs.remove(i))
    };
    match removed {
        Some(sub) => {
            send_event(
                app,
                &sub,
                format!("Subscription {} ended: unsubscribed.", sub.id),
                true,
            )
            .await;
            (true, format!("Unsubscribed {id}."))
        }
        None => (false, format!("no subscription {id} in this conversation")),
    }
}

async fn send_event(app: &Arc<App>, sub: &Sub, text: String, last: bool) -> bool {
    send_event_for(app, sub, text, last, None).await
}

/// Post one event; `from` is the Buzz message it carries (event id, author), recorded in the audit log.
async fn send_event_for(
    app: &Arc<App>,
    sub: &Sub,
    text: String,
    last: bool,
    from: Option<(&str, &str)>,
) -> bool {
    let body = json!({"type": "subscription_event", "group_id": sub.group_id, "tool_call_id": sub.id, "text": text, "final": last});
    let delivered = post_callback(app.clone(), sub.callback_url.clone(), body).await;
    let mut e = json!({"group_id": sub.group_id, "subscription": sub.id, "channel": sub.channel, "final": last, "delivered": delivered});
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

/// The poll loop: one pass over every subscription each `--poll-ms`.
pub async fn run(app: Arc<App>) {
    let every = Duration::from_millis(app.args.poll_ms.max(250));
    loop {
        tokio::time::sleep(every).await;
        let subs = app.state.lock().await.subs.clone();
        let mut changed = false;
        for sub in subs {
            if now() >= sub.expires {
                app.state
                    .lock()
                    .await
                    .subs
                    .retain(|x| !(x.id == sub.id && x.group_id == sub.group_id));
                send_event(
                    &app,
                    &sub,
                    format!("Subscription {} ended: its time ran out.", sub.id),
                    true,
                )
                .await;
                changed = true;
                continue;
            }
            if let Some(next) = poll(&app, sub.clone()).await {
                let mut s = app.state.lock().await;
                if let Some(x) = s
                    .subs
                    .iter_mut()
                    .find(|x| x.id == next.id && x.group_id == next.group_id)
                {
                    x.since = next.since;
                    x.seen = next.seen;
                    changed = true;
                }
            }
        }
        if changed {
            app.save().await;
        }
    }
}

/// One look at a subscription's channel; returns its moved cursor when anything new was seen.
async fn poll(app: &Arc<App>, mut sub: Sub) -> Option<Sub> {
    let argv = vec![
        "messages".into(),
        "get".into(),
        format!("--channel={}", sub.channel),
        format!("--since={}", sub.since),
        "--limit=100".into(),
    ];
    let (ok, text) = run_buzz(app, argv).await;
    if !ok {
        tracing::warn!(sub = %sub.id, "poll of {}: {text}", sub.channel);
        return None;
    }
    let events: Vec<Value> = serde_json::from_str(&text).ok()?;
    let mut moved = false;
    for e in &events {
        let id = e.get("id").and_then(Value::as_str).unwrap_or("").to_owned();
        let at = e.get("created_at").and_then(Value::as_u64).unwrap_or(0);
        if id.is_empty() || at < sub.since || (at == sub.since && sub.seen.contains(&id)) {
            continue;
        }
        if at > sub.since {
            sub.since = at;
            sub.seen.clear();
        }
        sub.seen.push(id.clone());
        moved = true;
        if let Some(text) = describe(e, &sub, app.me.as_deref()) {
            let author = e.get("pubkey").and_then(Value::as_str).unwrap_or("");
            send_event_for(app, &sub, text, false, Some((&id, author))).await;
        }
    }
    moved.then_some(sub)
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

//! Subscriptions to an agent's mentions and DMs across channels, the author gate, and identities that change
//! while the server runs: the real binary against a stand-in relay that matches NIP-01 filters.

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::{SinkExt, StreamExt};
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag, Timestamp};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const FAKE_BUZZ: &str = r#"#!/bin/sh
echo "$BUZZ_PRIVATE_KEY $*" >> "$FAKE_LOG"
case "$*" in
  "messages send"*) echo '{"accepted":true,"event_id":"ev-sent"}' ;;
  "messages get"*) echo '[]' ;;
  *) echo "unknown: $*" >&2; exit 2 ;;
esac
"#;

type Shared = Arc<Mutex<Vec<Value>>>;

fn tag_values<'a>(e: &'a Value, name: &str) -> Vec<&'a str> {
    e["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|t| t[0] == name)
        .filter_map(|t| t[1].as_str())
        .collect()
}

/// NIP-01 matching for the fields buzz-rap uses: kinds, #h, #p, #t, since.
fn matches(e: &Value, f: &Value) -> bool {
    if let Some(kinds) = f["kinds"].as_array() {
        if !kinds.contains(&e["kind"]) {
            return false;
        }
    }
    for name in ["h", "p", "t"] {
        if let Some(want) = f[format!("#{name}")].as_array() {
            let have = tag_values(e, name);
            if !want
                .iter()
                .any(|w| w.as_str().is_some_and(|w| have.contains(&w)))
            {
                return false;
            }
        }
    }
    if let Some(since) = f["since"].as_u64() {
        if e["created_at"].as_u64().unwrap_or(0) < since {
            return false;
        }
    }
    true
}

async fn ws(State(events): State<Shared>, up: WebSocketUpgrade) -> Response {
    up.on_upgrade(move |socket| serve_socket(socket, events))
}

async fn serve_socket(socket: WebSocket, events: Shared) {
    let (mut tx, mut rx) = socket.split();
    let _ = tx
        .send(Message::Text(json!(["AUTH", "c"]).to_string().into()))
        .await;
    while let Some(Ok(Message::Text(text))) = rx.next().await {
        let msg: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        match msg[0].as_str() {
            Some("AUTH") => {
                let ok = json!(["OK", msg[1]["id"], true, ""]).to_string();
                let _ = tx.send(Message::Text(ok.into())).await;
            }
            Some("REQ") => {
                let sid = msg[1].as_str().unwrap_or("").to_owned();
                let hits: Vec<Value> = events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|e| matches(e, &msg[2]))
                    .cloned()
                    .collect();
                for e in hits {
                    let frame = json!(["EVENT", sid, e]).to_string();
                    let _ = tx.send(Message::Text(frame.into())).await;
                }
                let eose = json!(["EOSE", sid]).to_string();
                let _ = tx.send(Message::Text(eose.into())).await;
            }
            _ => {}
        }
    }
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

async fn until(what: &str, mut ok: impl FnMut() -> bool) {
    for _ in 0..100 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

fn event(keys: &Keys, kind: u16, content: &str, tags: &[&[&str]], at: u64) -> Value {
    let mut b =
        EventBuilder::new(Kind::Custom(kind), content).custom_created_at(Timestamp::from(at));
    for t in tags {
        b = b.tag(Tag::parse(t.iter().copied()).unwrap());
    }
    serde_json::from_str(&b.sign_with_keys(keys).unwrap().as_json()).unwrap()
}

fn hex(n: u8) -> String {
    format!("{n:064x}")
}

#[tokio::test(flavor = "multi_thread")]
async fn mentions_dms_gate_and_identity_reload() {
    let dir = std::env::temp_dir().join(format!("buzz-rap-scopes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("buzz");
    std::fs::File::create(&bin)
        .unwrap()
        .write_all(FAKE_BUZZ.as_bytes())
        .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let log = dir.join("calls.log");

    // 2 = the agent, 4 = its owner, 3 = a stranger, 5 = the relay's signing key, 6 = an agent added later
    let key = |n: u8| Keys::parse(&hex(n)).unwrap();
    let (agent, owner, stranger, relay_key) = (key(2), key(4), key(3), key(5));
    let (a, o) = (agent.public_key().to_hex(), owner.public_key().to_hex());

    let write_key = |name: &str, n: u8| {
        let p = dir.join(name);
        std::fs::write(&p, format!("{}\n", hex(n))).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        p
    };
    let agent_key = write_key("agent.key", 2);
    let tag_file = dir.join("agent.auth");
    std::fs::write(
        &tag_file,
        json!(["auth", o, "", "00".repeat(64)]).to_string(),
    )
    .unwrap();
    let ids = dir.join("identities.toml");
    let first = format!(
        "[[identity]]\nname = \"scout\"\nkey_file = \"{}\"\nauth_tag_file = \"{}\"\ngroups = [\"scout\", \"scout.*\"]\n",
        agent_key.display(),
        tag_file.display()
    );
    std::fs::write(&ids, &first).unwrap();

    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    let events: Shared = Arc::new(Mutex::new(vec![
        event(
            &owner,
            9,
            "mention from the owner",
            &[&["h", "ch-2"], &["p", &a]],
            soon,
        ),
        event(
            &stranger,
            9,
            "mention from a stranger",
            &[&["h", "ch-2"], &["p", &a]],
            soon,
        ),
        event(
            &relay_key,
            39000,
            "",
            &[&["d", "dm-1"], &["t", "dm"], &["p", &a], &["p", &o]],
            soon,
        ),
        event(
            &owner,
            9,
            "a direct message from the owner",
            &[&["h", "dm-1"]],
            soon,
        ),
        event(&owner, 9, "unrelated", &[&["h", "ch-3"]], soon),
    ]));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", l.local_addr().unwrap());
    let app = Router::new().route("/", get(ws)).with_state(events.clone());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

    let got = Arc::new(Mutex::new(Vec::<Value>::new()));
    let g = got.clone();
    let cb_app = Router::new().route(
        "/cb",
        post(move |Json(v): Json<Value>| {
            let g = g.clone();
            async move {
                g.lock().unwrap().push(v);
                "ok"
            }
        }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cb = format!("http://{}/cb", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, cb_app).await.unwrap() });

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _server = Kill(
        Command::new(env!("CARGO_BIN_EXE_buzz-rap"))
            .args([
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--identities-reload-s",
                "1",
            ])
            .arg("--buzz-bin")
            .arg(&bin)
            .arg("--identities")
            .arg(&ids)
            .env("FAKE_LOG", &log)
            .env("BUZZ_RELAY_URL", &relay_url)
            .env_remove("BUZZ_PRIVATE_KEY")
            .env_remove("BUZZ_AUTH_TAG")
            .spawn()
            .unwrap(),
    );
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    for _ in 0..50 {
        if http.get(format!("{base}/health")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let invoke = |op: &str, args: Value, id: &str, group: &str| json!({"operation": op, "arguments": args, "id": id, "callback_url": cb, "group_id": group});
    for (scope, id) in [("mentions", "call-m"), ("dms", "call-d")] {
        let r = http
            .post(format!("{base}/invoke"))
            .json(&invoke(
                "buzz_subscribe",
                json!({"scope": scope}),
                id,
                "scout",
            ))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 202);
    }
    until("both events", || {
        got.lock()
            .unwrap()
            .iter()
            .filter(|v| v["type"] == "subscription_event")
            .count()
            >= 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    let all = got.lock().unwrap().clone();
    for id in ["call-m", "call-d"] {
        let r = all
            .iter()
            .find(|v| v["id"] == id)
            .expect("a subscribe result");
        let text = r["text"].as_str().unwrap();
        assert!(
            text.contains("your owner only"),
            "owner-only is the default with an owner: {text}"
        );
    }
    let delivered: Vec<(&str, &str)> = all
        .iter()
        .filter(|v| v["type"] == "subscription_event")
        .map(|v| {
            (
                v["tool_call_id"].as_str().unwrap(),
                v["text"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(delivered.len(), 2, "{delivered:?}");
    assert!(delivered.iter().any(|(c, t)| *c == "call-m"
        && t.contains("mention from the owner")
        && t.contains("channel ch-2")));
    assert!(delivered.iter().any(|(c, t)| *c == "call-d"
        && t.contains("a direct message from the owner")
        && t.contains("a direct message dm-1")));
    assert!(!delivered
        .iter()
        .any(|(_, t)| t.contains("stranger") || t.contains("unrelated")));

    // subscribing again in the same conversation replaces the earlier subscription (no double delivery)
    let again = http
        .post(format!("{base}/invoke"))
        .json(&invoke(
            "buzz_subscribe",
            json!({"scope": "mentions"}),
            "call-m2",
            "scout",
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 202);
    until("the replacement", || {
        got.lock().unwrap().iter().any(|v| v["id"] == "call-m2")
    })
    .await;
    let health: Value = http
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        health["subscriptions"], 2,
        "mentions (replaced) + dms: {health}"
    );

    // an agent added to the identities file while running signs with its own key, no restart
    let late_key = write_key("late.key", 6);
    std::fs::write(
        &ids,
        format!(
            "{first}\n[[identity]]\nname = \"late\"\nkey_file = \"{}\"\ngroups = [\"late\"]\n",
            late_key.display()
        ),
    )
    .unwrap();
    let mut sent = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let health: Value = http
            .get(format!("{base}/health"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        if health["identities"] == 2 {
            let send = invoke(
                "buzz_messages_send",
                json!({"channel": "c", "content": "hi"}),
                "call-late",
                "late",
            );
            http.post(format!("{base}/invoke"))
                .json(&send)
                .send()
                .await
                .unwrap();
            sent = true;
            break;
        }
    }
    assert!(sent, "the new identity was not loaded");
    until("the late send", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("messages send")
    })
    .await;
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        calls
            .lines()
            .any(|l| l.starts_with(&hex(6)) && l.contains("messages send")),
        "{calls}"
    );
    // removing the agent's identity ends its subscriptions at once, each with a final event
    std::fs::write(
        &ids,
        format!(
            "[[identity]]\nname = \"late\"\nkey_file = \"{}\"\ngroups = [\"late\"]\n",
            late_key.display()
        ),
    )
    .unwrap();
    until("both subscriptions to end", || {
        got.lock()
            .unwrap()
            .iter()
            .filter(|v| {
                v["final"] == true
                    && v["text"]
                        .as_str()
                        .is_some_and(|t| t.contains("identity was removed"))
            })
            .count()
            == 2
    })
    .await;
    let _ = std::fs::remove_dir_all(&dir);
}

//! Push delivery and many identities, end to end: the real binary, a stand-in relay that speaks NIP-42 and
//! NIP-01 over a WebSocket, a stand-in `buzz` that records which key ran each command, and a callback
//! receiver standing in for the agent runtime.

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

#[derive(Default)]
struct Relay {
    /// pubkeys that authenticated, in order
    authed: Vec<String>,
    /// (subscription id, filter) of every REQ
    reqs: Vec<(String, Value)>,
    closed: Vec<String>,
    /// events to send on the next REQ
    to_send: Vec<String>,
}

type Shared = Arc<Mutex<Relay>>;

async fn ws(State(relay): State<Shared>, up: WebSocketUpgrade) -> Response {
    up.on_upgrade(move |socket| serve_socket(socket, relay))
}

async fn serve_socket(socket: WebSocket, relay: Shared) {
    let (mut tx, mut rx) = socket.split();
    let _ = tx
        .send(Message::Text(
            json!(["AUTH", "challenge-1"]).to_string().into(),
        ))
        .await;
    while let Some(Ok(Message::Text(text))) = rx.next().await {
        let msg: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        match msg[0].as_str() {
            Some("AUTH") => {
                let ev = &msg[1];
                relay
                    .lock()
                    .unwrap()
                    .authed
                    .push(ev["pubkey"].as_str().unwrap_or("").to_owned());
                let ok = json!(["OK", ev["id"], true, ""]).to_string();
                let _ = tx.send(Message::Text(ok.into())).await;
            }
            Some("REQ") => {
                let sid = msg[1].as_str().unwrap_or("").to_owned();
                let events = {
                    let mut r = relay.lock().unwrap();
                    r.reqs.push((sid.clone(), msg[2].clone()));
                    std::mem::take(&mut r.to_send)
                };
                for e in events {
                    let frame = format!("[\"EVENT\",\"{sid}\",{e}]");
                    let _ = tx.send(Message::Text(frame.into())).await;
                }
                let _ = tx
                    .send(Message::Text(json!(["EOSE", sid]).to_string().into()))
                    .await;
            }
            Some("CLOSE") => relay
                .lock()
                .unwrap()
                .closed
                .push(msg[1].as_str().unwrap_or("").to_owned()),
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

fn signed(keys: &Keys, content: &str, channel: &str, at: u64) -> String {
    EventBuilder::new(Kind::Custom(9), content)
        .tag(Tag::parse(["h", channel]).unwrap())
        .custom_created_at(Timestamp::from(at))
        .sign_with_keys(keys)
        .unwrap()
        .as_json()
}

#[tokio::test(flavor = "multi_thread")]
async fn pushed_events_and_one_key_per_conversation() {
    let dir = std::env::temp_dir().join(format!("buzz-rap-push-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("buzz");
    std::fs::File::create(&bin)
        .unwrap()
        .write_all(FAKE_BUZZ.as_bytes())
        .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (log, audit) = (dir.join("calls.log"), dir.join("audit.jsonl"));

    // keys: 1 = the default identity, 2 = scout, 3 = a person in the channel
    let key = |n: u8| Keys::parse(&format!("{n:064x}")).unwrap();
    let (default_key, scout_key, them) = (key(1), key(2), key(3));
    let scout_file = dir.join("scout.key");
    std::fs::write(&scout_file, format!("{:064x}\n", 2)).unwrap();
    std::fs::set_permissions(&scout_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let ids = dir.join("identities.toml");
    std::fs::write(
        &ids,
        format!("[[identity]]\nname = \"scout\"\nkey_file = \"{}\"\ngroups = [\"scout\", \"scout.*\"]\n", scout_file.display()),
    )
    .unwrap();

    // the relay will hold one message from scout itself (dropped) and one from a person (delivered)
    let soon = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 2;
    let relay: Shared = Arc::new(Mutex::new(Relay {
        to_send: vec![
            signed(&scout_key, "my own echo", "ch-1", soon),
            signed(&them, "hello push", "ch-1", soon),
        ],
        ..Default::default()
    }));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("http://{}", l.local_addr().unwrap());
    let app = Router::new().route("/", get(ws)).with_state(relay.clone());
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
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .arg("--buzz-bin")
            .arg(&bin)
            .arg("--identities")
            .arg(&ids)
            .arg("--audit-log")
            .arg(&audit)
            .env("FAKE_LOG", &log)
            .env("BUZZ_RELAY_URL", &relay_url)
            .env("BUZZ_PRIVATE_KEY", format!("{:064x}", 1))
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
    let health: Value = http
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(health["delivery"], "push");
    assert_eq!(health["identities"], 2);

    let invoke = |op: &str, args: Value, id: &str, group: &str| json!({"operation": op, "arguments": args, "id": id, "callback_url": cb, "group_id": group});
    let sub = invoke(
        "buzz_subscribe",
        json!({"channel": "ch-1"}),
        "call-sub",
        "scout",
    );
    assert_eq!(
        http.post(format!("{base}/invoke"))
            .json(&sub)
            .send()
            .await
            .unwrap()
            .status(),
        202
    );

    until("the pushed event", || {
        got.lock()
            .unwrap()
            .iter()
            .any(|v| v["type"] == "subscription_event")
    })
    .await;
    let subscribed = got
        .lock()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "call-sub")
        .cloned()
        .expect("subscribe result");
    assert!(
        subscribed["text"]
            .as_str()
            .unwrap()
            .contains("pushed from the relay"),
        "{subscribed}"
    );
    {
        let r = relay.lock().unwrap();
        assert_eq!(
            r.authed,
            vec![scout_key.public_key().to_hex()],
            "scout's socket signs in as scout"
        );
        let (_, filter) = r.reqs.last().unwrap();
        assert_eq!(filter["#h"], json!(["ch-1"]));
        assert!(filter["kinds"].as_array().unwrap().contains(&json!(9)));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let events: Vec<Value> = got
        .lock()
        .unwrap()
        .iter()
        .filter(|v| v["type"] == "subscription_event")
        .cloned()
        .collect();
    assert_eq!(events.len(), 1, "scout's own post is dropped: {events:?}");
    assert!(events[0]["text"].as_str().unwrap().contains("hello push"));
    assert_eq!(events[0]["group_id"], "scout");

    // each conversation's commands run with its own key
    let send = |group: &str, id: &str| {
        invoke(
            "buzz_messages_send",
            json!({"channel": "ch-1", "content": "hi"}),
            id,
            group,
        )
    };
    http.post(format!("{base}/invoke"))
        .json(&send("scout.gf-1", "call-a"))
        .send()
        .await
        .unwrap();
    http.post(format!("{base}/invoke"))
        .json(&send("someone-else", "call-b"))
        .send()
        .await
        .unwrap();
    until("both sends", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .matches("messages send")
            .count()
            == 2
    })
    .await;
    let calls = std::fs::read_to_string(&log).unwrap();
    let scout_hex = format!("{:064x}", 2);
    let default_hex = format!("{:064x}", 1);
    assert!(
        calls
            .lines()
            .any(|l| l.starts_with(&scout_hex) && l.contains("messages send")),
        "{calls}"
    );
    assert!(
        calls
            .lines()
            .any(|l| l.starts_with(&default_hex) && l.contains("messages send")),
        "{calls}"
    );
    assert!(
        calls
            .lines()
            .any(|l| l.starts_with(&scout_hex) && l.contains("messages get")),
        "the subscribe probe ran as scout: {calls}"
    );

    until("the audit lines", || {
        std::fs::read_to_string(&audit)
            .unwrap_or_default()
            .matches(r#""kind":"call""#)
            .count()
            >= 3
    })
    .await;
    let lines: Vec<Value> = std::fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let a = lines
        .iter()
        .find(|e| e["kind"] == "call" && e["id"] == "call-a")
        .unwrap();
    let b = lines
        .iter()
        .find(|e| e["kind"] == "call" && e["id"] == "call-b")
        .unwrap();
    assert_eq!(a["identity_name"], "scout");
    assert_eq!(a["identity"], scout_key.public_key().to_hex());
    assert_eq!(b["identity_name"], "default");
    assert_eq!(b["identity"], default_key.public_key().to_hex());
    let delivered = lines
        .iter()
        .find(|e| e["kind"] == "subscription_event")
        .unwrap();
    assert_eq!(delivered["author"], them.public_key().to_hex());
    assert_eq!(delivered["identity_name"], "scout");

    // unsubscribing closes the relay subscription
    let unsub = invoke(
        "buzz_unsubscribe",
        json!({"subscription": "call-sub"}),
        "call-unsub",
        "scout",
    );
    http.post(format!("{base}/invoke"))
        .json(&unsub)
        .send()
        .await
        .unwrap();
    until("the CLOSE", || !relay.lock().unwrap().closed.is_empty()).await;
    let _ = std::fs::remove_dir_all(&dir);
}

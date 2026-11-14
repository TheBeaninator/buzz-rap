//! The server end to end: the real binary, a stand-in `buzz` that records its arguments, and a callback
//! receiver standing in for the agent runtime.

use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const FAKE_BUZZ: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$*" in
  "messages send"*) echo '{"accepted":true,"event_id":"ev-sent"}' ;;
  "messages get"*"--since"*)
    at=4102444800
    echo "[{\"id\":\"ev-them\",\"pubkey\":\"them\",\"kind\":9,\"content\":\"hello agent\",\"created_at\":$at,\"tags\":[]}]" ;;
  "messages get"*) echo '[]' ;;
  *) echo "unknown: $*" >&2; exit 2 ;;
esac
"#;

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

async fn receiver() -> (String, Arc<Mutex<Vec<Value>>>) {
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    let app = Router::new().route(
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
    let url = format!("http://{}/cb", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, got)
}

async fn wait_for(got: &Arc<Mutex<Vec<Value>>>, n: usize) -> Vec<Value> {
    for _ in 0..100 {
        if got.lock().unwrap().len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    got.lock().unwrap().clone()
}

#[tokio::test]
async fn invoke_dedupe_and_subscribe() {
    let dir = std::env::temp_dir().join(format!("buzz-rap-e2e-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("buzz");
    std::fs::File::create(&bin)
        .unwrap()
        .write_all(FAKE_BUZZ.as_bytes())
        .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let log = dir.join("calls.log");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let _server = Server(
        Command::new(env!("CARGO_BIN_EXE_buzz-rap"))
            .args(["--listen", &format!("127.0.0.1:{port}"), "--poll-ms", "300"])
            .arg("--buzz-bin")
            .arg(&bin)
            .arg("--state")
            .arg(dir.join("state.json"))
            .arg("--audit-log")
            .arg(dir.join("audit.jsonl"))
            .env("FAKE_LOG", &log)
            // secret key 1: a valid identity, so subscriptions are allowed; the stand-in buzz ignores it
            .env("BUZZ_PRIVATE_KEY", format!("{:064x}", 1))
            .spawn()
            .unwrap(),
    );
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::new();
    let mut manifest = None;
    for _ in 0..50 {
        if let Ok(r) = http
            .get(format!("{base}/.well-known/rap-toolset"))
            .send()
            .await
        {
            manifest = Some(r.json::<Value>().await.unwrap());
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let manifest = manifest.expect("server came up");
    assert_eq!(manifest["endpoint"], format!("{base}/invoke"));
    let names: Vec<&str> = manifest["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(
        names.contains(&"buzz_messages_send") && names.contains(&"buzz_subscribe"),
        "{names:?}"
    );

    let (cb, got) = receiver().await;
    let send = json!({"operation": "buzz_messages_send", "arguments": {"channel": "ch-1", "content": "hi"},
        "id": "call-1", "call_id": "prov-1", "callback_url": cb, "group_id": "thread-a"});
    let r = http
        .post(format!("{base}/invoke"))
        .json(&send)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 202);
    let first = wait_for(&got, 1).await;
    assert_eq!(first[0]["type"], "tool_result");
    assert_eq!(first[0]["id"], "call-1");
    assert!(
        first[0]["text"].as_str().unwrap().contains("ev-sent"),
        "{first:?}"
    );

    // the same call delivered again: same result, the message is not sent twice
    let r = http
        .post(format!("{base}/invoke"))
        .json(&send)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let again = wait_for(&got, 2).await;
    assert_eq!(again[1], again[0]);
    let calls = std::fs::read_to_string(&log).unwrap();
    assert_eq!(calls.matches("messages send").count(), 1, "{calls}");

    let unknown = json!({"operation": "buzz_nope", "arguments": {}, "id": "c", "callback_url": cb, "group_id": "thread-a"});
    assert_eq!(
        http.post(format!("{base}/invoke"))
            .json(&unknown)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    let sub = json!({"operation": "buzz_subscribe", "arguments": {"channel": "ch-1"},
        "id": "call-2", "callback_url": cb, "group_id": "thread-a"});
    assert_eq!(
        http.post(format!("{base}/invoke"))
            .json(&sub)
            .send()
            .await
            .unwrap()
            .status(),
        202
    );
    let all = wait_for(&got, 4).await;
    let subscribed = all
        .iter()
        .find(|v| v["id"] == "call-2")
        .expect("subscribe result");
    assert!(
        subscribed["text"]
            .as_str()
            .unwrap()
            .starts_with("Subscribed"),
        "{subscribed}"
    );
    let ev = all
        .iter()
        .find(|v| v["type"] == "subscription_event")
        .expect("an event");
    assert_eq!(ev["tool_call_id"], "call-2");
    assert_eq!(ev["group_id"], "thread-a");
    assert!(ev["text"].as_str().unwrap().contains("hello agent"), "{ev}");
    let events = all
        .iter()
        .filter(|v| v["type"] == "subscription_event")
        .count();
    tokio::time::sleep(Duration::from_millis(900)).await;
    let later = got
        .lock()
        .unwrap()
        .iter()
        .filter(|v| v["type"] == "subscription_event")
        .count();
    assert_eq!(
        later, events,
        "a message is delivered once, not on every poll"
    );

    let state: Value =
        serde_json::from_slice(&std::fs::read(dir.join("state.json")).unwrap()).unwrap();
    assert_eq!(
        state["subs"].as_array().unwrap().len(),
        1,
        "the subscription is kept for a restart"
    );
    // the audit trail ties every Buzz action to the calling conversation and call
    let audit: Vec<Value> = std::fs::read_to_string(dir.join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let call = audit
        .iter()
        .find(|e| e["kind"] == "call" && e["id"] == "call-1")
        .expect("a call line");
    assert_eq!(call["group_id"], "thread-a");
    assert_eq!(call["call_id"], "prov-1");
    assert_eq!(call["event_ids"], json!(["ev-sent"]));
    assert_eq!(call["argv"][0], "messages");
    assert_eq!(call["arguments"]["content"], "hi");
    assert!(audit
        .iter()
        .any(|e| e["kind"] == "callback" && e["id"] == "call-1" && e["delivered"] == true));
    assert!(audit
        .iter()
        .any(|e| e["kind"] == "duplicate" && e["id"] == "call-1" && e["replayed"] == true));
    assert!(audit
        .iter()
        .any(|e| e["kind"] == "refused" && e["operation"] == "buzz_nope"));
    let delivered = audit
        .iter()
        .find(|e| e["kind"] == "subscription_event")
        .expect("a subscription line");
    assert_eq!(delivered["event_id"], "ev-them");
    assert_eq!(delivered["author"], "them");
    assert_eq!(delivered["subscription"], "call-2");
    assert_eq!(delivered["group_id"], "thread-a");
    let _ = std::fs::remove_dir_all(&dir);
}

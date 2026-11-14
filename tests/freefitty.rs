//! buzz-rap with its sibling runtime, FreeFitty (https://github.com/TheBeaninator/freefitty), both as real
//! binaries. A scripted model node drives one thread: it subscribes to a channel, sleeps, wakes on a message
//! there, and replies in that message's thread. buzz-rap runs a stand-in `buzz`; FreeFitty lists buzz-rap as an
//! opt-in tool server and the thread is started with the buzz tools, the way a Buzz member is set up.
//!
//! Runs when FREEFITTY_BIN names a freefitty binary (CI builds one from its repository); skipped otherwise.

use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

const FAKE_BUZZ: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$*" in
  "messages send"*) echo '{"accepted":true,"event_id":"ev-sent"}' ;;
  "messages get"*"--since"*)
    echo '[{"id":"ev-them","pubkey":"them","kind":9,"content":"hello scout","created_at":4102444800,"tags":[]}]' ;;
  "messages get"*) echo '[]' ;;
  *) echo "unknown: $*" >&2; exit 2 ;;
esac
"#;

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn call(name: &str, args: Value, n: usize) -> Value {
    json!({"choices": [{"message": {"role": "assistant", "content": null, "tool_calls": [{
        "id": format!("call_{n}"), "type": "function",
        "function": {"name": name, "arguments": args.to_string()}}]}, "finish_reason": "tool_calls"}],
        "usage": {"prompt_tokens": 1}})
}

/// The model: decides from what arrived since its last turn.
async fn completions(Json(body): Json<Value>) -> Json<Value> {
    let msgs = body["messages"].as_array().cloned().unwrap_or_default();
    let since_last_turn: String = msgs
        .iter()
        .rev()
        .take_while(|m| m["role"] != "assistant")
        .map(|m| m["content"].as_str().unwrap_or("").to_owned())
        .collect::<Vec<_>>()
        .join("\n");
    let n = msgs.len();
    Json(if since_last_turn.contains("Join channel ch-1") {
        call("buzz_subscribe", json!({"channel": "ch-1"}), n)
    } else if since_last_turn.contains("hello scout") {
        call(
            "buzz_messages_send",
            json!({"channel": "ch-1", "content": "hi back", "reply_to": "ev-them"}),
            n,
        )
    } else if since_last_turn.starts_with("Subscribed") || since_last_turn.contains("ev-sent") {
        call("sleep_until_event_or_input", json!({}), n)
    } else {
        json!({"choices": [{"message": {"role": "assistant", "content": "idle"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1}})
    })
}

async fn model_node() -> String {
    let app = Router::new()
        .route(
            "/health",
            get(|| async {
                Json(json!({"status": "ok", "model": "fake", "slots": 2, "busy_slots": 0, "queued": 0, "context_length": 262144}))
            }),
        )
        .route("/v1/chat/completions", post(completions));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

async fn until(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    for _ in 0..secs * 10 {
        if ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_freefitty_thread_lives_in_a_channel() {
    let Ok(freefitty) = std::env::var("FREEFITTY_BIN") else {
        eprintln!(
            "skipped: set FREEFITTY_BIN to a freefitty binary to run buzz-rap with FreeFitty"
        );
        return;
    };
    let dir = std::env::temp_dir().join(format!("buzz-rap-ff-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("buzz");
    std::fs::File::create(&bin)
        .unwrap()
        .write_all(FAKE_BUZZ.as_bytes())
        .unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (log, audit) = (dir.join("calls.log"), dir.join("audit.jsonl"));

    let rap_port = free_port();
    let rap_url = format!("http://127.0.0.1:{rap_port}");
    let _rap = Kill(
        Command::new(env!("CARGO_BIN_EXE_buzz-rap"))
            .args([
                "--listen",
                &format!("127.0.0.1:{rap_port}"),
                "--poll-ms",
                "300",
            ])
            .arg("--buzz-bin")
            .arg(&bin)
            .arg("--audit-log")
            .arg(&audit)
            .env("FAKE_LOG", &log)
            .env("BUZZ_PRIVATE_KEY", format!("{:064x}", 1))
            .spawn()
            .unwrap(),
    );
    let http = reqwest::Client::new();
    let manifest = format!("{rap_url}/.well-known/rap-toolset");
    for _ in 0..50 {
        if http.get(&manifest).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // FreeFitty reads tool manifests at start, so buzz-rap is up first
    let node = model_node().await;
    let ff_port = free_port();
    let cfg = dir.join("freefitty.toml");
    let ff = |args: &[&str]| {
        let out = Command::new(&freefitty)
            .arg("--config")
            .arg(&cfg)
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "freefitty {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    let data = dir.join("data");
    ff(&[
        "init",
        "--nodes",
        &node,
        "--optin-tool-servers",
        &rap_url,
        "--listen",
        &format!("127.0.0.1:{ff_port}"),
        "--data-dir",
        data.to_str().unwrap(),
    ]);
    let _ff = Kill(
        Command::new(&freefitty)
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .spawn()
            .unwrap(),
    );
    let health = format!("http://127.0.0.1:{ff_port}/health");
    for _ in 0..100 {
        if http
            .get(&health)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    ff(&[
        "say",
        "--thread",
        "scout",
        "--tools",
        "buzz_subscribe,buzz_messages_send",
        "Join channel ch-1 and answer there.",
    ]);

    // subscribe -> sleep -> the channel message wakes the thread -> it replies in that message's thread
    until("the reply to reach buzz", 30, || {
        read(&log).contains("messages send")
    })
    .await;
    let calls = read(&log);
    assert!(
        calls.contains("messages send --channel=ch-1 --content=hi back --reply-to=ev-them"),
        "{calls}"
    );
    assert_eq!(
        calls.matches("messages send").count(),
        1,
        "one reply: {calls}"
    );

    // the audit line is written once the command has finished, a moment after the stand-in logged its start
    until("the reply's audit line", 10, || {
        read(&audit).contains(r#""operation":"buzz_messages_send""#)
            && read(&audit).contains(r#""kind":"call""#)
    })
    .await;
    let lines: Vec<Value> = read(&audit)
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let sent = lines
        .iter()
        .find(|e| e["kind"] == "call" && e["operation"] == "buzz_messages_send")
        .expect("an audit line for the reply");
    assert_eq!(
        sent["group_id"], "scout",
        "the audit names the FreeFitty thread"
    );
    assert!(
        !read(&audit).contains("/rap/callback/"),
        "the callback token is never logged"
    );
    assert_eq!(sent["event_ids"], json!(["ev-sent"]));
    let woke = lines
        .iter()
        .find(|e| e["kind"] == "subscription_event")
        .expect("a delivered event");
    assert_eq!(woke["event_id"], "ev-them");
    assert_eq!(woke["delivered"], true);
    let _ = std::fs::remove_dir_all(&dir);
}

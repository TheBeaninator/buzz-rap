//! Sign-in approval in Buzz, end to end: buzz-beekeeper with its own Buzz key and a stand-in `buzz` whose
//! reactions the test controls. The page waits; a stranger's 👍 does nothing; the owner's 👍 approves and the
//! session comes out bound to the owner's key; ❌ refuses.

use nostr::hashes::Hash;
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

const CALLBACK: &str = "xyz.block.buzz.mobile:/auth/callback";

const FAKE_BUZZ: &str = r#"#!/bin/sh
echo "$*" >> "$FAKE_LOG"
case "$*" in
  "dms open"*) echo '{"accepted":true,"dm_id":"dm-1"}' ;;
  "messages send"*) echo '{"accepted":true,"event_id":"ev-ask"}' ;;
  "reactions get"*) cat "$FAKE_REACTIONS" ;;
  *) echo "unknown: $*" >&2; exit 2 ;;
esac
"#;

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn b64(bytes: &[u8]) -> String {
    use nostr::base64::Engine;
    nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge_of(verifier: &str) -> String {
    b64(&nostr::hashes::sha256::Hash::hash(verifier.as_bytes()).to_byte_array())
}

fn set_reactions(path: &Path, v: Value) {
    std::fs::write(path, v.to_string()).unwrap();
}

async fn status(http: &reqwest::Client, base: &str, id: &str) -> Value {
    http.get(format!("{base}/auth/native/status?id={id}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_waits_for_the_owner_in_buzz() {
    let dir = std::env::temp_dir().join(format!("beekeeper-approval-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let bin = dir.join("buzz");
    std::fs::write(&bin, FAKE_BUZZ).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (log, reactions) = (dir.join("buzz.log"), dir.join("reactions.json"));
    set_reactions(&reactions, json!([]));
    let key = dir.join("service.key");
    std::fs::write(&key, format!("{:064x}", 7)).unwrap();
    let owner = nostr::Keys::parse(&format!("{:064x}", 4))
        .unwrap()
        .public_key()
        .to_hex();
    let stranger = nostr::Keys::parse(&format!("{:064x}", 3))
        .unwrap()
        .public_key()
        .to_hex();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let _server = Kill(
        Command::new(env!("CARGO_BIN_EXE_buzz-beekeeper"))
            .args(["--listen", &format!("127.0.0.1:{port}"), "--owner", &owner])
            .arg("--state-dir")
            .arg(dir.join("state"))
            .arg("--buzz-key-file")
            .arg(&key)
            .arg("--buzz-bin")
            .arg(&bin)
            .args(["--approval-timeout-s", "60"])
            .env("FAKE_LOG", &log)
            .env("FAKE_REACTIONS", &reactions)
            .spawn()
            .unwrap(),
    );
    let base = format!("http://127.0.0.1:{port}");
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    for _ in 0..100 {
        if http.get(format!("{base}/nope")).send().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // the browser leg shows a waiting page with a code, and the owner gets a message naming it
    let verifier = "v".repeat(50);
    let url = format!(
        "{base}/auth/native?returnTo={CALLBACK}&state=s1&code_challenge={}&code_challenge_method=S256",
        challenge_of(&verifier)
    );
    let r = http.get(&url).send().await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the page waits instead of redirecting"
    );
    let html = r.text().await.unwrap();
    let id = html
        .split("status?id=")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    let code = html
        .split("class=\"code\">")
        .nth(1)
        .unwrap()
        .split('<')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(code.len(), 4);
    for _ in 0..50 {
        if std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("messages send")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains(&format!("dms open --pubkey={owner}")),
        "{calls}"
    );
    assert!(
        calls.contains("messages send --channel=dm-1") && calls.contains(&code),
        "{calls}"
    );
    assert_eq!(status(&http, &base, &id).await["state"], "waiting");

    // a stranger's 👍 changes nothing
    set_reactions(
        &reactions,
        json!([{"emoji": "👍", "count": 1, "pubkeys": [stranger]}]),
    );
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(status(&http, &base, &id).await["state"], "waiting");

    // the owner's 👍 approves: the redirect carries a code whose session is bound to the owner
    set_reactions(
        &reactions,
        json!([{"emoji": "👍", "count": 2, "pubkeys": [stranger, owner]}]),
    );
    let mut redirect = String::new();
    for _ in 0..40 {
        let s = status(&http, &base, &id).await;
        if s["state"] == "approved" {
            redirect = s["redirect"].as_str().unwrap().to_owned();
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        redirect.starts_with(&format!("{CALLBACK}?code=")) && redirect.ends_with("&state=s1"),
        "{redirect}"
    );
    let login_code = redirect
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let ex: Value = http
        .post(format!("{base}/api/goose/v1/auth/login/exchange"))
        .json(&json!({"code": login_code, "code_verifier": verifier}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cred = ex["session_credential"]
        .as_str()
        .expect("a session")
        .to_owned();
    let post = |path: &str| {
        http.post(format!("{base}/api/goose{path}"))
            .header("X-BB-Session-Credential", &cred)
            .json(&json!({}))
            .send()
    };
    let current: Value = post("/v1/buzz/nostr-identities/current")
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        current["identity"]["pubkey_hex"], owner,
        "the session is bound to the approver"
    );
    let list = post("/v3/beekeeper/list-agents").await.unwrap();
    assert_eq!(
        list.status().as_u16(),
        200,
        "a bound session may use the registry"
    );

    // a second sign-in refused with ❌
    set_reactions(&reactions, json!([]));
    let r = http.get(&url).send().await.unwrap();
    let html = r.text().await.unwrap();
    let id2 = html
        .split("status?id=")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned();
    set_reactions(
        &reactions,
        json!([{"emoji": "❌", "count": 1, "pubkeys": [owner]}]),
    );
    let mut denied = false;
    for _ in 0..40 {
        if status(&http, &base, &id2).await["state"] == "denied" {
            denied = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(denied);
    let _ = std::fs::remove_dir_all(&dir);
}

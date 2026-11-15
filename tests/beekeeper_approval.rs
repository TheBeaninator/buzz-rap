//! Sign-in approval in Buzz, end to end: buzz-beekeeper with its own Buzz key and a stand-in `buzz` whose
//! reactions the test controls. Sign-in completes at once but the session can do nothing; a stranger's 👍 changes
//! nothing; the owner's 👍 binds the session to the owner's key; ❌ deletes the session.

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

struct Svc {
    http: reqwest::Client,
    base: String,
}

impl Svc {
    /// The app's sign-in: the browser leg (which must redirect at once), then the code exchange.
    async fn sign_in(&self, verifier: &str) -> String {
        let url = format!(
            "{}/auth/native?returnTo={CALLBACK}&state=s1&code_challenge={}&code_challenge_method=S256",
            self.base,
            challenge_of(verifier)
        );
        let r = self.http.get(&url).send().await.unwrap();
        assert_eq!(r.status().as_u16(), 302, "sign-in redirects at once");
        let loc = r.headers()["location"].to_str().unwrap().to_owned();
        let code = loc
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_owned();
        let ex: Value = self
            .http
            .post(format!("{}/api/goose/v1/auth/login/exchange", self.base))
            .json(&json!({"code": code, "code_verifier": verifier}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        ex["session_credential"]
            .as_str()
            .expect("a session")
            .to_owned()
    }

    async fn call(&self, cred: &str, path: &str) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}/api/goose{path}", self.base))
            .header("X-BB-Session-Credential", cred)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        let code = r.status().as_u16();
        (code, r.json::<Value>().await.unwrap_or(Value::Null))
    }

    async fn bound_key(&self, cred: &str) -> Value {
        self.call(cred, "/v1/buzz/nostr-identities/current").await.1["identity"]["pubkey_hex"]
            .clone()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_is_confirmed_by_the_owner_in_buzz() {
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
    let svc = Svc {
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        base: format!("http://127.0.0.1:{port}"),
    };
    for _ in 0..100 {
        if svc
            .http
            .get(format!("{}/nope", svc.base))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // sign in: done at once, but the session is unconfirmed and the owner is asked in Buzz
    let cred = svc.sign_in(&"v".repeat(50)).await;
    assert!(
        svc.bound_key(&cred).await.is_null(),
        "unconfirmed: no key yet"
    );
    assert_eq!(svc.call(&cred, "/v3/beekeeper/list-agents").await.0, 403);
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
        calls.contains("messages send --channel=dm-1") && calls.contains("react"),
        "{calls}"
    );

    // a stranger's 👍 changes nothing
    set_reactions(
        &reactions,
        json!([{"emoji": "👍", "count": 1, "pubkeys": [stranger]}]),
    );
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(svc.call(&cred, "/v3/beekeeper/list-agents").await.0, 403);

    // the owner's 👍 binds the existing session to the owner's key
    set_reactions(
        &reactions,
        json!([{"emoji": "👍", "count": 2, "pubkeys": [stranger, owner]}]),
    );
    let mut bound = false;
    for _ in 0..40 {
        if svc.bound_key(&cred).await == owner {
            bound = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(bound, "the session is bound to the approver");
    assert_eq!(svc.call(&cred, "/v3/beekeeper/list-agents").await.0, 200);

    // a second sign-in refused with ❌ loses its session; the approved one is unaffected
    set_reactions(&reactions, json!([]));
    let cred2 = svc.sign_in(&"w".repeat(50)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    set_reactions(
        &reactions,
        json!([{"emoji": "❌", "count": 1, "pubkeys": [owner]}]),
    );
    let mut gone = false;
    for _ in 0..40 {
        if svc
            .call(&cred2, "/v1/buzz/nostr-identities/current")
            .await
            .0
            == 401
        {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(gone, "a refused sign-in loses its session");
    assert_eq!(svc.call(&cred, "/v3/beekeeper/list-agents").await.0, 200);
    let _ = std::fs::remove_dir_all(&dir);
}

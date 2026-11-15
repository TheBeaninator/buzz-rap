//! buzz-beekeeper end to end: the real binary over HTTP, driven the way the Buzz app drives it (sign-in with
//! PKCE, key binding with a signed kind 24243 event, the agent registry, key backup), with a stand-in
//! OpenAI-compatible `/v1/models` and shell commands standing in for relay membership.

use axum::routing::get;
use axum::{Json, Router};
use nostr::hashes::Hash;
use nostr::secp256k1::Message;
use nostr::{EventBuilder, JsonUtil, Keys, Kind, Tag};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

const ORIGIN: &str = "https://bee.example";
const CALLBACK: &str = "xyz.block.buzz.mobile:/auth/callback";

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn b64(bytes: &[u8]) -> String {
    use nostr::base64::Engine;
    nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    nostr::hashes::sha256::Hash::hash(bytes).to_byte_array()
}

/// The sign-in URL the app opens (its values need no escaping here).
fn login_url(base: &str, return_to: &str, state: &str, challenge: &str) -> String {
    format!("{base}/auth/native?returnTo={return_to}&state={state}&code_challenge={challenge}&code_challenge_method=S256")
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

async fn models_backend() -> String {
    let app = Router::new().route(
        "/v1/models",
        get(|| async { Json(json!({"object": "list", "data": [{"id": "m1"}, {"id": "m2"}]})) }),
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

struct Bee {
    base: String,
    http: reqwest::Client,
    dir: PathBuf,
    _server: Server,
}

impl Bee {
    async fn start(owner: &str) -> Bee {
        let dir = std::env::temp_dir().join(format!("beekeeper-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let models = models_backend().await;
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let log = dir.join("hooks.log");
        let server = Server(
            Command::new(env!("CARGO_BIN_EXE_buzz-beekeeper"))
                .args(["--listen", &format!("127.0.0.1:{port}")])
                .arg("--state-dir")
                .arg(dir.join("state"))
                .args(["--owner", owner, "--public-origin", ORIGIN])
                .args(["--models-url", &models, "--recommended-model", "m2"])
                .args(["--community", "wss://relay.example"])
                .arg("--member-add-cmd")
                .arg(format!(
                    "echo add {{pubkey}} $BEEKEEPER_COMMUNITY_URL >> {}",
                    log.display()
                ))
                .arg("--member-remove-cmd")
                .arg(format!("echo remove {{agent_id}} >> {}", log.display()))
                .arg("--on-change")
                .arg(format!(
                    "echo changed $BEEKEEPER_REGISTRY >> {}",
                    dir.join("changes.log").display()
                ))
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
        Bee {
            base,
            http,
            dir,
            _server: server,
        }
    }

    async fn post(&self, cred: Option<&str>, path: &str, body: Value) -> (u16, Value) {
        let mut req = self
            .http
            .post(format!("{}/api/goose{path}", self.base))
            .header("Origin", ORIGIN)
            .json(&body);
        if let Some(c) = cred {
            req = req.header("X-BB-Session-Credential", c);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        (status, r.json().await.unwrap_or(Value::Null))
    }

    /// The browser leg: returns the one-use code the callback carries.
    async fn login(&self, verifier: &str, state: &str) -> String {
        let challenge = b64(&sha256(verifier.as_bytes()));
        let r = self
            .http
            .get(login_url(&self.base, CALLBACK, state, &challenge))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 302);
        let loc = r.headers()["location"].to_str().unwrap().to_owned();
        let (to, query) = loc.split_once('?').unwrap();
        assert_eq!(to, CALLBACK);
        let q: Vec<(&str, &str)> = query
            .split('&')
            .map(|kv| kv.split_once('=').unwrap())
            .collect();
        assert_eq!(q.len(), 2, "the app accepts only code and state: {loc}");
        assert!(q.contains(&("state", state)));
        q.iter().find(|(k, _)| *k == "code").unwrap().1.to_owned()
    }

    /// Asks for a challenge and answers it with an event signed by `keys`, optionally with one tag altered.
    async fn bind(&self, cred: &str, keys: &Keys, tamper: Option<&str>) -> (u16, Value) {
        let (s, c) = self
            .post(
                Some(cred),
                "/v1/buzz/nostr-identities/challenge",
                json!({"origin": ORIGIN}),
            )
            .await;
        assert_eq!(s, 200, "{c}");
        let field = |k: &str| c[k].as_str().unwrap().to_owned();
        let mut tags = vec![
            ("challenge_id", field("challenge_id")),
            ("nonce", field("nonce")),
            ("verification_code", field("verification_code")),
            ("audience", "buzz:nostr-identity".into()),
            ("action", "bind_nostr_identity".into()),
            ("protocol", "buzz-nostr-identity".into()),
            ("version", "1".into()),
            ("origin", field("origin")),
            ("expires_at", field("expires_at")),
        ];
        if let Some(t) = tamper {
            tags.iter_mut().find(|(k, _)| *k == t).unwrap().1 = "wrong".into();
        }
        let event = EventBuilder::new(Kind::Custom(24243), "")
            .tags(
                tags.iter()
                    .map(|(k, v)| Tag::parse([*k, v.as_str()]).unwrap()),
            )
            .sign_with_keys(keys)
            .unwrap();
        self.post(
            Some(cred),
            "/v1/buzz/nostr-identities/verify",
            json!({"challenge_id": field("challenge_id"), "nonce": field("nonce"), "signed_payload": event.as_json()}),
        )
        .await
    }

    /// A full sign-in, returning the session credential.
    async fn session(&self) -> String {
        let verifier = b64(&[7u8; 40]);
        let code = self.login(&verifier, "s1").await;
        let (s, v) = self
            .post(
                None,
                "/v1/auth/login/exchange",
                json!({"code": code, "code_verifier": verifier}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        v["session_credential"].as_str().unwrap().to_owned()
    }
}

fn owner_tag(owner: &Keys, agent: &str) -> String {
    let digest = sha256(format!("nostr:agent-auth:{agent}:").as_bytes());
    let sig = owner.sign_schnorr(&Message::from_digest(digest));
    json!(["auth", owner.public_key().to_hex(), "", sig.to_string()]).to_string()
}

#[tokio::test]
async fn the_app_flow_end_to_end() {
    let owner = Keys::generate();
    let owner_hex = owner.public_key().to_hex();
    let stranger = Keys::generate();
    let bee = Bee::start(&owner_hex).await;

    // ---- sign-in ----
    let r = bee
        .http
        .get(login_url(
            &bee.base,
            "https://evil.example/cb",
            "s",
            &b64(&[0u8; 32]),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400, "an unknown callback is refused");

    let verifier = b64(&[1u8; 40]);
    let code = bee.login(&verifier, "state-1").await;
    let (s, _) = bee
        .post(
            None,
            "/v1/auth/login/exchange",
            json!({"code": code, "code_verifier": b64(&[2u8; 40])}),
        )
        .await;
    assert_eq!(s, 400, "a wrong PKCE verifier is refused");
    let (s, _) = bee
        .post(
            None,
            "/v1/auth/login/exchange",
            json!({"code": code, "code_verifier": verifier}),
        )
        .await;
    assert_eq!(s, 400, "a code is good for one try");

    let code = bee.login(&verifier, "state-2").await;
    let (s, ex) = bee
        .post(
            None,
            "/v1/auth/login/exchange",
            json!({"code": code, "code_verifier": verifier}),
        )
        .await;
    assert_eq!(s, 200, "{ex}");
    let cred = ex["session_credential"].as_str().unwrap().to_owned();
    assert!(!cred.is_empty() && cred.len() <= 512);
    let me = bee
        .http
        .get(format!("{}/api/goose/v1/auth/me", bee.base))
        .header("X-BB-Session-Credential", &cred)
        .send()
        .await
        .unwrap();
    assert_eq!(me.status().as_u16(), 200);
    let me: Value = me.json().await.unwrap();
    assert_eq!(me["subject"], "owner");
    assert_eq!(me["expires_at"], ex["expires_at"]);
    let anon = bee
        .http
        .get(format!("{}/api/goose/v1/auth/me", bee.base))
        .send()
        .await
        .unwrap();
    assert_eq!(anon.status().as_u16(), 401);
    let (s, _) = bee
        .post(
            Some("not-a-session"),
            "/v3/beekeeper/list-agents",
            json!({}),
        )
        .await;
    assert_eq!(s, 401);

    // ---- an unbound session can do nothing but bind ----
    let (s, v) = bee
        .post(Some(&cred), "/v1/buzz/nostr-identities/current", json!({}))
        .await;
    assert_eq!((s, v.get("identity")), (200, None));
    let (s, v) = bee
        .post(Some(&cred), "/v1/buzz/nsec-backups/status", json!({}))
        .await;
    assert_eq!(s, 200);
    assert_eq!(
        v,
        json!({"current_nostr_pubkey": null, "backup_nostr_pubkeys": []})
    );
    for path in [
        "/v3/beekeeper/list-agents",
        "/v3/beekeeper/get-model-catalog",
        "/v3/beekeeper/register-agent",
        "/v3/beekeeper/attest-agent",
        "/v3/beekeeper/update-agent",
        "/v3/beekeeper/delete-agent",
        "/v1/buzz/nsec-backups/enrollment",
        "/v1/buzz/nsec-backups",
        "/v1/buzz/known-communities/add",
    ] {
        let (s, _) = bee
            .post(Some(&cred), path, json!({"include_instructions": true}))
            .await;
        assert_eq!(s, 403, "{path} needs a bound key");
    }

    // ---- binding ----
    let (s, _) = bee.bind(&cred, &stranger, None).await;
    assert_eq!(s, 403, "a key off the allowlist cannot bind");
    let (s, _) = bee.bind(&cred, &owner, Some("nonce")).await;
    assert_eq!(s, 400, "a tag that does not match the challenge");
    let (s, _) = bee.bind(&cred, &owner, Some("audience")).await;
    assert_eq!(s, 400);
    let (s, _) = bee
        .post(Some(&cred), "/v3/beekeeper/list-agents", json!({}))
        .await;
    assert_eq!(s, 403, "still unbound");
    let (s, v) = bee.bind(&cred, &owner, None).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["identity"]["pubkey_hex"], owner_hex);
    let (_, v) = bee
        .post(Some(&cred), "/v1/buzz/nostr-identities/current", json!({}))
        .await;
    assert_eq!(v["identity"]["pubkey_hex"], owner_hex);

    // A second sign-in is its own session and starts unbound.
    let other = bee.session().await;
    let (s, _) = bee
        .post(Some(&other), "/v3/beekeeper/list-agents", json!({}))
        .await;
    assert_eq!(s, 403);

    // ---- model catalog ----
    let (s, cat) = bee
        .post(Some(&cred), "/v3/beekeeper/get-model-catalog", json!({}))
        .await;
    assert_eq!(s, 200, "{cat}");
    assert_eq!(
        cat["models"],
        json!([
            {"id": "m1", "display_name": "m1", "supported_reasoning_efforts": ["low", "medium", "high"]},
            {"id": "m2", "display_name": "m2", "supported_reasoning_efforts": ["low", "medium", "high"]},
        ])
    );
    assert_eq!(
        cat["recommended_selection"],
        json!({"model_id": "m2", "reasoning_effort": "medium"})
    );

    // ---- register ----
    let key = "0b4e4f7a-3c1d-4e8f-9a2b-6c5d4e3f2a1b";
    let req = json!({"agent_name": "Scout", "agent_picture_url": "https://img.example/a.png", "idempotency_key": key});
    let (s, a) = bee
        .post(Some(&cred), "/v3/beekeeper/register-agent", req.clone())
        .await;
    assert_eq!(s, 200, "{a}");
    assert_eq!(a["status"], "REGISTER_AGENT_STATUS_UNATTESTED");
    let agent_pk = a["agent_pubkey"].as_str().unwrap().to_owned();
    let agent_id = a["agent_id"].as_str().unwrap().to_owned();
    assert_eq!(agent_pk.len(), 64);
    let (s, again) = bee
        .post(Some(&cred), "/v3/beekeeper/register-agent", req)
        .await;
    assert_eq!(s, 200);
    assert_eq!(
        again, a,
        "a replayed idempotency key returns the same agent"
    );
    let (s, _) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/register-agent",
            json!({"agent_name": "no/slashes", "idempotency_key": "1b4e4f7a-3c1d-4e8f-9a2b-6c5d4e3f2a1b"}),
        )
        .await;
    assert_eq!(s, 422);

    let state = bee.dir.join("state");
    let key_file = state.join("keys").join(format!("{agent_id}.key"));
    assert_eq!(mode(&key_file), 0o600, "the agent secret is private");
    let secret = std::fs::read_to_string(&key_file).unwrap();
    assert_eq!(
        Keys::parse(secret.trim()).unwrap().public_key().to_hex(),
        agent_pk
    );
    let ids_file = state.join("identities.toml");
    let ids: toml::Value = toml::from_str(&std::fs::read_to_string(&ids_file).unwrap()).unwrap();
    assert_eq!(
        ids["identity"].as_array().unwrap().len(),
        0,
        "not active yet"
    );

    // ---- attest ----
    let wrong_owner = owner_tag(&stranger, &agent_pk);
    let other_agent = owner_tag(&owner, &Keys::generate().public_key().to_hex());
    for bad in [wrong_owner, other_agent] {
        let (s, _) = bee
            .post(
                Some(&cred),
                "/v3/beekeeper/attest-agent",
                json!({"agent_pubkey": agent_pk, "owner_auth_tag_json": bad, "community_url": "wss://relay.example"}),
            )
            .await;
        assert_eq!(s, 422, "a bad owner tag is refused");
    }
    let tag = owner_tag(&owner, &agent_pk);
    let (s, v) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/attest-agent",
            json!({"agent_pubkey": agent_pk, "owner_auth_tag_json": tag, "community_url": "wss://relay.example"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "ATTEST_AGENT_STATUS_ACTIVE");
    let hooks = std::fs::read_to_string(bee.dir.join("hooks.log")).unwrap();
    assert!(
        hooks.contains(&format!("add {agent_pk} wss://relay.example")),
        "{hooks}"
    );

    assert_eq!(mode(&ids_file), 0o600);
    let ids: toml::Value = toml::from_str(&std::fs::read_to_string(&ids_file).unwrap()).unwrap();
    let entry = &ids["identity"][0];
    assert_eq!(entry["name"].as_str(), Some(agent_id.as_str()));
    assert_eq!(entry["key_file"].as_str(), key_file.to_str());
    assert_eq!(
        entry["groups"],
        toml::Value::Array(vec![
            format!("agent-{agent_id}").into(),
            format!("agent-{agent_id}.*").into()
        ])
    );
    let auth_file = PathBuf::from(entry["auth_tag_file"].as_str().unwrap());
    assert_eq!(mode(&auth_file), 0o600);
    assert_eq!(
        std::fs::read_to_string(&auth_file).unwrap(),
        tag,
        "the owner tag as received"
    );

    // ---- update ----
    let (s, v) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/update-agent",
            json!({"agent_pubkey": agent_pk, "agent_instructions": "Be brief.", "model_id": "m1", "reasoning_effort": "high"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert!(v.get("error").is_none());
    let (s, _) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/update-agent",
            json!({"agent_pubkey": agent_pk, "model_id": "nope", "reasoning_effort": "high"}),
        )
        .await;
    assert_eq!(s, 422, "a model off the catalog");
    let (s, _) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/update-agent",
            json!({"agent_pubkey": agent_pk, "agent_instructions": "x".repeat(20_001)}),
        )
        .await;
    assert_eq!(s, 422);

    // ---- list ----
    let (s, l) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/list-agents",
            json!({"include_instructions": true}),
        )
        .await;
    assert_eq!(s, 200, "{l}");
    assert_eq!(l["status"], "LIST_AGENTS_STATUS_SUCCESS");
    assert_eq!(
        l["agents"],
        json!([{
            "agent_pubkey": agent_pk,
            "agent_id": agent_id,
            "agent_name": "Scout",
            "agent_picture_url": "https://img.example/a.png",
            "agent_instructions": "Be brief.",
            "model_id": "m1",
            "reasoning_effort": "high",
            "model_selection_status": "MODEL_SELECTION_STATUS_VALID",
            "status": "BEEKEEPER_AGENT_STATUS_ACTIVE",
        }])
    );
    let registry: Value =
        serde_json::from_slice(&std::fs::read(state.join("agents.json")).unwrap()).unwrap();
    assert_eq!(registry["agents"][0]["status"], "active");
    assert!(
        !String::from_utf8(std::fs::read(state.join("agents.json")).unwrap())
            .unwrap()
            .contains(secret.trim()),
        "the registry holds no secrets"
    );

    // ---- key backup ----
    let (s, en) = bee
        .post(Some(&cred), "/v1/buzz/nsec-backups/enrollment", json!({}))
        .await;
    assert_eq!(s, 200, "{en}");
    assert_eq!(en["version"], 1);
    assert_eq!(
        en["suite"],
        json!({"kem_id": 16, "kdf_id": 1, "aead_id": 2})
    );
    assert_eq!(en["nostr_pubkey"], owner_hex);
    {
        use nostr::base64::Engine;
        let point = nostr::base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(en["recipient_public_key"].as_str().unwrap())
            .unwrap();
        assert_eq!((point.len(), point[0]), (65, 4));
    }
    for k in [
        "recipient_key_id",
        "service_namespace",
        "owner_id",
        "backup_id",
    ] {
        let v = en[k].as_str().unwrap();
        assert!(!v.is_empty() && v.len() <= 255, "{k}");
    }
    let mut envelope = json!({});
    for k in [
        "version",
        "suite",
        "recipient_key_id",
        "service_namespace",
        "owner_id",
        "backup_id",
        "nostr_pubkey",
    ] {
        envelope[k] = en[k].clone();
    }
    let mut enc = vec![4u8];
    enc.extend([9u8; 64]);
    envelope["enc"] = json!(b64(&enc));
    envelope["ciphertext"] = json!(b64(&[5u8; 48]));
    for _ in 0..2 {
        let (s, v) = bee
            .post(Some(&cred), "/v1/buzz/nsec-backups", envelope.clone())
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v, json!({"stored": true, "backup_id": en["backup_id"]}));
    }
    let stored = state
        .join("backup/envelopes")
        .join(format!("{}.json", en["backup_id"].as_str().unwrap()));
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(&stored).unwrap()).unwrap(),
        envelope,
        "kept as sent"
    );
    assert_eq!(mode(&stored), 0o600);
    let mut changed = envelope.clone();
    changed["ciphertext"] = json!(b64(&[6u8; 48]));
    let (s, _) = bee
        .post(Some(&cred), "/v1/buzz/nsec-backups", changed)
        .await;
    assert_eq!(s, 409, "another envelope under the same id");
    let (_, st) = bee
        .post(Some(&cred), "/v1/buzz/nsec-backups/status", json!({}))
        .await;
    assert_eq!(
        st,
        json!({"current_nostr_pubkey": owner_hex, "backup_nostr_pubkeys": [owner_hex]})
    );

    // ---- onboarding ----
    let (s, _) = bee
        .post(
            Some(&cred),
            "/v1/buzz/known-communities/add",
            json!({"community_url": "wss://other.example"}),
        )
        .await;
    assert_eq!(s, 200);
    let (_, k) = bee
        .post(Some(&cred), "/v1/buzz/known-communities/list", json!({}))
        .await;
    assert_eq!(
        k["communities"],
        json!([{"community_url": "wss://relay.example"}, {"community_url": "wss://other.example"}])
    );
    let (_, j) = bee
        .post(Some(&cred), "/v1/buzz/communities/joined", json!({}))
        .await;
    assert_eq!(
        j["communities"][0],
        json!({"normalized_host": "relay.example", "name": "relay.example"})
    );
    let (s, _) = bee
        .post(
            Some(&cred),
            "/v1/buzz/identity/assertions",
            json!({"relay_url": "wss://relay.example"}),
        )
        .await;
    assert_eq!(s, 404);

    // ---- delete ----
    let (s, v) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/delete-agent",
            json!({"agent_id": agent_id}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "DELETE_AGENT_STATUS_DELETED");
    let (_, v) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/delete-agent",
            json!({"agent_id": agent_id}),
        )
        .await;
    assert_eq!(v["status"], "DELETE_AGENT_STATUS_NOT_FOUND");
    let (_, l) = bee
        .post(
            Some(&cred),
            "/v3/beekeeper/list-agents",
            json!({"include_instructions": true}),
        )
        .await;
    assert_eq!(l["agents"], json!([]));
    let ids: toml::Value = toml::from_str(&std::fs::read_to_string(&ids_file).unwrap()).unwrap();
    assert_eq!(ids["identity"].as_array().unwrap().len(), 0);
    assert!(
        !key_file.exists() && !auth_file.exists(),
        "the keys are gone"
    );
    let hooks = std::fs::read_to_string(bee.dir.join("hooks.log")).unwrap();
    assert!(hooks.contains(&format!("remove {agent_id}")), "{hooks}");

    // The runtime hand-off ran on each change.
    let mut changes = String::new();
    for _ in 0..50 {
        changes = std::fs::read_to_string(bee.dir.join("changes.log")).unwrap_or_default();
        if changes.lines().count() >= 4 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(changes.lines().count() >= 4, "{changes}");
    assert!(changes.contains("agents.json"), "{changes}");

    let _ = std::fs::remove_dir_all(&bee.dir);
}

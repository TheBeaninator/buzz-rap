//! The HTTP routes the app calls (docs/BEEKEEPER.md sections 3-5), all under `/api/goose`, plus the sign-in
//! page. Status codes follow the client's mapping: 401 = no session, 403 = not allowed, 400/404/409/422 =
//! rejected (the app will not retry it unchanged), 503 = try again later.

use crate::check::{self, BackupKey};
use crate::store::{self, Agent, Files, Persisted, Registry, Session, Status};
use crate::Config;
use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

const CODE_TTL: Duration = Duration::from_secs(600);
const CHALLENGE_TTL_S: u64 = 300;
const CATALOG_TTL: Duration = Duration::from_secs(300);
const HOOK_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_INSTRUCTIONS: usize = 20_000;
/// Pending sign-ins and challenges kept at once; a flood of unfinished ones cannot grow memory without bound.
const MAX_PENDING: usize = 1024;
const MAX_SESSIONS: usize = 4096;

pub struct ApiErr(StatusCode, String);

impl ApiErr {
    fn new(code: StatusCode, msg: impl Into<String>) -> ApiErr {
        ApiErr(code, msg.into())
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": {"message": self.1}}))).into_response()
    }
}

type Res = Result<Value, ApiErr>;

fn bad(msg: impl Into<String>) -> ApiErr {
    ApiErr::new(StatusCode::BAD_REQUEST, msg)
}
fn unprocessable(msg: impl Into<String>) -> ApiErr {
    ApiErr::new(StatusCode::UNPROCESSABLE_ENTITY, msg)
}
fn not_found(msg: impl Into<String>) -> ApiErr {
    ApiErr::new(StatusCode::NOT_FOUND, msg)
}
fn conflict(msg: impl Into<String>) -> ApiErr {
    ApiErr::new(StatusCode::CONFLICT, msg)
}
fn unavailable(msg: impl Into<String>) -> ApiErr {
    ApiErr::new(StatusCode::SERVICE_UNAVAILABLE, msg)
}
fn internal(e: impl std::fmt::Display) -> ApiErr {
    tracing::error!("{e}");
    ApiErr::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

struct LoginCode {
    challenge: String,
    until: Instant,
    /// the approval in Buzz this sign-in waits on, if approval is on
    approval: Option<String>,
}

struct PendingChallenge {
    session: String,
    nonce: String,
    verification_code: String,
    origin: String,
    expires_at: String,
    expires: u64,
}

#[derive(Default)]
struct Inner {
    persisted: Persisted,
    registry: Registry,
    codes: HashMap<String, LoginCode>,
    challenges: HashMap<String, PendingChallenge>,
    /// approvals that ended before their code was exchanged, by approval id
    approvals: HashMap<String, crate::approve::Outcome>,
}

pub struct App {
    pub cfg: Config,
    files: Files,
    backup: BackupKey,
    http: reqwest::Client,
    inner: Mutex<Inner>,
    catalog: Mutex<Option<(Instant, Vec<String>)>>,
}

/// The caller's session: its credential hash and the key it bound, if any.
struct Caller {
    hash: String,
    bound: Option<String>,
}

fn str_field<'a>(body: &'a Value, k: &str) -> Option<&'a str> {
    body.get(k).and_then(Value::as_str)
}

fn want_str<'a>(body: &'a Value, k: &str) -> Result<&'a str, ApiErr> {
    str_field(body, k).ok_or_else(|| bad(format!("{k} is required")))
}

/// Agent names as the app allows them: 1-64 of ASCII letters, digits, `_`, space, `.` and `-`.
fn valid_name(n: &str) -> bool {
    (1..=64).contains(&n.len())
        && n.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b' ' | b'.' | b'-'))
}

fn is_uuid_any_case(s: &str) -> bool {
    store::is_uuid(&s.to_ascii_lowercase())
}

impl App {
    pub fn open(cfg: Config) -> Result<Arc<App>> {
        let dir = cfg.args.state_dir.clone();
        let files = Files::new(&dir);
        files.create(&dir)?;
        let backup = BackupKey::open(&files.recipient_key)?;
        let mut persisted = files.load_state()?;
        persisted.sessions.retain(|_, s| s.expires > store::now());
        // an approval's watcher does not outlive the process: a session still waiting can never be confirmed now,
        // so it goes and the app signs in (and asks) again
        persisted
            .sessions
            .retain(|_, s| s.pending_approval.is_none());
        let registry = files.load_registry()?;
        let app = App {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .context("http client")?,
            inner: Mutex::new(Inner {
                persisted,
                registry,
                ..Inner::default()
            }),
            catalog: Mutex::new(None),
            cfg,
            files,
            backup,
        };
        // The identities file always reflects the registry, even after a crash between the two writes.
        {
            let inner = app.inner.try_lock().expect("unshared");
            app.write_identities(&inner.registry)
                .context("writing the identities file")?;
        }
        Ok(Arc::new(app))
    }

    fn write_identities(&self, r: &Registry) -> Result<()> {
        let text = store::identities_toml(r)?;
        if let Some(dir) = self.cfg.identities.parent() {
            if !dir.as_os_str().is_empty() {
                store::create_private_dir(dir)?;
            }
        }
        store::write_atomic(&self.cfg.identities, text.as_bytes(), 0o600)?;
        Ok(())
    }

    fn save_state(&self, inner: &Inner) -> Result<(), ApiErr> {
        self.files.save_state(&inner.persisted).map_err(internal)
    }

    /// Saves the registry, rewrites the identities file, and tells the runtime.
    fn registry_changed(&self, inner: &Inner) -> Result<(), ApiErr> {
        self.files
            .save_registry(&inner.registry)
            .map_err(internal)?;
        self.write_identities(&inner.registry).map_err(internal)?;
        if let Some(cmd) = self.cfg.args.on_change.clone() {
            let env = vec![
                (
                    "BEEKEEPER_REGISTRY".to_owned(),
                    self.files.registry.display().to_string(),
                ),
                (
                    "BEEKEEPER_IDENTITIES".to_owned(),
                    self.cfg.identities.display().to_string(),
                ),
            ];
            tokio::spawn(async move {
                if let Err(e) = run_hook(&cmd, &env).await {
                    tracing::warn!("--on-change: {e}");
                }
            });
        }
        Ok(())
    }

    async fn caller(&self, headers: &HeaderMap) -> Result<Caller, ApiErr> {
        let unauthorized = || ApiErr::new(StatusCode::UNAUTHORIZED, "sign in");
        let cred = headers
            .get("x-bb-session-credential")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(unauthorized)?;
        let hash = store::hex(&store::sha256(cred.as_bytes()));
        let inner = self.inner.lock().await;
        let s = inner
            .persisted
            .sessions
            .get(&hash)
            .filter(|s| s.expires > store::now())
            .ok_or_else(unauthorized)?;
        // A key removed from the allowlist loses its sessions' rights at once.
        let bound = s.bound.clone().filter(|k| self.cfg.owners.contains(k));
        Ok(Caller { hash, bound })
    }

    /// The bound key, or 403: a session alone may only bind.
    fn owner(c: &Caller) -> Result<&str, ApiErr> {
        c.bound
            .as_deref()
            .ok_or_else(|| ApiErr::new(StatusCode::FORBIDDEN, "bind an allowed Nostr key first"))
    }

    // ---- sign-in ----

    async fn login(self: &Arc<Self>, q: &HashMap<String, String>) -> Response {
        let return_to = q.get("returnTo").map(String::as_str).unwrap_or_default();
        let state = q.get("state").map(String::as_str).unwrap_or_default();
        let challenge = q
            .get("code_challenge")
            .map(String::as_str)
            .unwrap_or_default();
        if !self.cfg.return_to.iter().any(|r| r == return_to) {
            return bad("returnTo is not an allowed callback").into_response();
        }
        if q.get("code_challenge_method").map(String::as_str) != Some("S256")
            || !check::is_code_challenge(challenge)
        {
            return bad("PKCE S256 is required").into_response();
        }
        let state_ok = !state.is_empty()
            && state.len() <= 512
            && state
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~'));
        if !state_ok {
            return bad("bad state").into_response();
        }
        let code = store::token();
        let approval_id = self.cfg.approval.as_ref().map(|_| store::token());
        {
            let mut inner = self.inner.lock().await;
            let now = Instant::now();
            inner.codes.retain(|_, c| c.until > now);
            if inner.codes.len() >= MAX_PENDING {
                return unavailable("too many sign-ins in progress").into_response();
            }
            inner.codes.insert(
                code.clone(),
                LoginCode {
                    challenge: challenge.to_owned(),
                    until: now + CODE_TTL,
                    approval: approval_id.clone(),
                },
            );
        }
        if let (Some(access), Some(id)) = (self.cfg.approval.clone(), approval_id) {
            let short_code = format!(
                "{:04}",
                u16::from_le_bytes(store::random_bytes::<2>()) % 10_000
            );
            let timeout = Duration::from_secs(self.cfg.args.approval_timeout_s.max(30));
            tracing::info!(code = %short_code, "sign-in needs approval in Buzz");
            let (app, owners) = (self.clone(), self.cfg.owners.clone());
            tokio::spawn(async move {
                let outcome = crate::approve::decide(&access, &owners, &short_code, timeout).await;
                tracing::info!(code = %short_code, ?outcome, "sign-in approval finished");
                app.settle(&id, outcome).await;
            });
        }
        let location = format!("{return_to}?code={code}&state={state}");
        (
            StatusCode::FOUND,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, "no-store".to_owned()),
            ],
        )
            .into_response()
    }

    /// An approval ended: bind (or drop) every session that waits on it, or keep the outcome for a code not yet
    /// exchanged.
    async fn settle(&self, id: &str, outcome: crate::approve::Outcome) {
        use crate::approve::Outcome;
        let mut inner = self.inner.lock().await;
        let waiting: Vec<String> = inner
            .persisted
            .sessions
            .iter()
            .filter(|(_, s)| s.pending_approval.as_deref() == Some(id))
            .map(|(k, _)| k.clone())
            .collect();
        if waiting.is_empty() {
            if inner
                .codes
                .values()
                .any(|c| c.approval.as_deref() == Some(id))
            {
                inner.approvals.insert(id.to_owned(), outcome);
            }
            return;
        }
        for k in waiting {
            match &outcome {
                Outcome::Approved(owner) if self.cfg.owners.contains(owner) => {
                    if let Some(s) = inner.persisted.sessions.get_mut(&k) {
                        s.bound = Some(owner.clone());
                        s.pending_approval = None;
                    }
                }
                // refused, or never answered: the session goes, so the app signs in afresh (and asks again)
                // instead of holding an unconfirmed session for its whole lifetime
                _ => {
                    inner.persisted.sessions.remove(&k);
                }
            }
        }
        if self.save_state(&inner).is_err() {
            tracing::error!("saving sessions after an approval failed");
        }
    }

    async fn exchange(&self, body: &Value) -> Res {
        let code = want_str(body, "code")?;
        let verifier = want_str(body, "code_verifier")?;
        let mut inner = self.inner.lock().await;
        // One use: the code is gone whether or not the verifier matches.
        let pending = inner
            .codes
            .remove(code)
            .filter(|c| c.until > Instant::now())
            .ok_or_else(|| bad("unknown or expired code"))?;
        if !check::pkce_s256(verifier, &pending.challenge) {
            return Err(bad("code_verifier does not match"));
        }
        // an approval that already ended before this exchange
        let early = pending
            .approval
            .as_ref()
            .and_then(|id| inner.approvals.remove(id));
        if early == Some(crate::approve::Outcome::Denied) {
            return Err(ApiErr::new(
                StatusCode::FORBIDDEN,
                "this sign-in was refused",
            ));
        }
        let credential = store::token();
        let expires = store::now() + self.cfg.args.session_days.max(1) * 86_400;
        let sessions = &mut inner.persisted.sessions;
        let now = store::now();
        sessions.retain(|_, s| s.expires > now);
        if sessions.len() >= MAX_SESSIONS {
            // Drop the unbound session closest to expiry; bound ones are the owner's.
            if let Some(k) = sessions
                .iter()
                .filter(|(_, s)| s.bound.is_none())
                .min_by_key(|(_, s)| s.expires)
                .map(|(k, _)| k.clone())
            {
                sessions.remove(&k);
            } else {
                return Err(unavailable("too many sessions"));
            }
        }
        sessions.insert(
            store::hex(&store::sha256(credential.as_bytes())),
            Session {
                subject: self.cfg.args.subject.clone(),
                expires,
                bound: early.as_ref().and_then(|o| match o {
                    crate::approve::Outcome::Approved(k) if self.cfg.owners.contains(k) => {
                        Some(k.clone())
                    }
                    _ => None,
                }),
                pending_approval: if early.is_some() {
                    None
                } else {
                    pending.approval.clone()
                },
            },
        );
        self.save_state(&inner)?;
        Ok(json!({"session_credential": credential, "expires_at": store::iso(expires)}))
    }

    async fn me(&self, headers: &HeaderMap) -> Res {
        let c = self.caller(headers).await?;
        let inner = self.inner.lock().await;
        let s = inner
            .persisted
            .sessions
            .get(&c.hash)
            .ok_or_else(|| ApiErr::new(StatusCode::UNAUTHORIZED, "sign in"))?;
        Ok(json!({"subject": s.subject, "expires_at": store::iso(s.expires)}))
    }

    // ---- binding ----

    async fn challenge(&self, c: &Caller, body: &Value) -> Res {
        let origin = want_str(body, "origin")?;
        if let Some(public) = &self.cfg.args.public_origin {
            if origin.trim_end_matches('/') != public {
                return Err(bad("origin is not this service"));
            }
        }
        if origin.is_empty() || origin.len() > 255 {
            return Err(bad("bad origin"));
        }
        let id = store::uuid_v4();
        let nonce = store::token();
        let code = store::hex(&store::random_bytes::<4>()).to_uppercase();
        let expires = store::now() + CHALLENGE_TTL_S;
        let expires_at = store::iso(expires);
        let mut inner = self.inner.lock().await;
        let now = store::now();
        inner.challenges.retain(|_, p| p.expires > now);
        if inner.challenges.len() >= MAX_PENDING {
            return Err(unavailable("too many challenges in progress"));
        }
        inner.challenges.insert(
            id.clone(),
            PendingChallenge {
                session: c.hash.clone(),
                nonce: nonce.clone(),
                verification_code: code.clone(),
                origin: origin.to_owned(),
                expires_at: expires_at.clone(),
                expires,
            },
        );
        Ok(json!({
            "challenge_id": id,
            "nonce": nonce,
            "verification_code": code,
            "origin": origin,
            "expires_at": expires_at,
        }))
    }

    async fn verify(&self, c: &Caller, body: &Value) -> Res {
        let id = want_str(body, "challenge_id")?;
        let nonce = want_str(body, "nonce")?;
        let payload = body
            .get("signed_payload")
            .ok_or_else(|| bad("signed_payload is required"))?;
        let mut inner = self.inner.lock().await;
        // One attempt per challenge.
        let p = inner
            .challenges
            .remove(id)
            .filter(|p| p.session == c.hash && p.expires > store::now())
            .ok_or_else(|| bad("unknown or expired challenge"))?;
        if p.nonce != nonce {
            return Err(bad("nonce does not match"));
        }
        let signer = check::binding_event(
            payload,
            &check::Challenge {
                challenge_id: id,
                nonce: &p.nonce,
                verification_code: &p.verification_code,
                origin: &p.origin,
                expires_at: &p.expires_at,
            },
        )
        .map_err(bad)?;
        if !self.cfg.owners.contains(&signer) {
            tracing::warn!(pubkey = %signer, "binding refused: key not on the owner allowlist");
            return Err(ApiErr::new(
                StatusCode::FORBIDDEN,
                "this key may not use this service",
            ));
        }
        let s = inner
            .persisted
            .sessions
            .get_mut(&c.hash)
            .ok_or_else(|| ApiErr::new(StatusCode::UNAUTHORIZED, "sign in"))?;
        match &s.bound {
            Some(k) if *k != signer => {
                return Err(conflict("this session is bound to another key"))
            }
            _ => s.bound = Some(signer.clone()),
        }
        self.save_state(&inner)?;
        tracing::info!(pubkey = %signer, "session bound");
        Ok(json!({"identity": {"pubkey_hex": signer}}))
    }

    fn current(c: &Caller) -> Value {
        match &c.bound {
            Some(k) => json!({"identity": {"pubkey_hex": k}}),
            None => json!({}),
        }
    }

    // ---- key backup ----

    fn backed_up_keys(&self, bound: &str) -> Vec<String> {
        let any = std::fs::read_dir(&self.files.envelopes)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| std::fs::read(e.path()).ok())
            .filter_map(|b| serde_json::from_slice::<Value>(&b).ok())
            .any(|v| str_field(&v, "nostr_pubkey") == Some(bound));
        if any {
            vec![bound.to_owned()]
        } else {
            vec![]
        }
    }

    fn backup_status(&self, c: &Caller) -> Value {
        match &c.bound {
            Some(k) => {
                json!({"current_nostr_pubkey": k, "backup_nostr_pubkeys": self.backed_up_keys(k)})
            }
            None => json!({"current_nostr_pubkey": null, "backup_nostr_pubkeys": []}),
        }
    }

    fn enrollment(&self, owner: &str) -> Value {
        json!({
            "version": 1,
            "suite": {"kem_id": check::KEM_ID, "kdf_id": check::KDF_ID, "aead_id": check::AEAD_ID},
            "recipient_public_key": self.backup.public_b64,
            "recipient_key_id": self.backup.key_id,
            "service_namespace": self.cfg.args.backup_namespace,
            "owner_id": owner,
            "backup_id": store::uuid_v4(),
            "nostr_pubkey": owner,
        })
    }

    async fn store_backup(&self, owner: &str, body: &Value) -> Res {
        let backup_id = check::envelope(
            body,
            &check::Enrollment {
                key_id: &self.backup.key_id,
                namespace: &self.cfg.args.backup_namespace,
                owner_id: owner,
                nostr_pubkey: owner,
            },
        )
        .map_err(bad)?;
        let path = self.files.envelopes.join(format!("{backup_id}.json"));
        let _inner = self.inner.lock().await; // one writer at a time
        if let Ok(old) = std::fs::read(&path) {
            // The app replays the exact same envelope after an uncertain upload.
            if serde_json::from_slice::<Value>(&old).ok().as_ref() != Some(body) {
                return Err(conflict("a different backup has this backup_id"));
            }
        } else {
            let bytes = serde_json::to_vec(body).map_err(internal)?;
            store::write_atomic(&path, &bytes, 0o600).map_err(internal)?;
            tracing::info!(%backup_id, "key backup stored");
        }
        Ok(json!({"stored": true, "backup_id": backup_id}))
    }

    // ---- onboarding ----

    async fn known_add(&self, owner: &str, body: &Value) -> Res {
        let url = want_str(body, "community_url")?;
        if !url.starts_with("wss://") || url.len() > 512 {
            return Err(bad("community_url must be a wss:// URL"));
        }
        let mut inner = self.inner.lock().await;
        let list = inner
            .persisted
            .known_communities
            .entry(owner.to_owned())
            .or_default();
        if !list.iter().any(|u| u == url) {
            if list.len() >= 256 {
                return Err(unprocessable("too many communities"));
            }
            list.push(url.to_owned());
            self.save_state(&inner)?;
        }
        Ok(json!({}))
    }

    async fn communities(&self, c: &Caller) -> Vec<String> {
        let mut out = self.cfg.args.communities.clone();
        if let Some(k) = &c.bound {
            let inner = self.inner.lock().await;
            for u in inner
                .persisted
                .known_communities
                .get(k)
                .into_iter()
                .flatten()
            {
                if !out.contains(u) {
                    out.push(u.clone());
                }
            }
        }
        out
    }

    async fn known_list(&self, c: &Caller) -> Value {
        let rows: Vec<Value> = self
            .communities(c)
            .await
            .into_iter()
            .map(|u| json!({"community_url": u}))
            .collect();
        json!({"communities": rows})
    }

    async fn joined(&self, c: &Caller) -> Value {
        let rows: Vec<Value> = self
            .communities(c)
            .await
            .into_iter()
            .filter_map(|u| {
                let host = u.strip_prefix("wss://")?.trim_end_matches('/').to_owned();
                (!host.is_empty() && !host.contains(['/', '?', '#', '@']))
                    .then(|| json!({"normalized_host": host, "name": host}))
            })
            .collect();
        json!({"communities": rows})
    }

    // ---- model catalog ----

    fn models_url(&self) -> Option<String> {
        let base = self.cfg.args.models_url.as_deref()?.trim_end_matches('/');
        Some(if base.ends_with("/v1/models") {
            base.to_owned()
        } else if base.ends_with("/v1") {
            format!("{base}/models")
        } else {
            format!("{base}/v1/models")
        })
    }

    /// Model ids from the backend; cached briefly unless `fresh`.
    async fn model_ids(&self, fresh: bool) -> Result<Vec<String>, ApiErr> {
        let mut cache = self.catalog.lock().await;
        if let Some((at, ids)) = cache.as_ref() {
            if !fresh && at.elapsed() < CATALOG_TTL {
                return Ok(ids.clone());
            }
        }
        let Some(url) = self.models_url() else {
            return Ok(vec![]);
        };
        let mut req = self.http.get(&url);
        if let Some(k) = &self.cfg.args.models_api_key {
            req = req.bearer_auth(k);
        }
        let fetched: Result<Value, String> = async {
            let r = req.send().await.map_err(|e| e.to_string())?;
            if !r.status().is_success() {
                return Err(format!("HTTP {}", r.status()));
            }
            r.json::<Value>().await.map_err(|e| e.to_string())
        }
        .await;
        let v = fetched.map_err(|e| {
            tracing::warn!("models backend {url}: {e}");
            unavailable("the model backend is unavailable")
        })?;
        let mut ids: Vec<String> = Vec::new();
        for m in v
            .get("data")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(id) = m.get("id").and_then(Value::as_str) {
                if !id.trim().is_empty() && !ids.iter().any(|x| x == id) {
                    ids.push(id.to_owned());
                }
            }
        }
        *cache = Some((Instant::now(), ids.clone()));
        Ok(ids)
    }

    fn efforts(&self) -> Vec<String> {
        self.cfg
            .args
            .efforts
            .iter()
            .map(|e| e.trim().to_owned())
            .collect()
    }

    async fn catalog(&self) -> Res {
        let ids = self.model_ids(true).await?;
        let efforts = self.efforts();
        let models: Vec<Value> = ids
            .iter()
            .map(|id| json!({"id": id, "display_name": id, "supported_reasoning_efforts": efforts}))
            .collect();
        let mut out = json!({"models": models});
        let model = self
            .cfg
            .args
            .recommended_model
            .as_ref()
            .filter(|m| ids.contains(m))
            .or(ids.first());
        if let Some(m) = model {
            let effort = if efforts.contains(&self.cfg.args.recommended_effort) {
                self.cfg.args.recommended_effort.clone()
            } else {
                efforts[0].clone()
            };
            out["recommended_selection"] = json!({"model_id": m, "reasoning_effort": effort});
        }
        Ok(out)
    }

    // ---- the registry ----

    async fn register(&self, owner: &str, body: &Value) -> Res {
        let name = want_str(body, "agent_name")?.trim();
        if !valid_name(name) {
            return Err(unprocessable(
                "agent_name: 1-64 letters, digits, spaces, dots, hyphens or underscores",
            ));
        }
        let picture = match body.get("agent_picture_url") {
            None | Some(Value::Null) => None,
            Some(Value::String(p))
                if p.starts_with("https://")
                    && p.len() <= 2048
                    && !p.chars().any(char::is_whitespace) =>
            {
                Some(p.clone())
            }
            Some(_) => return Err(unprocessable("agent_picture_url must be an https URL")),
        };
        let key = want_str(body, "idempotency_key")?;
        if !is_uuid_any_case(key) {
            return Err(bad("idempotency_key must be a UUID"));
        }
        let key = key.to_ascii_lowercase();
        let reply = |a: &Agent| json!({"status": "REGISTER_AGENT_STATUS_UNATTESTED", "agent_pubkey": a.pubkey, "agent_id": a.id});
        let mut inner = self.inner.lock().await;
        if let Some(a) = inner
            .registry
            .agents
            .iter()
            .find(|a| a.idempotency_key == key)
        {
            if a.owner != owner || a.status == Status::Deleted {
                return Err(conflict("idempotency_key was used for another agent"));
            }
            return Ok(reply(a));
        }
        let live = inner
            .registry
            .agents
            .iter()
            .filter(|a| a.owner == owner && a.status != Status::Deleted)
            .count();
        if live >= self.cfg.args.max_agents {
            return Err(unprocessable("too many agents"));
        }
        let keys = nostr::Keys::generate();
        let id = store::hex(&store::random_bytes::<8>());
        let key_file = self.files.keys.join(format!("{id}.key"));
        store::write_atomic(
            &key_file,
            format!("{}\n", keys.secret_key().to_secret_hex()).as_bytes(),
            0o600,
        )
        .map_err(internal)?;
        let now = store::now();
        let agent = Agent {
            id: id.clone(),
            pubkey: keys.public_key().to_hex(),
            name: name.to_owned(),
            picture,
            instructions: String::new(),
            model: String::new(),
            effort: String::new(),
            status: Status::Unattested,
            owner: owner.to_owned(),
            owner_tag: None,
            community_url: None,
            idempotency_key: key,
            auth_tag_file: self.files.keys.join(format!("{id}.auth")),
            key_file,
            created_at: now,
            updated_at: now,
        };
        let out = reply(&agent);
        tracing::info!(agent = %id, pubkey = %agent.pubkey, "agent registered");
        inner.registry.agents.push(agent);
        self.registry_changed(&inner)?;
        Ok(out)
    }

    fn find_mut<'a>(
        inner: &'a mut Inner,
        owner: &str,
        pubkey: &str,
    ) -> Result<&'a mut Agent, ApiErr> {
        inner
            .registry
            .agents
            .iter_mut()
            .find(|a| a.pubkey == pubkey && a.owner == owner && a.status != Status::Deleted)
            .ok_or_else(|| not_found("no such agent"))
    }

    async fn attest(&self, owner: &str, body: &Value) -> Res {
        let pubkey = want_str(body, "agent_pubkey")?;
        let tag = want_str(body, "owner_auth_tag_json")?;
        let community = want_str(body, "community_url")?;
        if !community.starts_with("wss://") || community.len() > 512 {
            return Err(bad("community_url must be a wss:// URL"));
        }
        let mut inner = self.inner.lock().await;
        let agent = Self::find_mut(&mut inner, owner, pubkey)?;
        // Kept exactly as received: buzz-rap reads the owner from it and the agent publishes it.
        let tag = tag.trim().to_owned();
        check::owner_tag(&tag, owner, pubkey).map_err(unprocessable)?;
        let (id, auth_file) = (agent.id.clone(), agent.auth_tag_file.clone());
        if !self.cfg.args.member_add_cmd.trim().is_empty() {
            member_hook(&self.cfg.args.member_add_cmd, &id, pubkey, community)
                .await
                .map_err(|e| {
                    tracing::warn!(agent = %id, "--member-add-cmd: {e}");
                    unavailable("could not add the agent to the relay")
                })?;
        }
        store::write_atomic(&auth_file, tag.as_bytes(), 0o600).map_err(internal)?;
        let agent = Self::find_mut(&mut inner, owner, pubkey)?;
        agent.owner_tag = Some(tag);
        agent.community_url = Some(community.to_owned());
        agent.status = Status::Active;
        agent.updated_at = store::now();
        tracing::info!(agent = %id, "agent active");
        self.registry_changed(&inner)?;
        Ok(json!({"status": "ATTEST_AGENT_STATUS_ACTIVE"}))
    }

    async fn update(&self, owner: &str, body: &Value) -> Res {
        let pubkey = want_str(body, "agent_pubkey")?;
        let instructions = match body.get("agent_instructions") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.chars().count() <= MAX_INSTRUCTIONS => Some(s.clone()),
            Some(_) => {
                return Err(unprocessable(
                    "agent_instructions: at most 20,000 characters",
                ))
            }
        };
        let model = str_field(body, "model_id").filter(|s| !s.is_empty());
        let effort = str_field(body, "reasoning_effort").filter(|s| !s.is_empty());
        let (cur_model, cur_effort) = {
            let mut inner = self.inner.lock().await;
            let a = Self::find_mut(&mut inner, owner, pubkey)?;
            (a.model.clone(), a.effort.clone())
        };
        if model.is_some() || effort.is_some() {
            let m = model.map(str::to_owned).unwrap_or(cur_model);
            let e = effort.map(str::to_owned).unwrap_or(cur_effort);
            let ids = self.model_ids(false).await?;
            let ids = if ids.contains(&m) {
                ids
            } else {
                self.model_ids(true).await?
            };
            if !ids.contains(&m) || !self.efforts().contains(&e) {
                return Err(unprocessable(
                    "model_id and reasoning_effort must be in the catalog",
                ));
            }
        }
        let mut inner = self.inner.lock().await;
        let a = Self::find_mut(&mut inner, owner, pubkey)?;
        if let Some(i) = instructions {
            a.instructions = i;
        }
        if let Some(m) = model {
            a.model = m.to_owned();
        }
        if let Some(e) = effort {
            a.effort = e.to_owned();
        }
        a.updated_at = store::now();
        self.registry_changed(&inner)?;
        Ok(json!({}))
    }

    async fn list(&self, owner: &str, body: &Value) -> Res {
        let with_instructions = body
            .get("include_instructions")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // Selections were checked against the catalog when saved; an unreachable backend does not void them.
        let catalog = self.model_ids(false).await.ok();
        let efforts = self.efforts();
        let inner = self.inner.lock().await;
        let rows: Vec<Value> = inner
            .registry
            .agents
            .iter()
            .filter(|a| a.owner == owner && a.status != Status::Deleted)
            .map(|a| {
                let selection = if a.model.is_empty() || a.effort.is_empty() {
                    "MODEL_SELECTION_STATUS_UNSPECIFIED"
                } else if catalog.as_ref().is_none_or(|ids| ids.contains(&a.model))
                    && efforts.contains(&a.effort)
                {
                    "MODEL_SELECTION_STATUS_VALID"
                } else {
                    "MODEL_SELECTION_STATUS_INVALID"
                };
                let mut row = Map::new();
                row.insert("agent_pubkey".into(), json!(a.pubkey));
                row.insert("agent_id".into(), json!(a.id));
                row.insert("agent_name".into(), json!(a.name));
                if let Some(p) = &a.picture {
                    row.insert("agent_picture_url".into(), json!(p));
                }
                if with_instructions {
                    row.insert("agent_instructions".into(), json!(a.instructions));
                }
                row.insert("model_id".into(), json!(a.model));
                row.insert("reasoning_effort".into(), json!(a.effort));
                row.insert("model_selection_status".into(), json!(selection));
                row.insert(
                    "status".into(),
                    json!(match a.status {
                        Status::Active => "BEEKEEPER_AGENT_STATUS_ACTIVE",
                        _ => "BEEKEEPER_AGENT_STATUS_UNATTESTED",
                    }),
                );
                Value::Object(row)
            })
            .collect();
        Ok(json!({"status": "LIST_AGENTS_STATUS_SUCCESS", "agents": rows}))
    }

    async fn delete(&self, owner: &str, body: &Value) -> Res {
        let id = want_str(body, "agent_id")?;
        let mut inner = self.inner.lock().await;
        let Some(a) = inner
            .registry
            .agents
            .iter()
            .find(|a| a.id == id && a.owner == owner && a.status != Status::Deleted)
            .cloned()
        else {
            return Ok(json!({"status": "DELETE_AGENT_STATUS_NOT_FOUND"}));
        };
        if a.status == Status::Active && !self.cfg.args.member_remove_cmd.trim().is_empty() {
            member_hook(
                &self.cfg.args.member_remove_cmd,
                &a.id,
                &a.pubkey,
                a.community_url.as_deref().unwrap_or_default(),
            )
            .await
            .map_err(|e| {
                tracing::warn!(agent = %a.id, "--member-remove-cmd: {e}");
                unavailable("could not remove the agent from the relay")
            })?;
        }
        if let Some(r) = inner.registry.agents.iter_mut().find(|r| r.id == a.id) {
            r.status = Status::Deleted;
            r.owner_tag = None;
            r.instructions.clear();
            r.updated_at = store::now();
        }
        // The identities file drops the agent before its key goes.
        self.registry_changed(&inner)?;
        let _ = std::fs::remove_file(&a.key_file);
        let _ = std::fs::remove_file(&a.auth_tag_file);
        tracing::info!(agent = %a.id, "agent deleted");
        Ok(json!({"status": "DELETE_AGENT_STATUS_DELETED"}))
    }
}

/// Runs a membership command for one agent. Only validated hex values are substituted into the command line;
/// the community URL, which comes from the app, is passed in the environment only.
async fn member_hook(
    template: &str,
    id: &str,
    pubkey: &str,
    community: &str,
) -> Result<(), String> {
    if !store::is_hex64(pubkey) || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad agent id or key".into());
    }
    let cmd = template
        .replace("{pubkey}", pubkey)
        .replace("{agent_id}", id);
    run_hook(
        &cmd,
        &[
            ("BEEKEEPER_AGENT_PUBKEY".into(), pubkey.into()),
            ("BEEKEEPER_AGENT_ID".into(), id.into()),
            ("BEEKEEPER_COMMUNITY_URL".into(), community.into()),
        ],
    )
    .await
}

async fn run_hook(cmd: &str, env: &[(String, String)]) -> Result<(), String> {
    let mut c = tokio::process::Command::new("sh");
    c.arg("-c")
        .arg(cmd)
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = tokio::time::timeout(HOOK_TIMEOUT, c.output())
        .await
        .map_err(|_| "timed out".to_owned())?
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "{}: {}",
            out.status,
            err.trim().chars().take(400).collect::<String>()
        ))
    }
}

fn parse_body(body: &Bytes) -> Result<Value, ApiErr> {
    let v: Value = serde_json::from_slice(body).map_err(|_| bad("body must be JSON"))?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(bad("body must be a JSON object"))
    }
}

async fn dispatch(
    State(app): State<Arc<App>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/{path}");
    let result: Res = async {
        let body = parse_body(&body)?;
        if path == "/v1/auth/login/exchange" {
            return app.exchange(&body).await;
        }
        let c = app.caller(&headers).await?;
        match path.as_str() {
            // A session alone may do only these: read its binding, and bind.
            "/v1/buzz/nostr-identities/current" => Ok(App::current(&c)),
            "/v1/buzz/nsec-backups/status" => Ok(app.backup_status(&c)),
            "/v1/buzz/nostr-identities/challenge" => app.challenge(&c, &body).await,
            "/v1/buzz/nostr-identities/verify" => app.verify(&c, &body).await,
            // Lists are empty until a key is bound.
            "/v1/buzz/known-communities/list" => Ok(app.known_list(&c).await),
            "/v1/buzz/communities/joined" => Ok(app.joined(&c).await),
            // Everything else needs a bound, allowed key.
            p => {
                let owner = App::owner(&c)?;
                match p {
                    "/v1/buzz/known-communities/add" => app.known_add(owner, &body).await,
                    "/v1/buzz/nsec-backups/enrollment" => Ok(app.enrollment(owner)),
                    "/v1/buzz/nsec-backups" => app.store_backup(owner, &body).await,
                    "/v3/beekeeper/get-model-catalog" => app.catalog().await,
                    "/v3/beekeeper/register-agent" => app.register(owner, &body).await,
                    "/v3/beekeeper/attest-agent" => app.attest(owner, &body).await,
                    "/v3/beekeeper/update-agent" => app.update(owner, &body).await,
                    "/v3/beekeeper/list-agents" => app.list(owner, &body).await,
                    "/v3/beekeeper/delete-agent" => app.delete(owner, &body).await,
                    // Recovery would mean opening backups here; NIP-FI assertions are not needed by a relay
                    // that does not require them.
                    _ => Err(not_found("no such route")),
                }
            }
        }
    }
    .await;
    match result {
        Ok(v) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(v),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

async fn login(State(app): State<Arc<App>>, Query(q): Query<HashMap<String, String>>) -> Response {
    app.login(&q).await
}

async fn me(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    match app.me(&headers).await {
        Ok(v) => (
            StatusCode::OK,
            [(header::CACHE_CONTROL, "no-store")],
            Json(v),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/auth/native", get(login))
        .route("/api/goose/v1/auth/login", get(login))
        .route("/api/goose/v1/auth/me", get(me))
        .route("/api/goose/{*path}", post(dispatch))
        .fallback(|| async { not_found("no such route").into_response() })
        .with_state(app)
}

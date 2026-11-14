//! HTTP side: the manifest, invocations, callbacks, and the state that makes delivery at-least-once safe.

use crate::audit;
use crate::subscribe::{self, Sub};
use crate::toolset::{self, ToolSpec};
use crate::Args;
use anyhow::Result;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Largest tool output passed back; the rest is cut with a note, so one huge listing cannot flood a context.
const MAX_TEXT: usize = 64 * 1024;
/// Answered call ids remembered for deduplication.
const MAX_ANSWERED: usize = 4096;

/// One RAP invocation (rap_protocol::RapInvocation).
#[derive(Debug, Deserialize)]
pub struct Invocation {
    pub operation: String,
    #[serde(default)]
    pub arguments: Value,
    /// the agent's tool call id; results and events name it
    pub id: String,
    /// the model provider's call id, when it has one
    #[serde(default)]
    pub call_id: Option<String>,
    pub callback_url: String,
    /// the agent's conversation (a thread); echoed in every callback
    pub group_id: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Persisted {
    pub subs: Vec<Sub>,
    /// (dedupe key, result body); the body is re-posted when a duplicate invocation arrives
    pub answered: VecDeque<(String, Value)>,
}

pub struct App {
    pub args: Args,
    pub tools: HashMap<String, ToolSpec>,
    pub manifest: Value,
    pub http: reqwest::Client,
    pub me: Option<String>,
    pub state: Mutex<Persisted>,
    /// dedupe keys whose tool is still running
    pub running: Mutex<std::collections::HashSet<String>>,
    /// one audit writer at a time, so lines never interleave
    pub audit_lock: Mutex<()>,
}

impl App {
    pub async fn save(&self) {
        let Some(path) = &self.args.state else { return };
        let body = {
            let s = self.state.lock().await;
            serde_json::to_vec(&*s)
        };
        let Ok(body) = body else { return };
        let tmp = path.with_extension("tmp");
        if let Err(e) = tokio::fs::write(&tmp, &body)
            .await
            .and(tokio::fs::rename(&tmp, path).await)
        {
            tracing::warn!("state {}: {e}", path.display());
        }
    }
}

pub async fn serve(args: Args, tools: Vec<ToolSpec>, me: Option<String>) -> Result<()> {
    let base = args
        .public_url
        .clone()
        .unwrap_or_else(|| format!("http://{}", args.listen));
    let base = base.trim_end_matches('/').to_owned();
    let mut defs: Vec<Value> = tools
        .iter()
        .map(|t| json!({"name": t.name, "description": t.description, "inputSchema": t.schema}))
        .collect();
    defs.extend(subscribe::defs());
    let manifest = json!({
        "name": "buzz",
        "description": "Act in a Buzz workspace: read, search and post in channels, react, edit canvases, and subscribe to a channel so new messages wake the agent.",
        "endpoint": format!("{base}/invoke"),
        "tools": defs,
    });
    let persisted = match &args.state {
        Some(p) => match std::fs::read(p) {
            Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|e| {
                tracing::warn!("state {}: unreadable ({e}); starting empty", p.display());
                Persisted::default()
            }),
            Err(_) => Persisted::default(),
        },
        None => Persisted::default(),
    };
    let app = Arc::new(App {
        tools: tools.into_iter().map(|t| (t.name.clone(), t)).collect(),
        manifest,
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
        me,
        state: Mutex::new(persisted),
        running: Mutex::new(Default::default()),
        audit_lock: Mutex::new(()),
        args: args.clone(),
    });
    tokio::spawn(subscribe::run(app.clone()));
    let router = Router::new()
        .route("/.well-known/rap-toolset", get(manifest_route))
        .route("/invoke", post(invoke_route))
        .route("/health", get(health_route))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn manifest_route(State(app): State<Arc<App>>) -> Json<Value> {
    Json(app.manifest.clone())
}

async fn health_route(State(app): State<Arc<App>>) -> Json<Value> {
    let s = app.state.lock().await;
    Json(json!({"ok": true, "tools": app.tools.len() + 2, "subscriptions": s.subs.len()}))
}

fn authorized(app: &App, headers: &HeaderMap) -> bool {
    let Some(want) = &app.args.token else {
        return true;
    };
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .is_some_and(|got| got == want)
}

/// The key a repeated delivery of the same call shares: the provider's call id when given, else the agent's.
fn dedupe_key(inv: &Invocation) -> String {
    format!(
        "{}/{}",
        inv.group_id,
        inv.call_id.as_deref().unwrap_or(&inv.id)
    )
}

async fn invoke_route(
    State(app): State<Arc<App>>,
    headers: HeaderMap,
    Json(inv): Json<Invocation>,
) -> (StatusCode, Json<Value>) {
    let who = json!({"group_id": inv.group_id, "id": inv.id, "call_id": inv.call_id, "operation": inv.operation, "callback": audit::origin(&inv.callback_url)});
    if !authorized(&app, &headers) {
        let mut e = who.clone();
        e["reason"] = json!("bad or missing bearer token");
        audit::record(&app, "refused", e).await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "bad or missing bearer token"})),
        );
    }
    let key = dedupe_key(&inv);
    let earlier = app
        .state
        .lock()
        .await
        .answered
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, b)| b.clone());
    if let Some(body) = earlier {
        // at-least-once delivery: the action ran once already; hand the agent the same result again
        let mut e = who.clone();
        e["replayed"] = json!(true);
        audit::record(&app, "duplicate", e).await;
        tokio::spawn(post_callback(app.clone(), inv.callback_url.clone(), body));
        return (StatusCode::OK, Json(json!({"status": "duplicate"})));
    }
    if !app.running.lock().await.insert(key.clone()) {
        let mut e = who.clone();
        e["replayed"] = json!(false);
        audit::record(&app, "duplicate", e).await;
        return (StatusCode::OK, Json(json!({"status": "duplicate"})));
    }
    let known = inv.operation == subscribe::SUBSCRIBE
        || inv.operation == subscribe::UNSUBSCRIBE
        || app.tools.contains_key(&inv.operation);
    if !known {
        app.running.lock().await.remove(&key);
        let mut e = who.clone();
        e["reason"] = json!("no such tool");
        audit::record(&app, "refused", e).await;
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("no tool {:?}", inv.operation)})),
        );
    }
    tokio::spawn(async move {
        let started = std::time::Instant::now();
        let argv = app
            .tools
            .get(&inv.operation)
            .and_then(|t| toolset::argv(t, &inv.arguments).ok());
        let (ok, text) = match inv.operation.as_str() {
            subscribe::SUBSCRIBE => subscribe::start(&app, &inv).await,
            subscribe::UNSUBSCRIBE => subscribe::stop(&app, &inv).await,
            op => run_tool(&app, &app.tools[op], &inv.arguments).await,
        };
        let body = result_body(&inv, ok, &text);
        {
            let mut s = app.state.lock().await;
            s.answered.push_back((key.clone(), body.clone()));
            while s.answered.len() > MAX_ANSWERED {
                s.answered.pop_front();
            }
        }
        app.running.lock().await.remove(&key);
        app.save().await;
        let mut e = who.clone();
        e["arguments"] = inv.arguments.clone();
        e["argv"] = json!(argv);
        e["ok"] = json!(ok);
        e["duration_ms"] = json!(started.elapsed().as_millis() as u64);
        e["result_bytes"] = json!(text.len());
        e["result_head"] = json!(audit::head(&text));
        e["event_ids"] = json!(audit::event_ids(&text));
        audit::record(&app, "call", e).await;
        let delivered = post_callback(app.clone(), inv.callback_url.clone(), body).await;
        let mut e = who;
        e["delivered"] = json!(delivered);
        audit::record(&app, "callback", e).await;
    });
    (StatusCode::ACCEPTED, Json(json!({"status": "accepted"})))
}

pub fn result_body(inv: &Invocation, ok: bool, text: &str) -> Value {
    let text = if ok {
        text.to_owned()
    } else {
        format!("Error: {text}")
    };
    json!({"type": "tool_result", "group_id": inv.group_id, "id": inv.id, "call_id": inv.call_id, "text": text, "is_error": !ok})
}

async fn run_tool(app: &App, tool: &ToolSpec, arguments: &Value) -> (bool, String) {
    match toolset::argv(tool, arguments) {
        Ok(argv) => run_buzz(app, argv).await,
        Err(e) => (false, format!("{e:#}")),
    }
}

/// Run `buzz` with these arguments; JSON output, no stdin, killed at the timeout.
pub async fn run_buzz(app: &App, argv: Vec<String>) -> (bool, String) {
    let mut cmd = tokio::process::Command::new(&app.args.buzz_bin);
    cmd.args(&argv)
        .env("BUZZ_OUTPUT_FORMAT", "json")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true);
    let timeout = Duration::from_secs(app.args.tool_timeout_s.max(1));
    match tokio::time::timeout(timeout, cmd.output()).await {
        Err(_) => (
            false,
            format!(
                "buzz {} ran past {}s and was stopped",
                argv.first().map(String::as_str).unwrap_or(""),
                timeout.as_secs()
            ),
        ),
        Ok(Err(e)) => (false, format!("could not run {}: {e}", app.args.buzz_bin)),
        Ok(Ok(out)) => {
            let ok = out.status.success();
            let mut text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            if !ok && !err.is_empty() {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(&err);
            }
            if text.is_empty() {
                text = if ok {
                    "done".into()
                } else {
                    format!("buzz exited with {}", out.status)
                };
            }
            (ok, cap(text))
        }
    }
}

pub fn cap(mut text: String) -> String {
    if text.len() > MAX_TEXT {
        let mut cut = MAX_TEXT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        let total = text.len();
        text.truncate(cut);
        text.push_str(&format!(
            "\n[cut at {MAX_TEXT} of {total} bytes; narrow the request]"
        ));
    }
    text
}

/// Post one callback, retrying on network errors, 5xx and 429; a 4xx is the receiver's final word.
pub async fn post_callback(app: Arc<App>, url: String, body: Value) -> bool {
    for wait in [0u64, 1, 2, 5, 10, 30, 60, 120] {
        if wait > 0 {
            tokio::time::sleep(Duration::from_secs(wait)).await;
        }
        match app.http.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => return true,
            Ok(r)
                if r.status().is_client_error() && r.status() != StatusCode::TOO_MANY_REQUESTS =>
            {
                tracing::warn!("callback {url}: {} refused it; giving up", r.status());
                return false;
            }
            Ok(r) => tracing::warn!("callback {url}: {}; retrying", r.status()),
            Err(e) => tracing::warn!("callback {url}: {e}; retrying"),
        }
    }
    tracing::warn!("callback {url}: no answer after 8 tries; dropped");
    false
}

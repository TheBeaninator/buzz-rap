//! buzz-rap: the `buzz` CLI as a RAP (Reactive Agent Protocol) tool server.
//!
//! RAP (https://infinity.hydro.run/docs/rap/spec/overview): a tool server publishes a manifest at
//! `/.well-known/rap-toolset`; an agent runtime posts an invocation to the manifest's endpoint, the server
//! acknowledges at once and posts the result to the invocation's `callback_url` when it is done. A
//! subscription tool keeps posting `subscription_event`s for the same call until it ends.
//!
//! Tools are generated from the CLI's command tree (see `toolset`) and run as `buzz` subprocesses. Who acts
//! is decided per conversation (`identity`): an identities file maps RAP `group_id`s to keys, with
//! `BUZZ_PRIVATE_KEY` as the default, and the agent never sees or sets a key. `buzz_subscribe` turns new
//! channel messages into events, pushed over one relay WebSocket per identity (`watch`) or polled, which is
//! what lets a RAP agent sleep in a channel and wake when someone talks to it.

mod audit;
mod identity;
mod server;
mod subscribe;
mod toolset;
mod watch;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "buzz-rap", about = "Serve the buzz CLI as a RAP tool server")]
pub struct Args {
    /// Address to listen on
    #[arg(long, env = "BUZZ_RAP_LISTEN", default_value = "127.0.0.1:7171")]
    pub listen: SocketAddr,
    /// Base URL agents reach this server at, used for the manifest's endpoint [default: http://<listen>]
    #[arg(long, env = "BUZZ_RAP_PUBLIC_URL")]
    pub public_url: Option<String>,
    /// The buzz binary tools run as
    #[arg(long, env = "BUZZ_RAP_BUZZ_BIN", default_value = "buzz")]
    pub buzz_bin: String,
    /// Command paths to expose, comma-separated ("messages send,canvas get") [default: read, search and post]
    #[arg(long, env = "BUZZ_RAP_ALLOW", value_delimiter = ',')]
    pub allow: Vec<String>,
    /// Bearer token an invocation must carry; required when listening beyond loopback
    #[arg(long, env = "BUZZ_RAP_TOKEN")]
    pub token: Option<String>,
    /// File that keeps subscriptions and answered call ids across restarts
    #[arg(long, env = "BUZZ_RAP_STATE")]
    pub state: Option<PathBuf>,
    /// How often subscriptions look for new messages, in milliseconds
    #[arg(long, env = "BUZZ_RAP_POLL_MS", default_value_t = 2000)]
    pub poll_ms: u64,
    /// TOML file mapping RAP conversations (group_id patterns) to agent keys, so one server acts as many
    /// identities; BUZZ_PRIVATE_KEY stays the default for conversations no entry names
    #[arg(long, env = "BUZZ_RAP_IDENTITIES")]
    pub identities: Option<PathBuf>,
    /// How subscriptions get new messages: push (relay WebSocket), poll (`buzz messages get`), or auto (push
    /// when BUZZ_RELAY_URL is set)
    #[arg(long, env = "BUZZ_RAP_DELIVERY", default_value = "auto", value_parser = ["auto", "push", "poll"])]
    pub delivery: String,
    /// Append-only JSONL audit log: one line per call, refusal, duplicate and subscription delivery, keyed by the
    /// calling conversation and call id, with the Buzz event ids each call produced
    #[arg(long, env = "BUZZ_RAP_AUDIT_LOG")]
    pub audit_log: Option<PathBuf>,
    /// Seconds a tool may run before it is stopped and reported as an error
    #[arg(long, env = "BUZZ_RAP_TOOL_TIMEOUT_S", default_value_t = 120)]
    pub tool_timeout_s: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let mut args = Args::parse();
    if args.allow.is_empty() {
        args.allow = toolset::DEFAULT_ALLOW
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
    }
    if !args.listen.ip().is_loopback() && args.token.is_none() {
        anyhow::bail!(
            "listening on {} needs --token: a tool server posts to any callback_url it is given",
            args.listen
        );
    }
    let tools =
        toolset::build(&buzz_cli::command(), &args.allow).context("building the toolset")?;
    let identities =
        identity::Identities::load(args.identities.as_deref()).context("loading identities")?;
    let relay = std::env::var("BUZZ_RELAY_URL")
        .ok()
        .filter(|r| !r.trim().is_empty());
    let relay_ws = match (args.delivery.as_str(), &relay) {
        ("poll", _) => None,
        ("push", None) => anyhow::bail!("--delivery push needs BUZZ_RELAY_URL"),
        (_, r) => r.as_deref().map(watch::ws_url),
    };
    if identities.is_empty() {
        tracing::warn!("no identity (BUZZ_PRIVATE_KEY or --identities): tools act with whatever credential buzz finds, and subscriptions are refused");
    }
    for (name, pubkey) in identities.summary() {
        tracing::info!(identity = %name, %pubkey, "identity");
    }
    tracing::info!(
        tools = tools.len(),
        identities = identities.len(),
        delivery = if relay_ws.is_some() { "push" } else { "poll" },
        "buzz-rap on {}",
        args.listen
    );
    server::serve(args, tools, identities, relay_ws).await
}

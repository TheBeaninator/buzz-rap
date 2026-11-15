//! buzz-beekeeper: a self-hosted stand-in for the agent service the Buzz apps talk to (Builderlab's account
//! routes and its *beekeeper* agent registry), so the app's agent screens work on a self-hosted community.
//!
//! The contract is docs/BEEKEEPER.md. In short: the app signs in with PKCE, binds the user's Nostr key with a
//! signed kind 24243 challenge, then creates, lists, changes and deletes agents. Signing in is free; binding is
//! the gate, and only keys on the owner allowlist can bind. Every registry and backup route needs a bound
//! session. The service mints each agent's key, keeps it on this host (0600), and writes a buzz-rap identities
//! file so one buzz-rap process signs as every active agent. It never runs agents itself: a RAP runtime does.

mod api;
mod approve;
mod check;
mod store;

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

/// The callback the Buzz mobile app registers for its browser sign-in.
pub const MOBILE_CALLBACK: &str = "xyz.block.buzz.mobile:/auth/callback";

#[derive(Parser, Debug, Clone)]
#[command(
    name = "buzz-beekeeper",
    about = "Self-hosted agent service for the Buzz apps (sign-in, key binding, agent registry, key backup)"
)]
pub struct Args {
    /// Address to listen on; put a TLS reverse proxy in front of it
    #[arg(long, env = "BEEKEEPER_LISTEN", default_value = "127.0.0.1:7181")]
    pub listen: SocketAddr,
    /// Directory for sessions, the registry, agent keys, key backups and the identities file
    #[arg(long, env = "BEEKEEPER_STATE_DIR")]
    pub state_dir: PathBuf,
    /// Nostr public key (hex or npub) allowed to bind a session; repeat for more. Normally the community owner
    #[arg(long = "owner", env = "BEEKEEPER_OWNERS", value_delimiter = ',')]
    pub owners: Vec<String>,
    /// The service's public HTTPS origin, as the app is built with; a binding challenge must name it
    #[arg(long, env = "BEEKEEPER_PUBLIC_ORIGIN")]
    pub public_origin: Option<String>,
    /// OpenAI-compatible backend whose `GET /v1/models` is the model catalog (base URL or the full models URL)
    #[arg(long, env = "BEEKEEPER_MODELS_URL")]
    pub models_url: Option<String>,
    /// Bearer token for the models backend
    #[arg(long, env = "BEEKEEPER_MODELS_API_KEY")]
    pub models_api_key: Option<String>,
    /// Reasoning efforts every model offers
    #[arg(
        long,
        env = "BEEKEEPER_EFFORTS",
        value_delimiter = ',',
        default_value = "low,medium,high"
    )]
    pub efforts: Vec<String>,
    /// Model recommended for new agents [default: the first in the catalog]
    #[arg(long, env = "BEEKEEPER_RECOMMENDED_MODEL")]
    pub recommended_model: Option<String>,
    /// Effort recommended for new agents
    #[arg(long, env = "BEEKEEPER_RECOMMENDED_EFFORT", default_value = "medium")]
    pub recommended_effort: String,
    /// Shell command that makes a new agent a relay member; {pubkey} and {agent_id} are substituted, and
    /// BEEKEEPER_AGENT_PUBKEY, BEEKEEPER_AGENT_ID and BEEKEEPER_COMMUNITY_URL are set. Empty = skip
    #[arg(
        long,
        env = "BEEKEEPER_MEMBER_ADD_CMD",
        default_value = "buzz-admin add-member --pubkey {pubkey}"
    )]
    pub member_add_cmd: String,
    /// Shell command that removes a deleted agent from the relay, as --member-add-cmd. Empty = skip
    #[arg(
        long,
        env = "BEEKEEPER_MEMBER_REMOVE_CMD",
        default_value = "buzz-admin remove-member --pubkey {pubkey}"
    )]
    pub member_remove_cmd: String,
    /// Shell command run after every registry change, with BEEKEEPER_REGISTRY and BEEKEEPER_IDENTITIES set to
    /// the files' paths: the hand-off to the agent runtime and to buzz-rap
    #[arg(long, env = "BEEKEEPER_ON_CHANGE")]
    pub on_change: Option<String>,
    /// The buzz-rap identities file to write [default: <state-dir>/identities.toml]
    #[arg(long, env = "BEEKEEPER_IDENTITIES")]
    pub identities: Option<PathBuf>,
    /// A community (wss:// URL) to offer in the app's community lists; repeat for more
    #[arg(
        long = "community",
        env = "BEEKEEPER_COMMUNITIES",
        value_delimiter = ','
    )]
    pub communities: Vec<String>,
    /// The account subject every session reports
    #[arg(long, env = "BEEKEEPER_SUBJECT", default_value = "owner")]
    pub subject: String,
    /// Days a session lasts
    #[arg(long, env = "BEEKEEPER_SESSION_DAYS", default_value_t = 30)]
    pub session_days: u64,
    /// Extra sign-in callback a login may return to (the mobile app's is always allowed); repeat for more
    #[arg(long = "return-to", env = "BEEKEEPER_RETURN_TO", value_delimiter = ',')]
    pub return_to: Vec<String>,
    /// `service_namespace` named in key-backup enrollments
    #[arg(
        long,
        env = "BEEKEEPER_BACKUP_NAMESPACE",
        default_value = "buzz-beekeeper"
    )]
    pub backup_namespace: String,
    /// Most agents one owner may have
    #[arg(long, env = "BEEKEEPER_MAX_AGENTS", default_value_t = 64)]
    pub max_agents: usize,
    /// The service's own Buzz key (a relay member). With it, every sign-in waits for an owner to approve it in
    /// Buzz (a 👍 on a direct message from the service), and the session is bound to that owner's key
    #[arg(long, env = "BEEKEEPER_BUZZ_KEY_FILE")]
    pub buzz_key_file: Option<PathBuf>,
    /// The buzz CLI, for approval messages
    #[arg(long, env = "BEEKEEPER_BUZZ_BIN", default_value = "buzz")]
    pub buzz_bin: String,
    /// The relay the approval messages go through
    #[arg(long, env = "BUZZ_RELAY_URL", default_value = "http://127.0.0.1:3000")]
    pub buzz_relay_url: String,
    /// How long a sign-in waits for approval, in seconds
    #[arg(long, env = "BEEKEEPER_APPROVAL_TIMEOUT_S", default_value_t = 900)]
    pub approval_timeout_s: u64,
}

/// Flags checked and normalized.
pub struct Config {
    pub args: Args,
    /// allowlisted owner keys, lowercase hex
    pub owners: Vec<String>,
    pub identities: PathBuf,
    pub return_to: Vec<String>,
    /// sign-in approval in Buzz, when the service has its own key
    pub approval: Option<approve::BuzzAccess>,
}

impl Config {
    pub fn from_args(mut args: Args) -> Result<Config> {
        let mut owners = Vec::new();
        for o in &args.owners {
            let pk = nostr::PublicKey::parse(o.trim())
                .with_context(|| format!("--owner {o}: not a Nostr public key"))?;
            owners.push(pk.to_hex());
        }
        if args.efforts.iter().any(|e| e.trim().is_empty()) || args.efforts.is_empty() {
            bail!("--efforts must list at least one non-empty effort");
        }
        for c in &args.communities {
            if !c.starts_with("wss://") {
                bail!("--community {c}: must be a wss:// URL");
            }
        }
        if let Some(o) = &args.public_origin {
            args.public_origin = Some(o.trim_end_matches('/').to_owned());
        }
        let identities = args
            .identities
            .clone()
            .unwrap_or_else(|| args.state_dir.join("identities.toml"));
        let mut return_to = vec![MOBILE_CALLBACK.to_owned()];
        return_to.extend(args.return_to.iter().cloned());
        let approval = args
            .buzz_key_file
            .clone()
            .map(|key_file| approve::BuzzAccess {
                bin: args.buzz_bin.clone(),
                relay_url: args.buzz_relay_url.clone(),
                key_file,
            });
        Ok(Config {
            args,
            owners,
            identities,
            return_to,
            approval,
        })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cfg = Config::from_args(Args::parse())?;
    if cfg.owners.is_empty() {
        tracing::warn!("no --owner: nobody can bind a key, so every registry route answers 403");
    }
    if cfg.args.models_url.is_none() {
        tracing::warn!("no --models-url: the model catalog is empty and agents cannot be created");
    }
    if !cfg.args.listen.ip().is_loopback() {
        tracing::warn!(
            "listening on {}: serve it only behind a TLS reverse proxy",
            cfg.args.listen
        );
    }
    let app = api::App::open(cfg).context("opening the state directory")?;
    let listen = app.cfg.args.listen;
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {listen}"))?;
    tracing::info!(
        owners = app.cfg.owners.len(),
        state = %app.cfg.args.state_dir.display(),
        "buzz-beekeeper on {listen}"
    );
    axum::serve(listener, api::router(app)).await?;
    Ok(())
}

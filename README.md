# buzz-rap

The [Buzz](https://github.com/block/buzz) CLI as a [RAP](https://infinity.hydro.run/docs/rap/spec/overview)
(Reactive Agent Protocol) tool server. Any RAP agent runtime can then act in a Buzz workspace with its own
identity: read, search and post in channels, react, edit canvases, and subscribe to a channel so that new messages
wake the agent. Its sibling runtime is [FreeFitty](https://github.com/TheBeaninator/freefitty), where agents are
durable threads that hold nothing between turns, so an agent can wait in a channel for days at no cost.

```sh
cargo install --locked --git https://github.com/TheBeaninator/buzz-rap
BUZZ_RELAY_URL=https://relay.example BUZZ_PRIVATE_KEY=nsec1... buzz-rap --listen 127.0.0.1:7171
curl -s http://127.0.0.1:7171/.well-known/rap-toolset | jq '.tools[].name'
```

It runs the `buzz` binary for every tool, so `buzz` must be on `PATH` (or name it with `--buzz-bin`). Each
agent identity needs to be a member of the channels its agent works in.

## With FreeFitty

List buzz-rap as an opt-in tool server, so only threads given its tools see them, and start a thread with
those tools:

```sh
freefitty init --nodes http://127.0.0.1:5300 --optin-tool-servers http://127.0.0.1:7171
freefitty serve &
freefitty say --thread scout \
    --tools buzz_subscribe,buzz_unsubscribe,buzz_messages_send,buzz_messages_get,buzz_messages_thread,buzz_reactions_add \
    "You are Scout in Buzz channel <uuid>. Subscribe to it and answer anyone who mentions you, in their thread."
```

The thread calls `buzz_subscribe` and waits. Each new message in the channel arrives as an event that wakes it,
and it answers with `buzz_messages_send` (`reply_to` = the event id). Other threads on the same daemon never
see the buzz tools, so their prompts are unchanged. `tests/freefitty.rs` runs exactly this with both real
binaries; CI builds FreeFitty from its repository to run it.

Other RAP runtimes work the same way: read the manifest, post invocations to its endpoint, take results and
events on the callback URL.

## In the Buzz workspace

buzz-rap is laid out to drop into Buzz as `crates/buzz-rap`:

```sh
scripts/into-buzz-tree.sh /path/to/buzz && (cd /path/to/buzz && cargo test -p buzz-rap)
```

The script copies the crate, writes its manifest in the workspace's dependency form (`workspace = true`, and
`buzz-cli` as a path dependency), adds it to the workspace members, and applies `patches/` when the checkout
needs it. The only upstream change buzz-rap needs is
`patches/0001-buzz-cli-export-command.patch`: `buzz_cli::command()`, a public accessor for the CLI's clap
command tree (6 lines). Until block/buzz has it, the standalone build depends on
[that commit](https://github.com/TheBeaninator/buzz/tree/feat/cli-export-command) on top of upstream main. CI
runs the in-tree form against block/buzz main as well.

## How it works

- **Tools come from the CLI.** Each allowed command path (`messages send`, `canvas get`, ...) is one tool named
  `buzz_<path>`. Its input schema is generated from the command's clap arguments (`buzz_cli::command()`), so the
  toolset follows the CLI. Connection and identity flags are not exposed: the server's environment
  (`BUZZ_RELAY_URL`, `BUZZ_PRIVATE_KEY`, `BUZZ_AUTH_TAG`, or the desktop credential the CLI finds) decides who
  the agent is.
- **Invocations run `buzz` as a subprocess** with JSON output. Values are passed as `--name=value`, and unknown
  arguments are refused. The server acknowledges at once (202) and posts a `tool_result` to the invocation's
  `callback_url` when the command ends.
- **At-least-once delivery is safe.** RAP may deliver one call twice. A repeated `call_id` (or `id`) in the same
  conversation (`group_id`) gets the first result again, and the command is not run a second time. Answered
  ids are kept in `--state` across restarts.
- **`buzz_subscribe`** watches a channel, optionally one thread or mentions only, and posts each new message as
  a `subscription_event` for the subscribing call. With `BUZZ_RELAY_URL` set, messages are pushed: one
  authenticated relay WebSocket per identity carries a NIP-01 `REQ` per subscription, so a message arrives as
  soon as the relay stores it. A dropped connection is re-made with backoff and each subscription is asked
  again from its own cursor, so nothing is lost. Without a relay URL (or with `--delivery poll`) it polls
  `buzz messages get` instead. The agent's own messages are skipped, which is why subscriptions need a known
  identity (without one a reply would wake the agent in a loop). A subscription ends with `buzz_unsubscribe`,
  after `hours` (24 by default, at most 720), or when the relay closes it, always with a final event.
  Subscriptions are kept in `--state` and resume after a restart.

## Many agents, one process

An identities file maps RAP conversations to keys, so one server signs as each agent:

```toml
[[identity]]
name = "scout"
key_file = "/etc/buzz-rap/scout.key"   # nsec1... or 64 hex characters; chmod 600
groups = ["scout", "scout.*"]          # group_id patterns: exact, or a trailing * for a prefix

[[identity]]
name = "reviewer"
key_env = "REVIEWER_KEY"
groups = ["review-*"]
auth_tag_file = "/etc/buzz-rap/reviewer.auth"   # optional NIP-OA tag (what buzz takes in BUZZ_AUTH_TAG)
```

```sh
buzz-rap --identities identities.toml     # BUZZ_PRIVATE_KEY, if set, is the identity for every other conversation
```

The first entry whose pattern matches a call's `group_id` decides who acts. Its commands run with that key,
its subscriptions read through that identity's own relay connection, and the relay and the audit log both see
that agent. With FreeFitty, a goldfish's thread id starts with its elephant's (`scout.gf-...`), so `scout.*`
gives an agent's helpers the agent's identity. A conversation that matches no entry and has no default is
refused a subscription.

## Audit trail

The relay sees which key signed an action. With several conversations sharing one identity, it cannot say
which of them asked. The audit log closes that gap. It has one JSON line per event, keyed by the calling conversation (`group_id`)
and call (`id`, `call_id`):

- `call`: operation, arguments, the `buzz` argv, ok, duration, result size and head, and the `event_ids` the
  call produced
- `callback`: whether the result reached the agent
- `duplicate`: a repeated delivery of a call that already ran (`replayed`) or is still running
- `refused`: a bad token or an unknown tool
- `subscription_event` / `subscription_end`: a message passed to a subscribing conversation (its `event_id` and
  `author`), or the subscription closing

Each line names the callback by its origin only: a runtime keeps its callback token in the URL path (FreeFitty
does), and the log never holds it.

Any line can be traced from a Buzz event id to the agent call with `grep <event id> audit.jsonl`. The agent's
own transcript holds the same call ids and event ids, so the trace also runs from the transcript to the events.

## Options

| flag | env | default |
|---|---|---|
| `--listen` | `BUZZ_RAP_LISTEN` | `127.0.0.1:7171` |
| `--public-url` | `BUZZ_RAP_PUBLIC_URL` | `http://<listen>` (the manifest's endpoint) |
| `--buzz-bin` | `BUZZ_RAP_BUZZ_BIN` | `buzz` |
| `--allow` | `BUZZ_RAP_ALLOW` | read, search and post commands; nothing that deletes, archives, moderates or changes identity |
| `--token` | `BUZZ_RAP_TOKEN` | none; required when listening beyond loopback, since the server posts to any callback URL it is given |
| `--state` | `BUZZ_RAP_STATE` | none (in memory only) |
| `--identities` | `BUZZ_RAP_IDENTITIES` | none; `BUZZ_PRIVATE_KEY` is the one identity |
| `--delivery` | `BUZZ_RAP_DELIVERY` | `auto`: push when `BUZZ_RELAY_URL` is set, else poll; or `push`, `poll` |
| `--poll-ms` | `BUZZ_RAP_POLL_MS` | `2000` (poll delivery, and the expiry check) |
| `--audit-log` | `BUZZ_RAP_AUDIT_LOG` | none; lines still go to the `buzz_rap::audit` tracing target |
| `--tool-timeout-s` | `BUZZ_RAP_TOOL_TIMEOUT_S` | `120` |

## Security notes

- Every message an agent receives through a subscription was written by some channel member and reaches the
  model as input. Keep agents' channels to people they should listen to, use `mentions_only` where it fits, and
  give an agent only the tools it needs (`--allow` here, a per-thread tool list in the runtime).
- The server posts results to whatever `callback_url` an invocation names, so it listens on loopback unless
  `--token` is set.

## Limits

- Commands still run one `buzz` process per call; only subscriptions use a long-lived connection.
- Identities are read at start; changing the file means a restart. Membership is not managed here: add each
  identity to its channels with Buzz itself.

## Development

```sh
cargo test                                           # unit and end-to-end tests
FREEFITTY_BIN=/path/to/freefitty cargo test --test freefitty   # with the sibling runtime
```

[docs/DESIGN.md](docs/DESIGN.md) explains how Buzz is built, where RAP fits, and the choices made here.

## License

Apache-2.0, the same as Buzz.

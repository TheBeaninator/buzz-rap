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

It runs the `buzz` binary for every tool, so `buzz` must be on `PATH` (or name it with `--buzz-bin`). The
identity in `BUZZ_PRIVATE_KEY` needs to be a member of the channels the agent works in.

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
  a `subscription_event` for the subscribing call. The agent's own messages are skipped, which is why subscriptions
  need `BUZZ_PRIVATE_KEY` (without it a reply would wake the agent in a loop). A subscription ends with `buzz_unsubscribe` or after `hours` (24 by default, at most 720), with a
  final event. Subscriptions are kept in `--state` and resume after a restart.

## Audit trail

Every action is signed by the server's one identity, so the relay alone cannot say which agent asked for it.
The audit log closes that gap. It has one JSON line per event, keyed by the calling conversation (`group_id`)
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
| `--poll-ms` | `BUZZ_RAP_POLL_MS` | `2000` |
| `--audit-log` | `BUZZ_RAP_AUDIT_LOG` | none; lines still go to the `buzz_rap::audit` tracing target |
| `--tool-timeout-s` | `BUZZ_RAP_TOOL_TIMEOUT_S` | `120` |

## Security notes

- Every message an agent receives through a subscription was written by some channel member and reaches the
  model as input. Keep agents' channels to people they should listen to, use `mentions_only` where it fits, and
  give an agent only the tools it needs (`--allow` here, a per-thread tool list in the runtime).
- The server posts results to whatever `callback_url` an invocation names, so it listens on loopback unless
  `--token` is set.

## Limits

- Subscriptions poll `buzz messages get` every `--poll-ms`. A relay push subscription would remove the
  latency and the per-poll process.
- One identity per server. Run one `buzz-rap` per agent identity. The audit log says which conversation asked;
  the relay sees the server's key.

## Development

```sh
cargo test                                           # unit and end-to-end tests
FREEFITTY_BIN=/path/to/freefitty cargo test --test freefitty   # with the sibling runtime
```

[docs/DESIGN.md](docs/DESIGN.md) explains how Buzz is built, where RAP fits, and the choices made here.

## License

Apache-2.0, the same as Buzz.

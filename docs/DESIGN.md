# Design

How Buzz is built, how it expects agents to work, where RAP differs, and the choices buzz-rap makes.

## Buzz in brief

Buzz is a self-hosted workspace on the Nostr protocol. **The relay is the workspace.** One server
(`buzz-relay`) holds everything, and every action is a signed Nostr event identified by a `kind` integer: a
message, a reaction, a canvas edit, a workflow step, a git push. A new feature is a new kind number, and old
clients ignore it.

Behind the relay:

- Postgres stores events; Redis fans them out to live subscribers; Postgres full-text search indexes them.
- A hash-chained audit log records who did what (tamper-evident).
- Blossom media on S3 or MinIO, git smart-HTTP hosting, a YAML workflow engine, and an Opus voice relay for huddles.

Identity is a secp256k1 keypair, the same kind for humans and agents. **Channel membership is the only access
gate.** Clients are a desktop app, a mobile app, an MCP server and the agent-first `buzz` CLI (JSON in, JSON
out), which mirrors and extends the MCP surface.

## How Buzz runs agents today

`buzz-acp` is the agent harness. It holds a WebSocket to the relay, queues `@mentions` per channel (one prompt in
flight per channel), and hands them to ACP agents it spawns: Goose, Codex, Claude Code or buzz-agent. Each agent
has its own key and acts through MCP tools or the CLI. The relay holds the agent's profile, memberships and
history, so the machine running an agent is replaceable.

That model is **prompt-shaped**: a mention starts work, the agent loops over tools until it answers, and the
harness waits for it.

## Where RAP differs

In RAP (hydro-project/infinity), **tools are HTTP servers that answer whenever they are done.** A runtime posts
an invocation to a tool server's endpoint; the server acknowledges at once and later posts the result to the
invocation's `callback_url`. A tool may also post events for a call long after it was answered (a subscription).

Runtimes built on this, FreeFitty among them, treat an agent as a stored conversation: something arrives (a
person's message, a tool result, an event), the model takes one turn, the turn is committed, and the agent holds
nothing until the next thing arrives. Waiting costs nothing, so an agent can sit in a channel for days.

What a RAP agent needs from Buzz is a toolset: act in the workspace, and be woken when something happens there.
buzz-rap is that toolset. It adds no harness and replaces none; buzz-acp and buzz-rap can run side by side.

## Choices in buzz-rap

**Tools are generated from the CLI.** The CLI is the agent interface Buzz already maintains. buzz-rap walks
`buzz_cli::command()` (the clap tree) and turns each allowed command path into one tool with a JSON schema made
from its arguments. New CLI flags appear in the toolset without a buzz-rap change, and a removed command fails
at start (the allow list names a command that no longer exists) instead of at call time. Connection and identity
flags are never exposed.

**Tools run as `buzz` subprocesses.** The CLI's command functions print their output rather than return it, and
calling the binary keeps buzz-rap's behaviour identical to a person typing the command. The cost is one
short-lived process per call. Values go as `--name=value`, so a value starting with `-` is never a flag.

**Many identities, one process.** The agent never sees a key. An identities file maps the runtime's
conversation ids (`group_id`, exact or by prefix) to keys; `BUZZ_PRIVATE_KEY` is the default. Each call's
`buzz` process gets its conversation's key, each identity gets its own relay connection for subscriptions,
and the relay's own attribution then names the agent. This is Buzz's model, agents as members with their own
keys, without a process per agent.

**At-least-once delivery is made safe here.** A RAP runtime may deliver one invocation twice (a crash between
posting and recording the acknowledgement). buzz-rap keys every call by conversation and call id, runs it once,
and answers a repeat with the first result. For a message send, this is the difference between one post and two.

**Subscriptions are pushed.** With the relay URL known, buzz-rap keeps one NIP-42-authenticated WebSocket per
identity (Buzz's own `buzz-ws-client`) and sends a NIP-01 `REQ` per subscription, filtered to the channel's
message kinds and starting at the subscription's cursor. A message arrives as soon as the relay stores it. A
dropped connection is re-made with backoff and every subscription asks again from its cursor, so nothing is
lost, and a repeat at the cursor's second is dropped by event id. If the relay closes a subscription (lost
membership, a limit), the conversation gets a final event saying why. Without a relay URL, buzz-rap polls
`buzz messages get --since` instead, which needs nothing beyond the CLI. Either way the server drops the
agent's own messages by pubkey, which is why subscriptions require a known identity: otherwise each reply would
wake the agent to reply again.

**An audit log names the calling conversation.** The relay sees the key that signed; when several
conversations share an identity, it cannot say which one acted. buzz-rap writes one JSON line per call, duplicate, refusal and delivered event, keyed by the
runtime's conversation id and call ids, with the event ids each call produced. Callback URLs are logged by
origin only, because runtimes keep their callback token in the path.

**Opt-in on the runtime side.** A runtime that offers every tool to every agent would put the buzz tools into
every prompt. FreeFitty has `optin_tool_servers`: those tools reach only threads whose tool list names them, so
adding buzz-rap leaves every other thread's prompt, and its prompt cache, unchanged.

## Two ways to put agents on Buzz

Teams arrive at Buzz in one of two ways, and each has real merits.

**Buzz as a pipe.** The agents' work lives elsewhere (a task board, a job queue). Buzz carries notifications out
and a human's instructions in, often through one shared identity and a poller that accepts only the human's
signed events.

- Strong command gating: only one key can steer anything.
- One source of truth outside Buzz, and work goes on while the relay is down.
- Small surface: few features in use, few things to break.
- But Buzz cannot say which agent did what, rooms fill with posts instead of a current view, polling adds
  latency, the glue is custom, and humans steer by chatting about the work rather than where it happens.

**Buzz as the workspace.** Agents are members with their own keys. Work happens in channels and threads, code
in relay-hosted repos with a channel per branch, approvals in workflows, and the conversation is the record.

- Attribution and least privilege per agent, on a tamper-evident audit chain.
- Push delivery, threads, canvases and search that cover the work itself.
- The code is maintained upstream.
- But more agent keys to manage, a wider prompt-injection surface (any member's message can reach an agent),
  more of Buzz to operate, and the relay on the critical path of the work.

buzz-rap sits between the two. A durable runtime stays the brain and can keep its own state of record, while
its agents become members of channels: they act there, are woken there, and leave an audit trail. Moving
further toward the workspace model is a series of small steps, not a rewrite:

1. One key per agent (an identities file), so the relay itself attributes actions.
2. One thread per task instead of a flat channel.
3. A channel canvas as the current view, maintained by an agent.
4. Workflow approvals for decisions that need a human, once Buzz's approval gates resume runs.

## Possible upstream follow-ups

- `buzz_cli::command()` (the one patch this crate needs).
- An optional provenance tag on events written through buzz-rap (it would be visible to channel members, so it
  belongs in a discussion first).

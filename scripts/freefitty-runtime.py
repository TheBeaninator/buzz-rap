#!/usr/bin/env python3
"""Run buzz-beekeeper's agents as FreeFitty threads: the RAP runtime for agents made in the Buzz apps.

Reads the beekeeper registry (agents.json) and makes FreeFitty match it:

- each ACTIVE agent is a FreeFitty thread `agent-<id>`, started with the buzz tools and a brief built from the
  agent's name and the owner's instructions; the thread subscribes to its mentions and DMs and sleeps;
- the agent's Buzz profile (name, picture, and the NIP-OA owner tag the CLI adds from BUZZ_AUTH_TAG) is published
  with the agent's own key, so the apps list the agent as the owner's;
- changed instructions or a changed name are told to the thread;
- an agent that is deleted (or no longer ACTIVE) has its thread removed;
- alerts FreeFitty raises for an agent (a standing duty paused, its runs failing: replies of kind `alert` on the
  agent's thread) are posted to the agent's direct-message conversation with its owner, with the agent's own key,
  so the owner hears of them even when the agent's model does not relay them.

It is idempotent: run it from beekeeper's --on-change, and on a timer as a safety net. Nothing here holds a model
slot: a thread takes a model turn only when buzz-rap delivers a message to it, and sleeps between messages.

Thread ids match the beekeeper's identities file (`groups = ["agent-<id>", "agent-<id>.*"]`), so buzz-rap signs
each agent's calls with its own key. Standard library only (Python 3.11+).
"""

import argparse
import fcntl
import tomllib
import urllib.error
import urllib.request
import hashlib
import json
import os
import subprocess
import sys
import tempfile

TOOLS = [
    "buzz_subscribe",
    "buzz_unsubscribe",
    "buzz_messages_send",
    "buzz_messages_get",
    "buzz_messages_thread",
    "buzz_messages_search",
    "buzz_reactions_add",
    "buzz_channels_list",
    "buzz_users_get",
]

# FreeFitty's own opt-in tools for long-lived agents (docs/design/standing-work.md in FreeFitty): standing duties,
# a workspace with a memory file, and hand-offs. A FreeFitty without them offers nothing for these names.
STANDING = [
    "routine",
    "hand_off",
    "workspace_read",
    "workspace_list",
    "workspace_write",
    "workspace_delete",
]

STANDING_BRIEF = """
Standing duties: with the routine tool you keep duties that run while nobody is talking to you (every N minutes, at
times of day, or after you have been idle). When your owner asks for something regular ("every morning check X",
"tell me when Y"), add a duty for it. Each firing runs in a short-lived thread of its own with your tools and your
workspace; it reaches you with hand_off only when something needs you, and its one-line result is kept on the duty.
routine with action "list" shows your duties, their next run and last result: use it when your owner asks what you
are doing for them.

Memory: your workspace (workspace_read, workspace_write, workspace_list, workspace_delete) keeps files between
turns. Keep facts you must not lose in my/MEMORY.md (read it, change it, write it back with if_match). Your duty runs
can read and write it too.

Hand-off: hand_off gives work to another agent's thread. A message that starts with [Hand-off from ...] is work
handed to you, and one that starts with [Duty ...] is one of your duties firing in this conversation: act on it,
tell your owner with buzz_messages_send when it matters, and wait again. A message that starts with [FreeFitty] is a
notice about your duties (a pause, failing runs): tell your owner in your direct messages, then wait.
"""


def brief(agent: dict, tools: list) -> str:
    instructions = agent.get("instructions", "").strip() or "(none yet: be helpful and brief)"
    since = int(agent.get("created_at") or 0)
    since_arg = f", since {since}" if since else ""
    extra = [t for t in tools if t not in TOOLS and t not in STANDING]
    extra_line = f"\nBesides Buzz you have these tools: {', '.join(extra)}. Use them to answer your owner's questions.\n" if extra else ""
    if any(t in STANDING for t in tools):
        extra_line += STANDING_BRIEF
    if "image_generate" in extra:
        extra_line += ("To show an image you made with image_generate, send its file path in buzz_messages_send's files "
                       "list (files: [\"<path>\"]) with a short message; the image is uploaded and attached.\n")
    return f"""You are {agent['name']}, an agent in a Buzz workspace, with your own Buzz identity. Your owner's instructions:

{instructions}

How you work:
1. Call buzz_subscribe with scope "mentions", hours 720{since_arg}, and again with scope "dms", hours 720{since_arg}. Leave respond_to unset: by default only your owner's messages reach you.
2. Then wait with sleep_until_event_or_input. Nothing runs while you wait.
3. Each event is a message to you. It names its channel and its event id. Answer it with buzz_messages_send in that channel, following your instructions. In a direct message, reply like a person in a chat: a plain message in the conversation, without reply_to. In a channel, answer in the message's thread: reply_to set to its event id (or to its thread's root, when the event says it is in a thread). Read more context first with buzz_messages_thread or buzz_messages_get when you need it.
4. After answering, wait again with sleep_until_event_or_input.
5. If an event says a subscription ended, subscribe again the same way (unless it says your identity was removed: then stop).

Your owner reads only what you send with buzz_messages_send. A plain-text reply reaches no one, so never answer in plain text. Notes from the agent service need no reply of their own: act on them and wait.{extra_line}"""


def settings_note(agent: dict) -> str:
    instructions = agent.get("instructions", "").strip() or "(none)"
    return f"""[From the agent service] Your owner changed your settings. Your name is now {agent['name']}. Your instructions are now:

{instructions}

Keep working as before: answer each message that reaches you with buzz_messages_send (plain text reaches no one), then wait with sleep_until_event_or_input. This note needs no reply."""


def digest(*parts) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True).encode()).hexdigest()[:16]


def run(cmd, env=None, dry=False):
    if dry:
        print("would run:", " ".join(cmd[:4]), "...")
        return True, ""
    try:
        p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return p.returncode == 0, (p.stdout + p.stderr).strip()


def read_secret(path: str) -> str:
    with open(path) as f:
        return f.read().strip()


def publish_profile(args, agent: dict) -> bool:
    env = dict(os.environ)
    env["BUZZ_RELAY_URL"] = args.relay_url
    env["BUZZ_PRIVATE_KEY"] = read_secret(agent["key_file"])
    env["BUZZ_AUTH_TAG"] = read_secret(agent["auth_tag_file"])
    env["BUZZ_OUTPUT_FORMAT"] = "json"
    cmd = [args.buzz, "users", "set-profile", f"--name={agent['name']}"]
    if agent.get("picture"):
        cmd.append(f"--avatar={agent['picture']}")
    ok, out = run(cmd, env=env, dry=args.dry_run)
    if not ok:
        print(f"agent {agent['id']}: profile not published: {out[:300]}", file=sys.stderr)
    return ok


def freefitty(args, *rest):
    return run([args.freefitty, "--config", args.freefitty_config, *rest], dry=args.dry_run)


def write_atomic(path: str, data: dict):
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".runtime-")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def sync(args) -> int:
    with open(args.registry) as f:
        registry = json.load(f)
    try:
        with open(args.state) as f:
            state = json.load(f)
    except FileNotFoundError:
        state = {"agents": {}}
    applied = state.setdefault("agents", {})
    active = {a["id"]: a for a in registry.get("agents", []) if a.get("status") == "active"}
    tools = TOOLS + ([] if args.no_standing else STANDING) + [t for t in args.extra_tools if t and t not in TOOLS and t not in STANDING]
    tools_digest = digest(tools)
    failures = 0

    for agent_id, agent in active.items():
        thread = f"agent-{agent_id}"
        prev = applied.get(agent_id)
        profile = digest(agent["name"], agent.get("picture"))
        settings = digest(agent["name"], agent.get("instructions", ""))
        rec = dict(prev or {})
        if prev is None or prev.get("profile") != profile:
            if publish_profile(args, agent):
                rec["profile"] = profile
            else:
                failures += 1
        # a record from before tool tracking means the plain buzz tools
        if prev is not None and prev.get("started") and prev.get("tools", digest(TOOLS)) != tools_digest:
            # a thread's tool list is fixed when it starts: begin again with the new tools
            ok, out = freefitty(args, "rm", thread)
            if ok:
                rec["started"] = False
                prev = dict(rec)
                print(f"agent {agent_id}: tools changed; restarting {thread}")
            else:
                failures += 1
                print(f"agent {agent_id}: could not restart for new tools: {out[:300]}", file=sys.stderr)
        if prev is None or not prev.get("started"):
            ok, out = freefitty(args, "say", "--thread", thread, "--tools", ",".join(tools), brief(agent, tools))
            if ok:
                rec.update(started=True, settings=settings, tools=tools_digest)
                print(f"agent {agent_id}: thread {thread} started")
            else:
                failures += 1
                print(f"agent {agent_id}: thread not started: {out[:300]}", file=sys.stderr)
        elif prev.get("settings") != settings:
            ok, out = freefitty(args, "say", "--thread", thread, settings_note(agent))
            if ok:
                rec["settings"] = settings
                print(f"agent {agent_id}: told {thread} about new settings")
            else:
                failures += 1
                print(f"agent {agent_id}: settings not delivered: {out[:300]}", file=sys.stderr)
        applied[agent_id] = rec

    for agent_id in [i for i in applied if i not in active]:
        thread = f"agent-{agent_id}"
        ok, out = freefitty(args, "rm", thread)
        if ok or "no such thread" in out.lower() or "not found" in out.lower():
            del applied[agent_id]
            print(f"agent {agent_id}: thread {thread} removed")
        else:
            failures += 1
            print(f"agent {agent_id}: thread not removed: {out[:300]}", file=sys.stderr)

    if not args.dry_run:
        write_atomic(args.state, state)
    if args.rap_state and not args.dry_run:
        failures += relay_alerts(args, active)
    return 1 if failures else 0


def operator_api(args):
    """FreeFitty's operator API base URL and token, from its config file."""
    with open(args.freefitty_config, "rb") as f:
        cfg = tomllib.load(f)
    listen = cfg.get("listen", "127.0.0.1:8081")
    return f"http://{listen}", cfg.get("operator_token", "")


def pop_reply(base: str, token: str, thread: str):
    """The oldest uncollected reply of `thread` (FreeFitty removes it as it hands it out), or None."""
    req = urllib.request.Request(f"{base}/output?thread={thread}&wait=0", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=15) as r:
        if r.status == 204:
            return None
        return json.load(r)


def dm_channel(rap_state: str, agent_id: str):
    """The agent's direct-message conversation with its owner, from buzz-rap's subscription state."""
    try:
        with open(rap_state) as f:
            subs = json.load(f).get("subs", [])
    except (OSError, ValueError):
        return None
    for s in subs:
        if s.get("identity") == agent_id and s.get("scope") == "dms" and s.get("dm_channels"):
            return s["dm_channels"][0]
    return None


def relay_alerts(args, active: dict) -> int:
    """Post each active agent's `alert` replies to its owner's DM with the agent's key. Its other replies are plain
    text the agent wrote outside buzz_messages_send, which reach no one by design: they are collected and dropped,
    so they do not pile up. An alert that cannot be posted is printed and counted as a failure (FreeFitty has
    already handed it out; the next run cannot see it again)."""
    try:
        base, token = operator_api(args)
    except (OSError, ValueError) as e:
        print(f"alerts: cannot read {args.freefitty_config}: {e}", file=sys.stderr)
        return 1
    failures = 0
    for agent_id, agent in active.items():
        thread = f"agent-{agent_id}"
        dropped = 0
        while True:
            try:
                reply = pop_reply(base, token, thread)
            except (urllib.error.URLError, OSError, ValueError) as e:
                print(f"alerts: FreeFitty not reachable ({e}); trying again next run", file=sys.stderr)
                return failures
            if reply is None:
                break
            if reply.get("metadata", {}).get("kind") != "alert":
                dropped += 1
                continue
            text = reply.get("text", "")
            channel = dm_channel(args.rap_state, agent_id)
            if not channel:
                failures += 1
                print(f"agent {agent_id}: alert not posted (no direct-message conversation known yet): {text[:300]}", file=sys.stderr)
                continue
            env = dict(os.environ)
            env["BUZZ_RELAY_URL"] = args.relay_url
            env["BUZZ_PRIVATE_KEY"] = read_secret(agent["key_file"])
            env["BUZZ_AUTH_TAG"] = read_secret(agent["auth_tag_file"])
            ok, out = run([args.buzz, "messages", "send", "--channel", channel, "--content", text], env=env)
            if ok:
                print(f"agent {agent_id}: alert posted to its owner")
            else:
                failures += 1
                print(f"agent {agent_id}: alert not posted ({out[:200]}): {text[:300]}", file=sys.stderr)
        if dropped:
            print(f"agent {agent_id}: {dropped} plain-text repl{'y' if dropped == 1 else 'ies'} collected (they reach no one)")
    return failures


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--registry", default=os.environ.get("BEEKEEPER_REGISTRY"), help="beekeeper agents.json")
    p.add_argument("--state", required=True, help="this runtime's own record of what it applied")
    p.add_argument("--freefitty", default="freefitty")
    p.add_argument("--freefitty-config", default="freefitty.toml")
    p.add_argument("--buzz", default="buzz", help="the buzz CLI, for publishing agent profiles")
    p.add_argument("--relay-url", default=os.environ.get("BUZZ_RELAY_URL", "http://127.0.0.1:3000"))
    p.add_argument("--extra-tools", default="", type=lambda s: [t.strip() for t in s.split(",") if t.strip()],
                   help="more tools every agent gets besides the buzz tools, comma-separated (an opt-in server's)")
    p.add_argument("--no-standing", action="store_true", help="leave out FreeFitty's routine, hand_off and workspace tools")
    p.add_argument("--rap-state", default=os.environ.get("BUZZ_RAP_STATE"),
                   help="buzz-rap's --state file; with it, alerts are relayed to each agent's owner DM")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    if not args.registry:
        p.error("--registry (or BEEKEEPER_REGISTRY) is required")
    # one sync at a time: beekeeper's on-change and the timer may overlap
    with open(args.state + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return sync(args)


if __name__ == "__main__":
    sys.exit(main())

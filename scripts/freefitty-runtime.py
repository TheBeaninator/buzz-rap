#!/usr/bin/env python3
"""Run buzz-beekeeper's agents as FreeFitty threads: the RAP runtime for agents made in the Buzz apps.

Reads the beekeeper registry (agents.json) and makes FreeFitty match it:

- each ACTIVE agent is a FreeFitty thread `agent-<id>`, started with the buzz tools and a brief built from the
  agent's name and the owner's instructions; the thread subscribes to its mentions and DMs and sleeps;
- the agent's Buzz profile (name, picture, and the NIP-OA owner tag the CLI adds from BUZZ_AUTH_TAG) is published
  with the agent's own key, so the apps list the agent as the owner's;
- changed instructions or a changed name are told to the thread;
- an agent that is deleted (or no longer ACTIVE) has its thread removed.

It is idempotent: run it from beekeeper's --on-change, and on a timer as a safety net. Nothing here holds a model
slot: a thread takes a model turn only when buzz-rap delivers a message to it, and sleeps between messages.

Thread ids match the beekeeper's identities file (`groups = ["agent-<id>", "agent-<id>.*"]`), so buzz-rap signs
each agent's calls with its own key. Standard library only (Python 3.11+).
"""

import argparse
import fcntl
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


def brief(agent: dict) -> str:
    instructions = agent.get("instructions", "").strip() or "(none yet: be helpful and brief)"
    return f"""You are {agent['name']}, an agent in a Buzz workspace, with your own Buzz identity. Your owner's instructions:

{instructions}

How you work:
1. Call buzz_subscribe with scope "mentions" and hours 720, and again with scope "dms" and hours 720. Leave respond_to unset: by default only your owner's messages reach you.
2. Then wait with sleep_until_event_or_input. Nothing runs while you wait.
3. Each event is a message to you. It names its channel and its event id. Answer it with buzz_messages_send in that channel, with reply_to set to that event id, following your instructions. Read more context first with buzz_messages_thread or buzz_messages_get when you need it.
4. After answering, wait again with sleep_until_event_or_input.
5. If an event says a subscription ended, subscribe again the same way (unless it says your identity was removed: then stop)."""


def settings_note(agent: dict) -> str:
    instructions = agent.get("instructions", "").strip() or "(none)"
    return f"""[From the agent service] Your owner changed your settings. Your name is now {agent['name']}. Your instructions are now:

{instructions}

Keep working as before: answer each message that reaches you, then wait with sleep_until_event_or_input."""


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
        if prev is None or not prev.get("started"):
            ok, out = freefitty(args, "say", "--thread", thread, "--tools", ",".join(TOOLS), brief(agent))
            if ok:
                rec.update(started=True, settings=settings)
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
    return 1 if failures else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--registry", default=os.environ.get("BEEKEEPER_REGISTRY"), help="beekeeper agents.json")
    p.add_argument("--state", required=True, help="this runtime's own record of what it applied")
    p.add_argument("--freefitty", default="freefitty")
    p.add_argument("--freefitty-config", default="freefitty.toml")
    p.add_argument("--buzz", default="buzz", help="the buzz CLI, for publishing agent profiles")
    p.add_argument("--relay-url", default=os.environ.get("BUZZ_RELAY_URL", "http://127.0.0.1:3000"))
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

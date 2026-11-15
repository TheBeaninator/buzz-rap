#!/usr/bin/env python3
"""Hand a report to an agent made in the Buzz apps, so the agent summarizes it for its owner in Buzz.

Long-running work (a build, a batch job, another agent session) often ends with a report that someone should read,
and the someone is usually on a phone. This script delivers the report to one of the owner's own agents as a note
in its FreeFitty thread (`agent-<id>`, as scripts/freefitty-runtime.py runs them). The note wakes the agent and asks
it to post a short, plain-language summary in its direct-message conversation with its owner, so the owner reads it
in the Buzz app and can ask the agent follow-up questions there.

    agent-report.py --registry agents.json --agent Scout --from nightly-build --title "build 1432" < report.md

Why a thread note and not a Buzz message: agents answer only their owner by default (buzz-rap's respond_to gate), so
a message from another key would never reach the agent. The note goes straight into the agent's own conversation.

The owner's DM channel is read from buzz-rap's `--state` file when given (the agent's `dms` subscription records the
conversations it has seen); without it the agent is told to use its conversation with its owner. Reports over
--max-bytes are cut. With --log, every delivery appends one JSON line (time, sender, agent, title, size, ok).
Standard library only (Python 3.11+).
"""

import argparse
import json
import os
import subprocess
import sys
import time


def find_agent(registry_path: str, name: str) -> dict:
    with open(registry_path) as f:
        agents = json.load(f).get("agents", [])
    for a in agents:
        if a.get("status") == "active" and (a.get("name", "").lower() == name.lower() or a.get("id") == name):
            return a
    raise SystemExit(f"no active agent named {name!r} in {registry_path}")


def dm_channels(state_path: str | None, agent_id: str) -> list:
    if not state_path:
        return []
    try:
        with open(state_path) as f:
            subs = json.load(f).get("subs", [])
    except (OSError, ValueError):
        return []
    out = []
    for s in subs:
        if s.get("identity") == agent_id and s.get("scope") == "dms":
            out += [c for c in s.get("dm_channels", []) if c not in out]
    return out


def note(sender: str, title: str, body: str, channels: list) -> str:
    if len(channels) == 1:
        where = f"in your direct-message conversation with your owner (channel {channels[0]})"
    elif channels:
        where = f"in your direct-message conversation with your owner (one of channels {', '.join(channels)})"
    else:
        where = "in your direct-message conversation with your owner"
    head = f"[Report for your owner from {sender}{': ' + title if title else ''}]"
    return (
        f"{head}\n\n{body}\n\n"
        f"[What to do] Send your owner a short summary of this report {where} with buzz_messages_send, as a plain "
        "message (no reply_to). Lead with what needs your owner (a decision, something to do by hand, something "
        "broken), then what got done, then what is still running. Keep it to a few sentences or bullets in plain "
        f"language, and say it came from {sender}. Then wait again with sleep_until_event_or_input."
    )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--registry", default=os.environ.get("BEEKEEPER_REGISTRY"), help="buzz-beekeeper agents.json")
    p.add_argument("--agent", required=True, help="the agent's name (as shown in the apps) or id")
    p.add_argument("--from", dest="sender", required=True, help="who is reporting, as the owner should see it")
    p.add_argument("--title", default="", help="a one-line subject")
    p.add_argument("--rap-state", default=os.environ.get("BUZZ_RAP_STATE"), help="buzz-rap's --state file")
    p.add_argument("--freefitty", default="freefitty")
    p.add_argument("--freefitty-config", default="freefitty.toml")
    p.add_argument("--max-bytes", type=int, default=12 * 1024)
    p.add_argument("--log", help="append one JSON line per delivery here")
    a = p.parse_args()
    if not a.registry:
        p.error("--registry (or BEEKEEPER_REGISTRY) is required")
    body = sys.stdin.read().strip()
    if not body:
        p.error("the report comes on stdin")
    raw = body.encode()
    if len(raw) > a.max_bytes:
        body = raw[: a.max_bytes].decode(errors="ignore") + f"\n[report cut at {a.max_bytes} bytes]"
    agent = find_agent(a.registry, a.agent)
    thread = f"agent-{agent['id']}"
    text = note(a.sender, a.title, body, dm_channels(a.rap_state, agent["id"]))
    try:
        r = subprocess.run([a.freefitty, "--config", a.freefitty_config, "say", "--thread", thread, text],
                           capture_output=True, text=True, timeout=120)
        ok, out = r.returncode == 0, (r.stdout + r.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        ok, out = False, str(e)
    if a.log:
        with open(a.log, "a") as f:
            f.write(json.dumps({"ts": int(time.time()), "from": a.sender, "agent": agent["name"],
                                "title": a.title, "bytes": len(raw), "ok": ok}) + "\n")
    if not ok:
        print(f"not delivered: {out[:400]}", file=sys.stderr)
        return 1
    print(f"delivered to {agent['name']} ({thread})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

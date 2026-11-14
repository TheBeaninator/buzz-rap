#!/usr/bin/env bash
# Put buzz-rap into a Buzz checkout as crates/buzz-rap, the way it would live upstream:
#   scripts/into-buzz-tree.sh /path/to/buzz
# Copies the sources, writes the crate manifest in the workspace's dependency form, adds the crate to the
# workspace members, and applies patches/ (buzz_cli::command()) when the checkout does not have it yet.
# Then: cd /path/to/buzz && cargo test -p buzz-rap
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
buzz=${1:?usage: into-buzz-tree.sh /path/to/buzz}
[ -f "$buzz/crates/buzz-cli/src/lib.rs" ] || { echo "$buzz is not a Buzz checkout (no crates/buzz-cli)" >&2; exit 1; }

if ! grep -q 'pub fn command() -> clap::Command' "$buzz/crates/buzz-cli/src/lib.rs"; then
    for p in "$here"/patches/*.patch; do
        git -C "$buzz" apply --3way "$p" || { echo "patch $p does not apply; see its header" >&2; exit 1; }
        echo "applied $(basename "$p")"
    done
fi

dst="$buzz/crates/buzz-rap"
rm -rf "$dst"
mkdir -p "$dst"
cp -r "$here/src" "$here/tests" "$here/README.md" "$dst/"
cat > "$dst/Cargo.toml" <<'TOML'
[package]
name = "buzz-rap"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
description = "The buzz CLI as a RAP (Reactive Agent Protocol) tool server"

[[bin]]
name = "buzz-rap"
path = "src/main.rs"

[dependencies]
# The command tree the toolset is generated from
buzz-cli = { path = "../buzz-cli" }
clap = { version = "4", features = ["derive", "env"] }

# HTTP server for the manifest and invocations, client for callbacks
axum = { workspace = true }
reqwest = { workspace = true, features = ["json"] }
tokio = { workspace = true }

serde = { workspace = true }
serde_json = { workspace = true }
anyhow = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }

# Our own public key, so a subscription does not echo the agent's own posts
nostr = { workspace = true }
TOML

if ! grep -q '"crates/buzz-rap"' "$buzz/Cargo.toml"; then
    python3 - "$buzz/Cargo.toml" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
anchor = '    "crates/buzz-cli",\n'
if anchor not in s:
    sys.exit("workspace members: no crates/buzz-cli line to add buzz-rap after; add it by hand")
open(p, "w").write(s.replace(anchor, anchor + '    "crates/buzz-rap",\n', 1))
PY
fi
echo "crates/buzz-rap in place; next: (cd $buzz && cargo test -p buzz-rap)"

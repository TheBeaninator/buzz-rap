# The agent service contract the Buzz apps speak

The Buzz mobile app (and the desktop app, which shares the agent routes) creates, lists, changes and deletes
agents through a hosted service called Builderlab. The registry part of its API is called *beekeeper*. A
self-hosted Buzz community has no Builderlab, so the app's agent screens do nothing there. This document records
what the app sends and expects, read from the client, so a self-hosted service can answer it.

Source: block/buzz `mobile/lib/shared/hosted/` and `mobile/lib/shared/agents/remote_agents.dart` at upstream
`69742376a` (2026-11-14). Field names, status values and checks below are what the client code does. Server
behaviour that the client cannot observe is marked *(service choice)*.

## 1. Pointing the app at a service

The service location is build configuration (`--dart-define`), never read from a relay or a link
(`builderlab_build.dart`):

| define | meaning |
|---|---|
| `BUZZ_DISTRIBUTION` | `public` or `internal` |
| `BUZZ_BUILDERLAB_URL` | the service's HTTPS origin: `https`, no port (so 443), no path, query or fragment |
| `BUZZ_BUILDERLAB_RELAYS` | comma-separated relay domains that use this service; `internal` takes exactly one host |

All three or none. With none, the build is Nostr-only (no account, no agent screens).

**Which distribution.** Agent screens are gated by `supportsRemoteAgents()`:
`HostedEnvironment.enabled` (true only for `public`) and the community's relay matching
`BUZZ_BUILDERLAB_RELAYS` and having an owner pubkey. An `internal` build therefore never offers agents. A
`public` build may name any HTTPS origin; the parser does not restrict it to Block's. So a public build with
the self-hosted service's origin needs no code change for the gate.

**Relay URL constraints.** `matchesRelay` accepts a relay only as `wss://` or `https://`, on port 443, with an
empty path and no query, fragment or user info. A relay served on another port fails the match, and its
community gets no agent screens. Either serve the relay on 443 (and add the community at that address), or
patch `matchesRelay` to accept the port.

## 2. Transport

- Every call is `POST {origin}/api/goose{path}` with a JSON body, except the session check (`GET`).
- Headers: `Accept: application/json`, `Content-Type: application/json`, `Origin: {origin}`,
  `X-BB-Session-Credential: <session credential>`. A few identity routes also carry
  `Authorization: Nostr <NIP-98 event>` signed by the user's key (`/v1/buzz/identity/assertions`).
- Allowed paths: anything matching `^/v1/buzz(/[a-z0-9_-]+)+$` and the six beekeeper routes. Redirects are
  not followed.
- Responses must be a JSON object. Size limit 64 KiB, except `list-agents` (4 MiB).
- Status mapping in the client: `401` signed out (it then re-checks the session with `/v1/auth/me` and clears
  it only if that fails too); `403` denied (or "account setup required" if `/v1/auth/me` said so); `400`,
  `404`, `409`, `422` rejected (not retried unchanged); anything else outside 2xx is "unavailable".
- Many routes report success with a `status` field. The client accepts either the enum's number or a string
  ending in `_<NAME>` (for example `1` or `"REGISTER_AGENT_STATUS_UNATTESTED"`), per response type.

## 3. Sign-in

The app opens a browser with PKCE (S256) and returns via the custom scheme `xyz.block.buzz.mobile:/auth/callback`
with `code` and `state`.

- Public build: `GET {origin}/auth/native?returnTo=<callback>&state=<s>&code_challenge=<c>&code_challenge_method=S256`
- Internal build: `GET {origin}/api/goose/v1/auth/login?type=cli&product=buzz&...` with the same parameters.

| route | request | response |
|---|---|---|
| `POST /v1/auth/login/exchange` | `code`, `code_verifier` | `session_credential` (string, at most 512 chars), `expires_at` (ISO-8601; must equal `/v1/auth/me`'s) |
| `GET /v1/auth/me` (credential header) | | `subject` (string), `expires_at`, optional `email`, optional `account_status` (`ACCOUNT_STATUS_NEEDS_DETAILS` = needs setup) |

The session is bound to one `subject`. A login for another subject is refused until sign-out.

## 4. Binding the user's Nostr key to the account

The app works only with the key the account is bound to (`ensureBinding`, `hosted_identity_service.dart`).

| route | request | response |
|---|---|---|
| `/v1/buzz/nostr-identities/current` | `{}` | `identity: { pubkey_hex }` or no identity |
| `/v1/buzz/nsec-backups/status` | `{}` | `current_nostr_pubkey` (must equal the bound key, or null), `backup_nostr_pubkeys: [hex...]` |
| `/v1/buzz/nostr-identities/challenge` | `origin` | `challenge_id`, `nonce`, `verification_code`, `origin`, `expires_at` (all strings) |
| `/v1/buzz/nostr-identities/verify` | `challenge_id`, `nonce`, `signed_payload` | `identity: { pubkey_hex }` (must equal the signer) |

`signed_payload` is the JSON of a Nostr event, **kind 24243**, empty content, signed by the user's key, with one
tag per field: `challenge_id`, `nonce`, `verification_code`, `audience` = `buzz:nostr-identity`, `action` =
`bind_nostr_identity`, `protocol` = `buzz-nostr-identity`, `version` = `1`, `origin`, `expires_at`. The service
verifies the signature and that every tag matches the challenge it issued, then binds the signer's pubkey to
the subject.

**Key backup.** Once bound, a public build expects an encrypted backup of the key on the service before the
identity counts as ready (`needsBackup`, unless the phone holds a backup receipt for this service and subject).
The key is sealed on the phone with HPKE to a recipient key the service names, after the user consents
(`hosted_backup_service.dart`, `hpke_backup.dart`):

| route | request | response |
|---|---|---|
| `/v1/buzz/nsec-backups/enrollment` | `{}` | `version` = 1, `suite` = `{kem_id: 16, kdf_id: 1, aead_id: 2}` (DHKEM P-256, HKDF-SHA256, AES-256-GCM), `recipient_public_key` (base64url, 65-byte uncompressed P-256 point), `recipient_key_id`, `service_namespace`, `owner_id` (each 1-255 bytes, no control characters), `backup_id` (UUID), `nostr_pubkey` (the bound key) |
| `/v1/buzz/nsec-backups` | the envelope: the enrollment's `version`, `suite`, `recipient_key_id`, `service_namespace`, `owner_id`, `backup_id`, `nostr_pubkey`, plus `enc` (65-byte point) and `ciphertext` (48 bytes: the 32-byte key and a 16-byte tag), both base64url without padding | `stored: true`, `backup_id` (the same) |
| `/v1/buzz/nsec-backups/recovery` | `{}` (recovery on a new phone) | `backups: [{secret_key, backup_id, nostr_pubkey}]` (`secret_key` = the opened 32-byte key, base64url without padding; the app derives the public key and checks it equals `nostr_pubkey`) and `failed_backup_ids: [...]` (any entry blocks recovery). Only a service that opens backups can answer it |

The associated data is `"buzz/nsec-backup/aad/v1"`, the bytes `01 00 10 00 01 00 02`, then
`recipient_key_id`, `service_namespace` and `owner_id`, each as a 2-byte length and the UTF-8 bytes, then the
16 bytes of `backup_id` and the 32 bytes of `nostr_pubkey`. A self-hosted service stores the envelope as is
(only the holder of the recipient private key could open it), or the app is patched to skip the step.

**Onboarding routes** a public build also calls:

| route | request | response |
|---|---|---|
| `/v1/buzz/known-communities/add` | `community_url` | no `error` field |
| `/v1/buzz/known-communities/list` | `{}` | `communities: [{community_url}]` (may be omitted when empty); only `wss://` URLs on the configured relay domains are used |
| `/v1/buzz/communities/joined` | `{}` | `communities: [{normalized_host, name}]` (required, even when empty); `normalized_host` is a bare host (or `wss://` URL) on port 443 with no path, `name` non-empty; rows with `archived_at` (ISO string) are skipped. Discovery never grants admission |
| `/v1/buzz/identity/assertions` | `relay_url`, `nostr_pubkey`, NIP-98 signed | NIP-FI assertion, used only for relays whose NIP-FI discovery requires one; a relay that does not get none |

## 5. The agent registry (beekeeper)

All with the session credential. The app requires that the account's bound key equals the community's owner
pubkey (`community.pubkey == owner`) before creating.

### `get-model-catalog`

Request `{}`. Response:

```json
{"models": [{"id": "m", "display_name": "Model M", "supported_reasoning_efforts": ["low", "medium", "high"]}],
 "recommended_selection": {"model_id": "m", "reasoning_effort": "medium"}}
```

Every model needs a non-empty `id`, `display_name` and effort list. Creation and model changes are validated
against this list on the phone.

### `register-agent`

Request: `agent_name` (1-64 of letters, digits, space, `.`, `_`, `-`), optional `agent_picture_url` (https),
`idempotency_key` (UUID). Response: `status` = UNATTESTED (`1` or `*_UNATTESTED`), `agent_pubkey` (64 hex),
`agent_id` (string).

**The service mints the agent's keypair.** The same `idempotency_key` must return the same agent: the phone
replays it when a response was lost, possibly from another community.

### `attest-agent`

Request: `agent_pubkey`, `owner_auth_tag_json` (a JSON array string), `community_url` (the relay's `wss://` URL).
Response: `status` = ACTIVE (`1` or `*_ACTIVE`).

`owner_auth_tag_json` is a NIP-OA owner tag `["auth", <owner pubkey>, "", <sig>]`, where `sig` is a BIP-340
Schnorr signature by the owner's key over `sha256("nostr:agent-auth:<agent pubkey>:")` (the empty conditions
string at the end). The service verifies it against the account's bound key and keeps it: the agent publishes it
(section 6). The agent must also become able to act in `community_url` (relay membership) *(service choice: how)*.

### `update-agent`

Request: `agent_pubkey` plus any of `agent_instructions` (at most 20,000 chars), `model_id`, `reasoning_effort`.
Response: no `error` field. The phone then reads `list-agents` back and expects the new values, with
`model_selection_status` = VALID (`1` or `MODEL_SELECTION_STATUS_VALID`).

### `list-agents`

Request: `include_instructions: true`. Response: `status` = SUCCESS (`1` or `*_SUCCESS`) and `agents`, each:

| field | use in the app |
|---|---|
| `agent_pubkey` | identity (64 hex) |
| `agent_id` | the id `delete-agent` takes |
| `agent_name` | shown in lists and dialogs |
| `agent_instructions` | shown and edited |
| `model_id`, `reasoning_effort` | shown and changed |
| `model_selection_status` | `1` / `MODEL_SELECTION_STATUS_VALID` when the pair is current |
| `status` | `2` / `BEEKEEPER_AGENT_STATUS_ACTIVE` counts as available |

### `delete-agent`

Request: `agent_id`. Response `status`: DELETED (`1`) or NOT_FOUND (`3`) succeed; DISABLED (`2`) shows "deletion is
disabled on this server". Before calling it, the phone deletes the relay registration (section 6) and checks it
is gone.

## 6. What lives on the relay

The relay stores these as ordinary events; it gives kind 30177 no special validation beyond owner-authored,
parameterized-replaceable addressing.

- **Registration, kind 30177** (NIP-AP managed agent), published by the **phone** with the owner's key after
  `attest-agent` and `update-agent`: `d` = agent pubkey, `runtime` = `block.builderlab/builderlab`, content
  `{"name", "picture"?, "parallelism": 1, "respond_to": "owner-only"}`. Removed on delete with a kind 5 event
  tagged `["a", "30177:<owner pubkey>:<agent pubkey>"]`. It must never carry secrets: it is world-readable.
- **Agent profile, kind 0**, published by the **agent's own key**, carrying the NIP-OA `auth` tag from
  `attest-agent`. The phone lists an agent as the user's only when this profile's owner tag verifies to the
  user (`verifiedProfileOaOwnerPubkey`), and as available only when the owner's kind 30177 for it is live.
- `respond_to` follows buzz-acp's author gate: `owner-only`, `allowlist`, `anyone`, `nobody`.

## 7. A self-hosted service: the security model

- **Sign-in can stay simple; key binding is the gate.** A session alone may do nothing but bind. The service binds
  only pubkeys on its owner allowlist (the community owner), proven by the kind 24243 signature. Every
  registry route requires a session bound to an allowed key. A stranger who completes sign-in cannot bind the
  owner's key, so their session can do nothing.
- Verify every `owner_auth_tag_json` against the session's bound key before activating an agent.
- Agent secret keys stay on the service host (0600) and never leave it except to the agent's own runtime.
- Store key backups only as the sealed blobs the client sends.

## 8. App changes for a self-hosted community

| need | change |
|---|---|
| agent screens | none with `BUZZ_DISTRIBUTION=public` and the service's origin; an `internal` build needs `supportsRemoteAgents()` to accept it |
| relay on a port other than 443 | `BuilderlabBuild.matchesRelay` to accept it, or serve the relay on 443 |
| no key backup on the service | skip the `needsBackup` step in `hosted_flow_backup_consent.dart` (or store the envelopes, section 4) |
| agent cards (preset avatars and drafts) | optional; `avatarsCdnOrigin` is null for unknown origins and cards are simply absent |

## 9. Running the agents: RAP, not sessions

The registry only records agents; something must run them. Buzz's own harness (`buzz-acp`) answers each mention
with an ACP agent session: a process that loops prompt -> model -> tools until it replies, holding a model slot for
the whole turn and a process per agent. For a self-hosted community whose models run on a few local machines, a
dozen agents in that shape tie up the machines.

The service runs each agent on a RAP runtime instead (FreeFitty is the reference):

- **An agent is a durable conversation, not a process.** The runtime keeps its transcript; nothing runs between
  messages, and an idle agent holds no model slot (FreeFitty also parks its cached state off the node).
- **A mention is an event.** buzz-rap delivers the agent's mentions and DMs as RAP `subscription_event`s; the
  runtime wakes the conversation for one model turn and lets it sleep again (`sleep_until_event_or_input`).
- **Tools are RAP calls, answered asynchronously.** Each tool call ends the turn; the model slot is released while
  `buzz` runs, and the result wakes the conversation.
- **Each agent signs as itself.** The registry's agent keys go into buzz-rap's identities file, with the
  conversation id as the pattern, so one buzz-rap serves every agent.
- **The runtime schedules model time,** so agents queue for slots with everything else the runtime runs, rather
  than each session competing for a slot on its own.

The policy event's `runtime` tag (`block.builderlab/builderlab`) is what the stock app writes; the self-hosted
runtime recognizes its agents by the registry, not by that tag.

## 10. Status strings

The client accepts a number or any string ending in `_<NAME>`. buzz-beekeeper answers with these strings:
`REGISTER_AGENT_STATUS_UNATTESTED`, `ATTEST_AGENT_STATUS_ACTIVE`, `LIST_AGENTS_STATUS_SUCCESS`,
`DELETE_AGENT_STATUS_DELETED` / `DELETE_AGENT_STATUS_NOT_FOUND`, per agent `BEEKEEPER_AGENT_STATUS_ACTIVE` /
`BEEKEEPER_AGENT_STATUS_UNATTESTED`, and `MODEL_SELECTION_STATUS_VALID` (or `_UNSPECIFIED` / `_INVALID`, which
the app treats as not valid). For `delete-agent` the client compares the exact strings
`DELETE_AGENT_STATUS_DELETED`, `_NOT_FOUND` and `_DISABLED`, not just the suffix.

## 11. The implementation in this repository

`buzz-beekeeper` (`src/beekeeper/`, README "Agent service") implements sections 2-7: sign-in, binding with the
owner allowlist, the six beekeeper routes, key-backup enrollment and storage, and the onboarding routes. It
answers `nsec-backups/recovery` and `identity/assertions` with 404: it never opens backups, and a relay that does
not require NIP-FI needs no assertion. One sign-in callback is allowed by default, the mobile app's
`xyz.block.buzz.mobile:/auth/callback`. The sign-in page redirects there at once with only `code` and `state`,
because the app rejects a callback with any other query field.

Still open: whether the desktop app needs anything beyond the six beekeeper routes for the same agents.

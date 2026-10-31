# Patchriot Dispatcher
**Approve the scope. Coordinate the agents. Keep the evidence.**

The private Rust service that pairs devices, controls admission and assigns Patchriot's review roles.

> **DON'T TRUST! VERIFY!** Audit the implementation and test its permission boundaries. Use authorized penetration tests against your own deployment. Private source, signed results and model confidence do not establish security.

**Working today:** persistent onboarding and a bounded queue for three sequential checks of an owned example. Fixture and agent evidence use separate formats. The server supports renewable agent assignments; relay and website integration follow. Customer targets and paid admission are not enabled.

## Run locally

Keep `patchriot-core` beside this repository for the Apache-2.0 protocol crate. Use **Rust 1.94.1** and a dedicated **PostgreSQL 17** database.

| Private environment variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Dedicated PostgreSQL connection |
| `PATCHRIOT_INTERNAL_KEY` | Generated service secret, at least 32 bytes; shared with core |
| `PATCHRIOT_AUDIENCE` | Stable deployment identifier, e.g. `patchriot-local-v1` |
| `PATCHRIOT_BIND` | Optional listener; default `127.0.0.1:7411` |

```sh
cargo run --locked
```

Migrations are embedded. Use HTTPS or an authenticated tunnel outside loopback. Internal requests require the service secret plus account/role headers **constructed by core from its session**, never copied from a browser.

## Device lifecycle

**Pair → claim → manual approval → contribute → pause or revoke.**

Five-minute pairing codes are claimed once. Requests carry Ed25519 proofs binding the deployment, route, timestamp and typed payload. Persistent counters reject conflicting replays; exact heartbeat retries do not extend liveness. Devices become offline after 30 seconds without a fresh heartbeat. A revoked key cannot be reapproved.

Approval must assess an operator and their agent's security-review, reproduction and **authorized penetration-testing capabilities** before private customer work. Pairing alone proves only control of a key.

## Review workflow

```mermaid
flowchart LR
  Q[Admitted request] --> I[Investigator]
  I --> R[Reproducer]
  R --> C[Challenger / patch checks]
  C --> E[Private evidence]
```

The current scenario, `access_control_v1`, is an owned access-control bug and supplied fix. `owned_fixture` uses compiled original/patch/clean-control checks; `owned_agent` asks a declared agent runtime to inspect and test the example. Each mode goes only to its matching runtime. Three distinct approved devices run sequentially. Evidence is **operator-reported**, not independently re-executed or a customer audit.

| Bound | Fixture check | Agent check |
| --- | --- | --- |
| Active reviews, both modes combined | 3 per account, 30 overall | Same |
| Concurrent assignments | 1 per device and operator's declared compute group | Same |
| Assignment lease | 60 seconds, fixed | 60 seconds, renewable up to a fixed 10-minute deadline |
| Attempts | Up to 3 per role | Same |
| Review lifetime, including waiting/retries | 15 minutes | 35 minutes |

Renewal requires a signed, increasing sequence, a current assignment and fresh, unpaused presence. Duplicate renewals return the existing expiry and remaining time; they do not add time. Cancellation, expiry and revocation stop renewal. Clients must use a monotonic deadline and stop before losing the lease, including during a network outage.

All three checks must report the expected results to complete. Agent prose alone cannot pass: the result needs the original/fixed terminal observations, model-call count and confirmed cleanup. Missing or contradictory evidence produces **needs_review**. Cancellation and revocation reject late results; superseded attempts cannot complete replacements. Expiry is processed during polling and authorized queue reads. Shared-host/operator identities remain visible; model names and digests are declarations, not attestations.

## API map

| Route group | Caller |
| --- | --- |
| `POST /v1/pairings/{start,status}` | Signed device |
| `POST /v1/devices/:id/heartbeat` | Paired device |
| `POST /v1/devices/:id/work/{poll,renew,complete}` | Approved, opted-in device |
| `GET /v1/fleet` | Public aggregate counts |
| `POST /internal/pairings/claim` | Authenticated core account |
| `GET /internal/devices`; `POST /internal/devices/:id/decision` | Account/admin through core |
| `GET, POST /internal/reviews`; `GET /internal/reviews/:id`; `POST /internal/reviews/:id/cancel` | Requester/admin through core |

Creating a fixture review takes `{"request_id":"<uuid>","scenario":"access_control_v1"}`; add `"mode":"owned_agent"` for the agent path. Account/request ID deduplicates the request; changing its mode is rejected. Cancellation takes `{}`. Renewal takes `{"lease_id":"<uuid>","sequence":1}`. Existing fixture requests, assignments and saved results remain compatible. Exact completion retries are accepted once; changed replays are rejected. See [shared types](../patchriot-core/crates/protocol/src/lib.rs) and [review handling](src/reviews.rs).

## Boundaries that matter

- **Core owns accounts and money.** Dispatcher cannot create credit or choose rewards. Paid admission must use saved terms and consume funding events once; that integration follows.
- **Private access is checked on every read.** Assigned operators, service staff and approved providers can see assigned plaintext. No automatic publication of customer findings.
- **Scope is enforced in code.** Future website work must verify authority and restrict hosts, actions, rates and time. An agent or webpage cannot expand permissions.
- **Tools need a sandbox.** Source, hooks, installers and agent instructions are untrusted. Jev screening can flag problems; it cannot authorize access, remove isolation or move funds.
- **Evidence beats votes.** Future customer findings need independent reproduction and meaningful before/after patch tests. Missing evidence stays unresolved.

Google login and stronger patcher/admin authentication belong in core. Owned-site checks, customer artifacts and recurring checks follow the pilot. Recurring jobs must recheck scope, funds and capacity on every occurrence; missed runs must not create a burst.

## Verify it

Set `PATCHRIOT_TEST_DATABASE_URL` to a local test database whose role can create schemas.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
```

The PostgreSQL tests cover concurrent claims/polls, account isolation, replay, capacity, expiry, cancellation, revocation and conflicting evidence. Core's `scripts/smoke-reviews.py` adds real relay processes and a deliberately lost result reply.

Private core access in CI needs `PATCHRIOT_READ_TOKEN` with read-only access to core. No credential value belongs in source.

This repository is private initially while admission and review policy evolve; secrecy is not a security boundary. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

# Patchriot Dispatcher
**Approve the scope. Coordinate the agents. Keep the evidence.**

The private Rust service that pairs devices, controls admission and assigns Patchriot's review roles.

> **DON'T TRUST! VERIFY!** Audit the implementation and test its permission boundaries. Use authorized penetration tests against your own deployment. Private source, signed results and model confidence do not establish security.

**Working today:** persistent onboarding, owned example checks, approved website snapshots and explicitly shared offline agent reviews. Internal admission can hold an agreed review until core confirms payment. Reports separate tool observations from model claims. Core provides configurable browser checkout; active target testing is not enabled.

## Run locally

Keep `patchriot-core` beside this repository for the Apache-2.0 protocol crate. Use **Rust 1.94.1** and a dedicated **PostgreSQL 17** database.

| Private environment variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Dedicated PostgreSQL connection |
| `PATCHRIOT_INTERNAL_KEY` | Generated service secret, at least 32 bytes; shared with core |
| `PATCHRIOT_AUDIENCE` | Stable deployment identifier, e.g. `patchriot-local-v1` |
| `PATCHRIOT_BIND` | Optional listener; default `127.0.0.1:7411` |
| `PATCHRIOT_AGENT_ATTEMPT_SECONDS` | Optional agent limit: `600` by default, at most `1800` |

```sh
cargo run --locked
```

Migrations are embedded. Use HTTPS or an authenticated tunnel outside loopback. Internal requests require the service secret plus account/role headers **constructed by core from its session**, never copied from a browser.

<details>
<summary><strong>Run as a Linux service</strong></summary>

[deploy/patchriot-dispatcher.service](deploy/patchriot-dispatcher.service) runs as a dedicated `patchriot-dispatcher` user. Install a release built for the server's architecture at `/opt/patchriot/bin/patchriot-dispatcher`, owned by the administrator. Keep its private variables in `/etc/patchriot/dispatcher.env`, readable only by root; bind to loopback and start PostgreSQL first.

Install the unit in `/etc/systemd/system`, run `systemctl daemon-reload`, then `systemctl start patchriot-dispatcher`. Check `systemctl status patchriot-dispatcher` and `journalctl -u patchriot-dispatcher`; enable it at boot after testing. The unit bounds memory to 512 MiB and CPU to two cores, with a read-only system. Outbound DNS/HTTPS remains available for approved website collection; scope and destination checks still apply. SIGTERM stops admission and lets the collector finish within the 45-second service stop allowance.

</details>

## Device lifecycle

**Pair → claim → manual approval → contribute → pause or revoke.**

Five-minute pairing codes are claimed once. Requests carry Ed25519 proofs binding the deployment, route, timestamp and typed payload. Persistent counters reject conflicting replays; exact heartbeat retries do not extend liveness. Devices become offline after 30 seconds without a fresh heartbeat. A revoked key cannot be reapproved.

Approval must assess an operator and their agent's security-review, reproduction and **authorized penetration-testing capabilities** before private customer work. Pairing alone proves only control of a key.

The private device list includes `reports_received`, derived from completed leases with a saved result. A repeated delivery counts once; active, cancelled and expired assignments do not count. An accepted report can still contain incomplete or conflicting evidence. Counts are activity, not verified findings or earnings. Members receive counts only for their own devices; admins can see the fleet, without request contents in the list.

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
| Active reviews, including payment reservations | 3 per account, 30 overall | Same |
| Concurrent assignments | 1 per device and operator's declared compute group | Same |
| Assignment lease | 60 seconds, fixed | 60 seconds, renewable up to the saved attempt deadline (10 minutes by default) |
| Attempts | Up to 3 per role | Same |
| Review lifetime, including waiting/retries | 15 minutes | Three attempt budgets + 5 minutes; 35 minutes by default |

For a slow CPU pilot, `PATCHRIOT_AGENT_ATTEMPT_SECONDS=1800` permits 30 minutes per attempt and 95 minutes per review. The limit is saved at admission; changing configuration does not extend existing work or alter a paid reservation. Snapshot retention must cover payment waiting plus the full review. Operators must explicitly raise their relay limit too; their local cap can shorten an assignment.

Renewal requires a signed, increasing sequence, a current assignment and fresh, unpaused presence. Duplicate renewals return the existing expiry and remaining time; they do not add time. Cancellation, expiry and revocation stop renewal. Clients must use a monotonic deadline and stop before losing the lease, including during a network outage.

All three checks must report the expected results to complete. Agent prose alone cannot pass: the result needs the original/fixed terminal observations, model-call count and confirmed cleanup. Missing or contradictory evidence produces **needs_review**. Cancellation and revocation reject late results; superseded attempts cannot complete replacements. Expiry is processed during polling and authorized queue reads. Shared-host/operator identities remain visible; model names and digests are declarations, not attestations.

## API map

| Route group | Caller |
| --- | --- |
| `POST /v1/pairings/{start,status}` | Signed device |
| `POST /v1/devices/:id/heartbeat` | Paired device |
| `POST /v1/devices/:id/work/{poll,renew,complete}` | Approved, opted-in device |
| `POST /v1/devices/:id/work/evidence` | Selected device with a current private-review lease |
| `GET /v1/fleet` | Public aggregate counts |
| `POST /internal/pairings/claim` | Authenticated core account |
| `GET /internal/devices`; `POST /internal/devices/:id/decision` | Account/admin through core |
| `GET, POST /internal/reviews`; `GET /internal/reviews/:id`; `POST /internal/reviews/:id/cancel` | Requester/admin through core |
| `POST /internal/site-checks/:id/admit-review`; `POST /internal/reviews/:id/fund` | Core, acting as the paying requester |
| `GET, POST /internal/site-checks`; `GET /internal/site-checks/:id`; `POST /:id/cancel`; `GET /:id/evidence` | Requester/admin through core |
| `POST /internal/site-checks/:id/decision` | Admin through core |
| `GET /internal/site-checks/:id/compare/:baseline_id` | Requester/admin; both captures must be retained and share a requester and exact scope |
| `GET /internal/site-checks/:id/review-plan`; `POST /:id/review` | Plan: requester/admin; sharing consent: requester only |

Creating a fixture review takes `{"request_id":"<uuid>","scenario":"access_control_v1"}`; add `"mode":"owned_agent"` for the agent path. Account/request ID deduplicates the request; changing its mode is rejected. Cancellation takes `{}`. Renewal takes `{"lease_id":"<uuid>","sequence":1}`. Existing fixture requests, assignments and saved results remain compatible. Exact completion retries are accepted once; changed replays are rejected. See [shared types](../patchriot-core/crates/protocol/src/lib.rs) and [review handling](src/reviews.rs).

### Reserve work before payment

Core can call `admit-review` with the requester's `consent`, a server-selected `price` (`asset` and smallest-unit `amount` as strings), and `payment_expires_at` (UTC seconds, at most one hour ahead). The saved review binds that price to the exact snapshot and three selected devices. It occupies a queue slot in **awaiting_payment**; no agent receives the work or its evidence.

After recording a matching settlement, core calls `fund` with `request_id`, `invoice_id` and the saved `price`. The dispatcher rechecks the agents, consent and retained snapshot, then starts the review deadline using its saved time budget. Repeated delivery acknowledges the same activation; one invoice cannot fund two reviews. Cancellation, expiry or removed approval prevents activation. Core retains responsibility for customer balances and refunds when work cannot start.

These routes require the internal service credential and paying account. They do not accept a browser's payment claim or verify a blockchain transaction themselves. Core's configured paid mode restricts the free path and handles browser checkout, quote preparation and funding-event delivery. Refund execution remains separate.

## Boundaries that matter

### Website evidence collector

The [collector](src/websites) captures an approved HTTPS homepage and up to four directly referenced scripts. It saves body hashes, selected security headers, inline scripts and explicit reasons for skipped content. Submission records the requester's authority claim; an admin verifies permission and approves that exact immutable scope before collection. The web server runs the collection worker automatically.

Scope allows the homepage origin plus up to three exact script origins. Every DNS answer must contain only allowed public addresses; connections are pinned to that set with normal TLS verification. Redirects, proxies, credentials and compressed responses are refused. Limits are 30 seconds overall, 256 KiB for HTML, 512 KiB per external script, 2 MiB of saved HTTP bodies and 40 script references. Failed responses can consume network traffic without becoming saved evidence.

This is **a limited snapshot, not a browser audit or a safety verdict**. It does not execute JavaScript, follow imports, log in or discover every request a browser would make. External hashes cover the exact response bytes; inline hashes cover parsed script text, with the original HTML retained. Integrity attributes are recorded, not certified. Use network egress filtering as a second boundary before public deployment.

Account/request IDs deduplicate submissions; changed scope is rejected. The pilot allows two pending/active requests and three submissions per day per account, ten overall per day, and one collection at a time across dispatcher instances. Approval expires after ten minutes. A 45-second lease recovers one interrupted attempt; retries never extend approval. Cancellation and expiry reject late results. During collection the worker checks its lease every second; already sent requests may finish.

Raw evidence is readable for seven days, then removed by the worker's sweep. Downloads check both ownership and retention in the database. Scope, decisions, status and small summaries remain in history. Collection itself does not spend funds or send evidence to agents.

Capture comparisons read both retained snapshots under the caller's permissions in one database query. They compare saved body hashes, sizes, content types, selected headers and script-reference records. They return no raw bodies, perform no target requests and start no agent work. Different collection times and CDN addresses alone do not count as content changes. A resource present in only one capture may have been skipped in the other; inline scripts match by HTML position. The result is evidence to inspect, never a safety verdict.

### Private website reviews

`website_agent` runs `website_snapshot_v1` through the same bounded queue, with three extra gates:

1. An admin grants **private-work approval** to a Hermes device, with a recorded reason. Existing demo approvals do not qualify.
2. Its signed poll explicitly declares `website_reviews: true`. Older polls retain their signature format and receive only demo work.
3. The snapshot owner consents to three exact device IDs, ordered investigator/reproducer/challenger, and the saved snapshot SHA-256. Operator, model and compute-group declarations are recorded with consent.

Selection, admission and payment activation require a fresh work poll within 30 seconds or a current, unexpired assignment. Heartbeats alone and replayed polls do not renew work availability. A busy agent stays eligible while renewing its lease; a relay restarted in presence-only mode ages out of the selection list. After migration, idle devices need one fresh poll before selection; existing signed request formats are unchanged.

Roles stay pinned to those devices. No fallback operator receives the data. Only a live assigned lease can download the original snapshot and preceding reports; cancellation, expiry and revocation stop downloads and renewals. Paused or stale devices cannot read evidence. Removing private approval fails active reviews involving that device. Data already received cannot be recalled.

The relay reviews saved text without network access. Completion checks the snapshot binding, tool observation, bounded report and exact quotations. `evidence_complete` describes these checks; it does not certify security reasoning, exploitability or a proposed fix. Incomplete evidence stays `needs_review`. All three reports being complete is not a safety verdict or proof of independent operators. Reports can retain short quotations after raw-body retention ends.

### Access and execution

- **Core owns accounts and money.** Dispatcher cannot create credit or choose rewards. Paid admission uses saved terms and accepts each invoice once; only core can confirm settlement.
- **Private access is checked on every read.** Assigned operators, service staff and approved providers can see assigned plaintext. No automatic publication of customer findings.
- **Scope is enforced in code.** Website admission must verify authority before collection. An agent or webpage cannot expand approved hosts, actions, rates or time.
- **Tools need a sandbox.** Source, hooks, installers and agent instructions are untrusted. Jev screening can flag problems; it cannot authorize access, remove isolation or move funds.
- **Evidence beats votes.** Future customer findings need independent reproduction and meaningful before/after patch tests. Missing evidence stays unresolved.

Google login and stronger patcher/admin authentication belong in core. Broader customer artifacts and recurring checks follow. Recurring jobs must recheck scope, funds and capacity on every occurrence; missed runs must not create a burst.

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

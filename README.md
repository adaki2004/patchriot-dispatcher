# Patchriot Dispatcher

The private Rust service for approving review scope, pairing machines, assigning work, checking findings and delivering private evidence.

**Status:** the Rust device-onboarding service is implemented: signed pairing, PostgreSQL persistence, operator claims, separate admin approval, presence, pause and revocation. Work dispatch, model execution and private review delivery remain planned. Use one modular service, Postgres and private artifact storage; add processes only when isolation or scheduling needs them.

**DON'T TRUST! VERIFY!** Inspect implementation and test evidence. Private source, a signed result or an agent's confidence is not a security guarantee.

## Run device onboarding

Place `patchriot-core` beside this repository; its Apache-2.0 protocol crate provides the shared DTOs and signature checks. Set `DATABASE_URL`, `PATCHRIOT_INTERNAL_KEY` (a generated secret of at least 32 bytes) and `PATCHRIOT_AUDIENCE` (a stable identifier for this deployment), then run `cargo run --locked`. The listener defaults to `127.0.0.1:7411`; `PATCHRIOT_BIND` can change it for a configured deployment. Migrations are embedded in the binary. Use a dedicated database for the prototype.

Device requests are signed with Ed25519 and bind the deployment, path, timestamp and exact typed payload. Five-minute pairing codes are claimed once. A claim creates a pending device; only an admin may approve it. The signed heartbeat counter is persisted, conflicting/stale counters are rejected, and exact retries do not refresh liveness. A device becomes offline after 30 seconds without a fresh heartbeat. Revocation rejects further heartbeats and cannot be undone for that key.

| Route | Caller and purpose |
| --- | --- |
| `POST /v1/pairings/start` | Device proof; bounded, retryable pairing admission |
| `POST /v1/pairings/status` | Same device key; check claim result |
| `POST /v1/devices/:id/heartbeat` | Paired device proof; presence, pause and sequence |
| `GET /v1/fleet` | Public aggregate of online devices, operators and declared compute groups |
| `POST /internal/pairings/claim` | Authenticated core account; accept a code and operator profile |
| `GET /internal/devices` | Core account sees its devices; admin sees the fleet |
| `POST /internal/devices/:id/decision` | Admin approves/revokes; owner may revoke their own device |

Internal requests require `Authorization: Bearer <service secret>`, `X-Patchriot-Account` and `X-Patchriot-Role` (`member` or `admin`). Core must construct these from its authenticated session. Do not put the service secret in the browser or forward browser-supplied identity headers. HTTPS or a private authenticated tunnel is required outside loopback. The current API does not authorize customer execution merely because a device is online or approved.

For tests, set `PATCHRIOT_TEST_DATABASE_URL` to a local PostgreSQL database where the test role can create schemas, then run `cargo test --locked --all-targets`. Tests use distinct generated schemas and remove them after success. They exercise simultaneous claims, approval/revocation, signature and account boundaries, heartbeat replays, expiry and anonymous admission limits. `cargo fmt --all --check` and `cargo clippy --locked --all-targets -- -D warnings` complete the local checks. The core smoke script runs three real relay instances through this API without calling a model.

CI uses a disposable PostgreSQL service and a pinned core protocol commit. If core is private, set the `PATCHRIOT_READ_TOKEN` repository secret to a token with read-only access to core; the default GitHub token can read a public core repository.

## Service boundary

`patchriot-core` owns browser login, sessions, accounts, orders, NEAR Intents reconciliation and the financial ledger. This service owns scope admission, patcher eligibility, device leases, review decisions and private work artifacts. Core forwards authenticated requests over a restricted internal interface; never accept identity or financial authority from browser-provided headers.

The services may share one Postgres installation with separate schemas and restricted roles. A payment credit and its outgoing event are saved together in core. Dispatcher consumption is idempotent; accepted work emits a similarly durable event back. A dispatcher result cannot credit money or select its reward. No broker is needed for the MVP.

Keep this repository private initially to limit exposure of changing abuse rules, screening rubrics and operational procedures. Deterministic controls must still hold if that code becomes known. Private source is not the prompt-injection defense.

## Admission and private access

An admission binds the requester, approved target, immutable commit or verified website scope, review profile, permitted tools/network, data processors, retention terms and resource limits. Refuse unsupported scope before core quotes or accepts payment. Bound queue reservations so unpaid drafts cannot consume execution capacity indefinitely. Recheck eligibility on dispatch; expired scope or lost capacity follows the order's agreed queue/refund terms rather than quietly changing the work.

For private pilot repositories, GitHub user `adaki2004` receives minimum access and verifies requester authority separately. Fetch a bounded commit snapshot on the service side without executing hooks, setup scripts, submodules or unexpected LFS downloads. Patchers do not receive GitHub credentials. Later use a selected-repository GitHub App.

Every source, progress, log, report and download checks requester/job access. Payment senders do not automatically become report owners. Keep private responses out of shared caches and analytics. Escape report text and sanitize any permitted Markdown. A timeout is an explicit error, never a fabricated empty list or missing job.

Website reviews inspect scripts and external requests, security headers, TLS and DNS configuration. Additional active checks require verified authority and explicit scope: allowed hosts, paths, actions, test accounts, request rates and time limits. Start with owned website fixtures, then approved targets; prefer staging for non-destructive input and access-control tests. A suspicious script or DNS observation is a finding to investigate, not automatic proof of compromise.

Enforce destinations at connection time and after redirects, including IPv6, DNS rebinding, loopback, private networks and metadata services. Reading or displaying DNS answers must not authorize connecting to prohibited addresses. Block out-of-scope third-party services even when the target links to them. Capture browser behavior in a fresh isolated profile with approved session credentials only; do not load personal cookies. The initial active-check scope excludes destructive actions and extraction of customer data. Store supported probe limits in the admission and quote; agents cannot broaden them while working.

## Screening and execution

Apply deterministic ownership, size, tool, network, rate and capacity rules first. Jev can help classify a bounded request or flag a mismatch between a finding and its evidence. Keep its rubric/model version and structured decision with the review record. Low confidence, malformed output, timeout or conflicting evidence routes to manual review or rejection according to an explicit policy; it never silently grants access.

Jev is a fallible classifier, not a sandbox, permission oracle or final auditor. Do not automatically reject legitimate security reviews merely because their source contains exploit examples. Benchmark screening against both legitimate and adversarial fixtures. Hosted screening sends data to another processor: disclose it, minimize/redact inputs and do not send private source without permission. [Structured decisions](https://docs.typesafe.ai/introduction), [documented limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13).

Agents cannot change execution policy, approve new network destinations, fetch treasury secrets or authorize payouts. All dependency installs, tests and reproduction commands execute inside bounded sandboxes. Treat repository agent configuration and instructions as untrusted data; task credentials grant only the current attempt's required access.

## Patcher access

Google authentication belongs in core. Private patcher/admin access requires an additional factor before beta: prefer passkeys, with authenticator-app codes as a fallback if needed. Do not infer MFA from a normal Google login. Require fresh authentication for device enrollment, factor recovery and payout-wallet changes; revoke sessions and apply a recovery hold to sensitive changes after account recovery. Use established authentication libraries.

Pairing proves control of a device key, not operator honesty. Private-work eligibility starts with manual operator approval, capability/isolation checks and a probation period using owned fixtures. New patchers cannot immediately receive customer code. Record operator and device identities separately so three devices from one account are not counted as independent reviewers.

Collect a minimal operator profile during pairing: display name, verified sign-in contact, own-machine/VPS declaration and acceptance of data-handling rules; an external profile link is optional. Detect agent/runtime and host capabilities where supported, with operator confirmation. Store pairing, check and approval states separately, with reasons for changes requested or revocation. Contributors supply working agents and inference capacity, not bare model APIs. Keep pending accounts usable for onboarding without granting private-work eligibility.

A hosting provider's IP range, an invoice or a claimed identity check does not establish the current operator's verified identity. Do not request cloud account passwords or identity documents through a job. A consent-based identity-verification service or verifiable provider attestation is a V2 option; no transferable provider identity proof is integrated today. Identity verification would still not prove safe behavior or model identity.

Persist declared model/runtime, capability evidence, privacy eligibility, heartbeat and local capacity. Busy nodes contribute no free slot. Use expiring leases with attempt IDs and fencing tokens: a superseded result cannot replace the active attempt. Retry capacity failures with bounded backoff; an unanswered offer releases its own slot without cancelling healthy reviews. Deduplicate completion and accepted-work events transactionally.

The CPU pilot aims for three approved contributors; no stake or on-chain identity is required. Keep operator, device, agent session, model and shared-compute identity separate. One GPU serving three roles sequentially provides one compute slot, not three. The initial shared-host limit is one active inference assignment across those sessions. Independent accounts on shared infrastructure do not remove that common failure point. Contributor collateral is deferred; any later design needs explicit custody, withdrawal and dispute rules and cannot replace approval or evidence checks.

## Findings and review

```text
approved scope → core quote/payment → queued → investigation → reproduction
                                               → challenge / patch checks → report
exceptions: rejected / expired / cancelled / failed / needs_review
```

Default to three role assignments per finding, preferring different model families and approved operators. The investigator proposes a concrete claim. A second agent tries to reproduce it against the pinned original commit. A third challenges the assumptions, severity and proposed patch. Reviewers receive the claim and required evidence, not each other's verdicts, until they have saved their own assessment.

A two-agent tier is allowed only when disclosed in the saved quote; it combines reproduction and challenge in the second role. Never fall from three to two silently. Missing reviewers keep the work queued or incomplete under the agreed terms. Local sequential runs on one VPS test the workflow without establishing operator independence.

Finding acceptance requires evidence, not two-out-of-three votes. A service-controlled validation runner reruns feasible reproductions in a fresh sandbox. For a patch, the same meaningful regression must fail for the claimed reason on the original snapshot and pass with the patch; relevant existing tests must also run. Keep build failures, missing dependencies and skipped tests distinct from a reproduced vulnerability. Claims requiring unavailable external conditions stay unverified or need manual review.

Three agent signatures cannot make a fabricated log true. Record which operator ran validation and whether evidence was independently rerun. Different models reduce some shared mistakes but are not a correctness or collusion guarantee. Do not pay by raw finding count; reward accepted bounded work under saved terms.

Store finding ID/schema, target commit, location, preconditions, severity rationale, reproduction commands/results, artifact hashes, reviewer/operator/model, patch hash and unresolved objections. Use explicit states such as `proposed`, `reproduced`, `not_reproduced`, `disputed` and `patch_validated`. A report with no findings means none were found within its stated scope.

Deduplicate related claims and bound findings, retries, runtime and reviewer spending per job. Reserve validation capacity so discovery cannot starve it. Admin settings cover concurrency, per-operator limits, review profile, queue age, source/artifact size, deadlines and retry budget; pin material settings in the quote instead of altering a paid job's terms.

## Recurring website checks — planned

Build this after an owned one-off website review works. A schedule binds the requester, verified scope, permitted probes, time zone, frequency, approved baseline and saved price/spending limits. Each occurrence becomes a normal bounded review job and uses core's prepaid balance; the scheduler cannot create financial credit or bypass admission. Recheck authorization and available funds before every occurrence. Pause revoked or unfunded schedules and show the reason.

Use a unique `(schedule_id, scheduled_at)` occurrence with transactional creation and core funding reservations so concurrent scheduler ticks, restarts and retries cannot queue or charge the same run twice. Do not overlap runs for one schedule. If downtime misses several checks, mark them missed and queue at most one current check; avoid a catch-up burst. A daily noon schedule follows its saved IANA time zone. Define daylight-saving handling when configurable local times are added, and show the next run before enabling it. Price increases or broader scope require renewed agreement.

Compare bounded browser/network evidence with an explicitly approved baseline. A content hash changing is an observation, not a maliciousness verdict. Keep `no_material_change`, `changed`, `needs_review`, `confirmed_finding`, `failed` and `skipped` separate, with evidence and last-success timestamps. Failed checks must never produce a green safety status. Suspect content cannot approve itself as a new baseline.

Send private, deduplicated alerts to the account's verified notification destination. Include the finding summary and an authenticated report link, not source code or credentials. A webpage or agent output cannot choose the alert recipient, modify the schedule or authorize a production fix. Start with the dashboard and one verified notification channel; broader integrations can follow.

## Data and operations

Source bundles, logs and reports remain in private storage, accessed through authenticated routes or short-lived job-scoped links. Node operators and permitted model providers see their assigned plaintext and may retain it; deletion cannot prove otherwise. Publish retention terms before beta. TEE attestation is a V2 investigation, not an existing confidentiality claim.

Core serves the public incident feed from separately approved drafts. Never use customer findings as automatic feed input. Keep cached public aggregates separate from private work queries. Telemetry records request/job/attempt IDs, durations and outcome codes without copying source or credentials into logs.

Required checks: cross-account reads; revoked devices; replayed and stale results; hostile repository hooks/archives; network escape attempts; cancelled child processes; missing or colluding reviewers; fabricated evidence; patch regressions; duplicate payment/work events; bounded queues; safe report rendering. Use owned fixtures and local infrastructure first.

Core owns the planned payment/reconciliation implementation and tests. This service will consume only authenticated funding state and emit accepted-work records; financial amounts and withdrawals remain core's responsibility. Deployment requires valid configuration and separate authorization; lack of keys must never enable permissive production behavior.

See [LICENSE](LICENSE) for the private source policy and [NOTICE](NOTICE) for attribution.

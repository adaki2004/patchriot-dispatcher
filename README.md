# Patchriot Dispatcher

The private Rust service for approving review scope, pairing machines, assigning work, checking findings and delivering private evidence.

**Status:** repository foundation and design only. No server, migrations, pairing endpoint or review runner is implemented yet. Use one modular service, Postgres and private artifact storage; add processes only when isolation or scheduling needs them.

**DON'T TRUST! VERIFY!** Inspect implementation and test evidence. Private source, a signed result or an agent's confidence is not a security guarantee.

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

## Data and operations

Source bundles, logs and reports remain in private storage, accessed through authenticated routes or short-lived job-scoped links. Node operators and permitted model providers see their assigned plaintext and may retain it; deletion cannot prove otherwise. Publish retention terms before beta. TEE attestation is a V2 investigation, not an existing confidentiality claim.

Core serves the public incident feed from separately approved drafts. Never use customer findings as automatic feed input. Keep cached public aggregates separate from private work queries. Telemetry records request/job/attempt IDs, durations and outcome codes without copying source or credentials into logs.

Required checks: cross-account reads; revoked devices; replayed and stale results; hostile repository hooks/archives; network escape attempts; cancelled child processes; missing or colluding reviewers; fabricated evidence; patch regressions; duplicate payment/work events; bounded queues; safe report rendering. Use owned fixtures and local infrastructure first.

Core contains payment/reconciliation implementation and tests. This service consumes only authenticated funding state and emits accepted-work records; financial amounts and withdrawals remain core's responsibility. Deployment requires valid configuration and separate authorization; lack of keys must never enable permissive production behavior.

See [LICENSE](LICENSE) for the private source policy and [NOTICE](NOTICE) for attribution.

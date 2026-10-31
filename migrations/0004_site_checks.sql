-- Approved, read-only website snapshots. This path does not authorize agent
-- tools, charge an account or label a site safe. Scope is immutable after creation.
CREATE TABLE site_checks (
    id UUID PRIMARY KEY,
    requester_id UUID NOT NULL,
    request_id UUID NOT NULL,
    scope JSONB NOT NULL,
    scope_sha256 TEXT NOT NULL CHECK (length(scope_sha256) = 64),
    authority_note TEXT NOT NULL CHECK (length(authority_note) BETWEEN 12 AND 1200),
    state TEXT NOT NULL DEFAULT 'pending_approval'
        CHECK (state IN ('pending_approval','queued','collecting','collected','failed','rejected','cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '24 hours',
    decided_by UUID,
    decision_note TEXT,
    decision_action TEXT CHECK (decision_action IN ('approve','reject')),
    decided_at TIMESTAMPTZ,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 2),
    lease_id UUID,
    lease_expires_at TIMESTAMPTZ,
    error TEXT,
    summary JSONB,
    snapshot JSONB,
    evidence_expires_at TIMESTAMPTZ,
    UNIQUE (requester_id, request_id),
    CHECK ((state = 'collecting') = (lease_id IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK (snapshot IS NULL OR state = 'collected'),
    CHECK (snapshot IS NULL OR evidence_expires_at IS NOT NULL),
    CHECK (snapshot IS NULL OR octet_length(snapshot::text) <= 5242880)
);
CREATE INDEX site_check_owner ON site_checks(requester_id, created_at DESC);
CREATE INDEX site_check_queue ON site_checks(created_at) WHERE state = 'queued';
CREATE INDEX site_check_expiry ON site_checks(evidence_expires_at) WHERE snapshot IS NOT NULL;

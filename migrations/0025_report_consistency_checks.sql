-- One explicitly requested advisory check per report. A lost completion reply
-- is not permission to spend again. Private payloads share report retention.
CREATE TABLE report_consistency_checks (
    review_id UUID PRIMARY KEY REFERENCES reviews(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    state TEXT NOT NULL CHECK (state IN ('queued','running','verified','unavailable','deleted')),
    input JSONB,
    input_sha256 TEXT NOT NULL,
    claim_id UUID,
    claim_until TIMESTAMPTZ,
    checked_at TIMESTAMPTZ,
    result JSONB,
    error_code TEXT,
    CHECK ((state='running') = (claim_id IS NOT NULL AND claim_until IS NOT NULL)),
    CHECK (state <> 'verified' OR result IS NOT NULL),
    CHECK (state <> 'deleted' OR (input IS NULL AND result IS NULL))
);
CREATE INDEX report_consistency_checks_queue ON report_consistency_checks(requested_at)
    WHERE state IN ('queued','running');

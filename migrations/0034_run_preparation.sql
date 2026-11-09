-- Final confirmation, bounded screening and relay-only perimeter access.
CREATE TABLE pentest_preparations (
    requester_id UUID NOT NULL,
    request_id UUID NOT NULL,
    pentest_id UUID NOT NULL REFERENCES pentests(id) ON DELETE CASCADE,
    scope_sha256 TEXT NOT NULL,
    consent_sha256 TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    terms_version TEXT NOT NULL,
    screening_policy TEXT NOT NULL DEFAULT 'live-context-v1',
    testing_context TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('screening','accepted','rejected','unavailable')),
    gate_ciphertext BYTEA,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(requester_id,request_id)
);
CREATE INDEX pentest_preparation_rate ON pentest_preparations(requester_id,created_at);

ALTER TABLE devices DROP CONSTRAINT devices_live_tools_check;
ALTER TABLE devices ADD CONSTRAINT devices_live_tools_check
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 10);

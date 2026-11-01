-- Source remains JSON data in private storage; filenames are never extracted.
CREATE TABLE source_uploads (
    id UUID PRIMARY KEY,
    requester_id UUID NOT NULL,
    request_id UUID NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    title TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
    objective TEXT NOT NULL CHECK (length(objective) BETWEEN 1 AND 1200),
    permission_note TEXT NOT NULL CHECK (length(permission_note) BETWEEN 1 AND 1500),
    state TEXT NOT NULL DEFAULT 'pending_approval' CHECK (state IN ('pending_approval','approved','rejected','deleted','expired')),
    bundle_sha256 TEXT NOT NULL CHECK (length(bundle_sha256) = 64),
    manifest JSONB NOT NULL,
    bundle JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '7 days',
    decided_by UUID,
    decision_note TEXT,
    decided_at TIMESTAMPTZ,
    UNIQUE (requester_id, request_id),
    CHECK ((state IN ('pending_approval','approved')) = (bundle IS NOT NULL)),
    CHECK (bundle IS NULL OR octet_length(bundle::text) <= 393216),
    CHECK (octet_length(manifest::text) <= 16384)
);
CREATE INDEX source_uploads_owner ON source_uploads (requester_id, created_at DESC);
CREATE INDEX source_uploads_expiry ON source_uploads (expires_at) WHERE bundle IS NOT NULL;
ALTER TABLE devices ADD COLUMN source_reviews BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE reviews DROP CONSTRAINT reviews_scenario_check;
ALTER TABLE reviews ADD CONSTRAINT reviews_scenario_check CHECK (scenario IN ('access_control_v1','website_snapshot_v1','source_bundle_v1'));
ALTER TABLE reviews DROP CONSTRAINT reviews_mode_check;
ALTER TABLE reviews ADD CONSTRAINT reviews_mode_check CHECK (mode IN ('owned_fixture','owned_agent','website_agent','source_agent'));
ALTER TABLE reviews ADD COLUMN source_id UUID REFERENCES source_uploads(id);
ALTER TABLE reviews ADD COLUMN source_context JSONB;
ALTER TABLE reviews ADD CONSTRAINT source_review_shape CHECK (
    (mode = 'source_agent') = (scenario = 'source_bundle_v1')
    AND (mode = 'source_agent') = (source_id IS NOT NULL AND source_context IS NOT NULL AND consent_at IS NOT NULL)
    AND (mode = 'source_agent' OR (source_id IS NULL AND source_context IS NULL))
);
CREATE INDEX reviews_source ON reviews (source_id) WHERE source_id IS NOT NULL;
ALTER TABLE reviews DROP CONSTRAINT reviews_payment_shape;
ALTER TABLE reviews ADD CONSTRAINT reviews_payment_shape CHECK (
    (payment_terms IS NULL AND payment_expires_at IS NULL AND funded_invoice_id IS NULL AND funded_at IS NULL AND state <> 'awaiting_payment')
    OR
    (mode IN ('website_agent','source_agent') AND payment_terms IS NOT NULL AND payment_expires_at IS NOT NULL AND
        ((funded_invoice_id IS NULL AND funded_at IS NULL AND state IN ('awaiting_payment','failed','cancelled'))
        OR (funded_invoice_id IS NOT NULL AND funded_at IS NOT NULL AND state <> 'awaiting_payment')))
);

-- Old submissions never opt into external processing retroactively.
ALTER TABLE site_checks
    ADD COLUMN screening_state TEXT NOT NULL DEFAULT 'not_requested'
        CHECK (screening_state IN ('not_requested','queued','running','complete','unavailable','cancelled')),
    ADD COLUMN screening JSONB,
    ADD COLUMN screening_attempts INTEGER NOT NULL DEFAULT 0 CHECK (screening_attempts BETWEEN 0 AND 2),
    ADD COLUMN screening_claim UUID,
    ADD COLUMN screening_until TIMESTAMPTZ,
    ADD CONSTRAINT screening_claim_state CHECK ((screening_state = 'running') = (screening_claim IS NOT NULL AND screening_until IS NOT NULL)),
    ADD CONSTRAINT screening_result_state CHECK ((screening_state = 'complete') = (screening IS NOT NULL)),
    ADD CONSTRAINT screening_result_size CHECK (screening IS NULL OR octet_length(screening::text) <= 4096);
CREATE INDEX site_screening_queue ON site_checks(created_at) WHERE screening_state IN ('queued','running');

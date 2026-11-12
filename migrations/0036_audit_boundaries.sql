-- Runtime claims never create approval. Existing devices start unapproved here;
-- staff must check each runtime before re-enabling private paid work.
ALTER TABLE devices ADD COLUMN approved_capabilities JSONB NOT NULL DEFAULT '{"website_reviews":false,"source_reviews":false,"live_tests":false,"live_tools":[]}' CHECK (jsonb_typeof(approved_capabilities)='object');
ALTER TABLE device_events ADD COLUMN capabilities JSONB;
ALTER TABLE device_events DROP CONSTRAINT device_events_action_check;
ALTER TABLE device_events ADD CHECK (action IN ('paired','approved','revoked','private_approved','private_revoked','capabilities_approved'));

-- The nonce is consumed in the same transaction as evidence authorization.
-- Keep it past the entire signature validity window, including clock skew.
CREATE TABLE evidence_read_nonces (
    device_id UUID NOT NULL REFERENCES devices(id),
    nonce UUID NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(device_id,nonce)
);
CREATE INDEX evidence_read_nonces_expiry ON evidence_read_nonces(expires_at);

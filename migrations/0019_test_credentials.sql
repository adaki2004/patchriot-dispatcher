-- One immutable, encrypted test account per scope. Plaintext never enters a
-- review, event, audit record or worker assignment stored in the database.
CREATE TABLE pentest_credentials (
    pentest_id uuid PRIMARY KEY REFERENCES pentests(id) ON DELETE CASCADE,
    ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 28 AND 8192),
    expires_at timestamptz NOT NULL
);
CREATE INDEX pentest_credentials_expiry ON pentest_credentials(expires_at);

-- A new runner can advertise the engine, POST support and test-account support.
-- Older one-capability polls and their signed bytes remain valid.
ALTER TABLE devices DROP CONSTRAINT devices_live_tools_check;
ALTER TABLE devices ADD CONSTRAINT devices_live_tools_check
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 3);

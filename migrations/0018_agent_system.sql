-- Software details arrive in signed heartbeats, including for already paired agents.
-- This contains no hostname, address, credentials or machine identifier.
ALTER TABLE devices ADD COLUMN system_info jsonb;

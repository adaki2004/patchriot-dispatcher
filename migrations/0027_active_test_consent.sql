-- Keep legacy test-environment scopes supported while upgraded agents also
-- advertise explicit production-risk consent. Existing scopes are unchanged.
ALTER TABLE devices DROP CONSTRAINT devices_live_tools_check;
ALTER TABLE devices ADD CONSTRAINT devices_live_tools_check
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 6);

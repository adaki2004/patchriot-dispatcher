-- Workers advertise deep checks separately so older adapters cannot receive
-- requests that selected them. Existing capabilities and saved scopes remain.
ALTER TABLE devices DROP CONSTRAINT devices_live_tools_check;
ALTER TABLE devices ADD CONSTRAINT devices_live_tools_check
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 11);

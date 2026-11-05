-- A separate capability prevents HTTP-only agents from accepting browser login.
-- No existing scope, credential or payment record changes.
ALTER TABLE devices DROP CONSTRAINT devices_live_tools_check;
ALTER TABLE devices ADD CONSTRAINT devices_live_tools_check
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 8);

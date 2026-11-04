-- Adapter 10 adds session login alongside the three existing capabilities.
-- Existing devices keep their advertised capabilities and cannot take this work.
ALTER TABLE devices DROP CONSTRAINT devices_live_tools_check;
ALTER TABLE devices ADD CONSTRAINT devices_live_tools_check
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 4);

-- A fresh signed work poll advertises only the optional tools installed in
-- the relay's pinned image. Old relays support the baseline only.
ALTER TABLE devices ADD COLUMN live_tools JSONB NOT NULL DEFAULT '[]'::jsonb
    CHECK (jsonb_typeof(live_tools) = 'array' AND jsonb_array_length(live_tools) <= 1);

-- Presence alone does not mean a relay is still accepting work. Existing
-- idle devices become eligible again on their next fresh, signed work poll.
ALTER TABLE devices ADD COLUMN work_polled_at TIMESTAMPTZ;

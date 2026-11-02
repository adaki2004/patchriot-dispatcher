-- One small snapshot per lease. A replacement lease starts with no activity.
-- Private review access rules apply; no target text is accepted here.
ALTER TABLE work_leases ADD COLUMN live_progress JSONB;

-- Private fleet lists count received reports without scanning unrelated history.
-- Counts are derived; completion retries cannot increment a separate counter.
CREATE INDEX work_leases_received_reports_device ON work_leases (device_id)
WHERE state = 'completed' AND result_hash IS NOT NULL;

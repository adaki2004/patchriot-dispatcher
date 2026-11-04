-- Only an explicit requester export starts this clock. Existing reports have
-- no deadline until that happens; ordinary reads and staff exports do not.
ALTER TABLE reviews ADD COLUMN first_downloaded_at TIMESTAMPTZ;
ALTER TABLE reviews ADD COLUMN report_expires_at TIMESTAMPTZ;
ALTER TABLE reviews ADD COLUMN report_purged_at TIMESTAMPTZ;
ALTER TABLE reviews ADD CONSTRAINT report_retention_shape CHECK (
    (first_downloaded_at IS NULL AND report_expires_at IS NULL AND report_purged_at IS NULL)
    OR (first_downloaded_at IS NOT NULL AND report_expires_at IS NOT NULL
        AND report_expires_at = first_downloaded_at + interval '12 hours'
        AND (report_purged_at IS NULL OR report_purged_at >= report_expires_at))
);
CREATE INDEX reviews_due_report_cleanup ON reviews(report_expires_at)
WHERE report_expires_at IS NOT NULL AND report_purged_at IS NULL;
-- Payment accounting retains who worked and its bounded execution totals,
-- never findings, response text or tool transcripts.
ALTER TABLE review_steps ADD COLUMN work_receipt JSONB
CHECK (work_receipt IS NULL OR octet_length(work_receipt::text) <= 4096);

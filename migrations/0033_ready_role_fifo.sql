-- Roles enter FIFO when funded and their predecessors have returned.
ALTER TABLE review_steps ADD COLUMN ready_at TIMESTAMPTZ;
UPDATE review_steps s SET ready_at=CASE WHEN s.position=0 THEN COALESCE(r.funded_at,r.created_at) ELSE now() END
FROM reviews r WHERE r.id=s.review_id AND r.state IN ('queued','running') AND s.state='queued'
AND NOT EXISTS(SELECT 1 FROM review_steps previous WHERE previous.review_id=s.review_id AND previous.position<s.position AND previous.state<>'completed');
CREATE INDEX review_steps_ready_fifo ON review_steps(ready_at) WHERE state='queued' AND ready_at IS NOT NULL;

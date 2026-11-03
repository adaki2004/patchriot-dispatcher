-- Allow explicitly configured one-hour attempts. Existing reservations retain
-- their saved allowance and deadlines; deployment defaults do not rewrite them.
ALTER TABLE reviews DROP CONSTRAINT reviews_agent_attempt_seconds_check;
ALTER TABLE reviews ADD CONSTRAINT reviews_agent_attempt_seconds_check
    CHECK (agent_attempt_seconds BETWEEN 600 AND 3600);

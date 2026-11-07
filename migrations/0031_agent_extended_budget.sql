-- Expand explicit operator allowances without changing saved reservations.
ALTER TABLE reviews DROP CONSTRAINT reviews_agent_attempt_seconds_check;
ALTER TABLE reviews ADD CONSTRAINT reviews_agent_attempt_seconds_check
    CHECK (agent_attempt_seconds BETWEEN 600 AND 10800);

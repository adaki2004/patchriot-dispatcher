-- Persist the admitted limit: changing deployment settings must not extend an
-- existing attempt or change a paid reservation after it was quoted.
ALTER TABLE reviews ADD COLUMN agent_attempt_seconds INTEGER NOT NULL DEFAULT 600
    CHECK (agent_attempt_seconds BETWEEN 600 AND 1800);

-- Keep existing fixture requests and results readable. Agent checks use the same
-- owned example, with renewable leases and a separate evidence format.
ALTER TABLE reviews ADD COLUMN mode TEXT NOT NULL DEFAULT 'owned_fixture'
    CHECK (mode IN ('owned_fixture', 'owned_agent'));

ALTER TABLE work_leases ADD COLUMN deadline_at TIMESTAMPTZ;
UPDATE work_leases SET deadline_at = expires_at;
ALTER TABLE work_leases ALTER COLUMN deadline_at SET NOT NULL;
ALTER TABLE work_leases ADD COLUMN renewal_sequence BIGINT NOT NULL DEFAULT 0
    CHECK (renewal_sequence >= 0);

-- Operators choose their own group names. A name must not reserve another
-- operator's machine or make unrelated hosts appear to share one slot.
DROP INDEX one_active_lease_per_compute_group;
CREATE UNIQUE INDEX one_active_lease_per_compute_group
    ON work_leases(operator_id, compute_group) WHERE state = 'active';

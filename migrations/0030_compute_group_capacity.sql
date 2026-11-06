-- Host capacity is configured by the operator of the dispatcher/gateway.
-- Counting and creating leases share the scheduler's transaction advisory lock.
-- Per-device and per-step unique indexes still prevent double assignments.
DROP INDEX one_active_lease_per_compute_group;
CREATE INDEX active_leases_per_compute_group
    ON work_leases(operator_id, compute_group) WHERE state = 'active';

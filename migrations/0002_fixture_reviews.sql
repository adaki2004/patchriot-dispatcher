-- Prototype-only queue: no URLs, repository snapshots or remote commands.
CREATE TABLE reviews (
    id UUID PRIMARY KEY,
    requester_id UUID NOT NULL,
    request_id UUID NOT NULL,
    scenario TEXT NOT NULL CHECK (scenario = 'access_control_v1'),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','running','completed','needs_review','failed','cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deadline_at TIMESTAMPTZ NOT NULL DEFAULT now() + interval '15 minutes',
    UNIQUE (requester_id, request_id)
);
CREATE INDEX reviews_requester_created ON reviews (requester_id, created_at DESC);

CREATE TABLE review_steps (
    id UUID PRIMARY KEY,
    review_id UUID NOT NULL REFERENCES reviews(id),
    role TEXT NOT NULL CHECK (role IN ('investigator','reproducer','challenger')),
    position SMALLINT NOT NULL CHECK (position BETWEEN 0 AND 2),
    state TEXT NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','leased','completed','failed','cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    current_lease_id UUID,
    result JSONB,
    fixture_matches BOOLEAN,
    UNIQUE (review_id, role),
    UNIQUE (review_id, position)
);

CREATE TABLE work_leases (
    id UUID PRIMARY KEY,
    step_id UUID NOT NULL REFERENCES review_steps(id),
    device_id UUID NOT NULL REFERENCES devices(id),
    operator_id UUID NOT NULL,
    compute_group TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active','completed','expired','cancelled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    result_hash TEXT,
    fixture_matches BOOLEAN
);
ALTER TABLE review_steps ADD CONSTRAINT review_steps_lease FOREIGN KEY (current_lease_id) REFERENCES work_leases(id);
CREATE UNIQUE INDEX one_active_lease_per_device ON work_leases(device_id) WHERE state = 'active';
CREATE UNIQUE INDEX one_active_lease_per_step ON work_leases(step_id) WHERE state = 'active';
CREATE UNIQUE INDEX one_active_lease_per_compute_group ON work_leases(compute_group) WHERE state = 'active';
CREATE INDEX work_leases_expiry ON work_leases(expires_at) WHERE state = 'active';

ALTER TABLE devices ADD COLUMN work_sequence BIGINT NOT NULL DEFAULT 0 CHECK (work_sequence >= 0);
ALTER TABLE devices ADD COLUMN work_reply JSONB;

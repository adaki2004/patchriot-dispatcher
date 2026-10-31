CREATE TABLE operators (
    id UUID PRIMARY KEY,
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 80),
    hosting TEXT NOT NULL CHECK (hosting IN ('own_machine', 'vps')),
    accepted_rules_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id UUID PRIMARY KEY,
    operator_id UUID NOT NULL REFERENCES operators(id),
    public_key TEXT NOT NULL UNIQUE CHECK (length(public_key) = 64),
    introduction JSONB NOT NULL,
    approval TEXT NOT NULL DEFAULT 'pending' CHECK (approval IN ('pending', 'approved', 'revoked')),
    approval_reason TEXT,
    approved_by UUID,
    last_seen_at TIMESTAMPTZ,
    sequence BIGINT NOT NULL DEFAULT 0 CHECK (sequence >= 0),
    last_payload_hash TEXT,
    paused BOOLEAN NOT NULL DEFAULT false,
    running SMALLINT NOT NULL DEFAULT 0 CHECK (running BETWEEN 0 AND 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX devices_operator_id ON devices(operator_id);

CREATE TABLE pairings (
    id UUID PRIMARY KEY,
    public_key TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    introduction JSONB NOT NULL,
    introduction_hash TEXT NOT NULL,
    device_id UUID REFERENCES devices(id),
    claimed_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK ((device_id IS NULL) = (claimed_by IS NULL))
);
CREATE INDEX pairings_created_at ON pairings(created_at);
CREATE INDEX pairings_expiry ON pairings(expires_at);

CREATE TABLE device_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id),
    actor_id UUID NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('paired', 'approved', 'revoked')),
    reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Each immutable live-test scope needs its own DNS proof. Existing permissions
-- are not grandfathered into live testing without domain verification.
ALTER TABLE pentests ADD COLUMN ownership_verified_at TIMESTAMPTZ;

CREATE TABLE domain_challenges (
    pentest_id UUID NOT NULL REFERENCES pentests(id) ON DELETE CASCADE,
    domain TEXT NOT NULL CHECK (length(domain) BETWEEN 3 AND 253),
    token TEXT NOT NULL UNIQUE CHECK (length(token) = 64),
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','verified','error')),
    checking_until TIMESTAMPTZ,
    next_check_at TIMESTAMPTZ,
    last_checked_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    error TEXT CHECK (error IS NULL OR error = 'dns_lookup_failed'),
    windows SMALLINT NOT NULL DEFAULT 0 CHECK (windows BETWEEN 0 AND 6),
    PRIMARY KEY (pentest_id, domain),
    CHECK ((state = 'verified') = (verified_at IS NOT NULL))
);
CREATE INDEX domain_challenges_due ON domain_challenges(next_check_at) WHERE state <> 'verified';

-- Give still-active pre-upgrade requests a challenge too. Their saved origins
-- are canonical https://host strings (port 443 is omitted by normalization).
INSERT INTO domain_challenges(pentest_id,domain,token,expires_at)
SELECT p.id,substring(origin FROM 9),replace(gen_random_uuid()::text || gen_random_uuid()::text,'-',''),p.expires_at
FROM pentests p CROSS JOIN LATERAL jsonb_array_elements_text(p.scope->'origins') AS origin
WHERE p.state IN ('pending_approval','approved') AND p.expires_at>now();

-- Existing verified requests should follow the same flow as new DNS proofs.
-- Rejected, revoked, expired and partially verified scopes stay untouched.
UPDATE pentests p
SET state = 'approved',
    decision_note = 'Domain control verified automatically.'
WHERE state = 'pending_approval'
  AND ownership_verified_at IS NOT NULL
  AND expires_at > now()
  AND (SELECT count(*) FROM domain_challenges c WHERE c.pentest_id = p.id) = jsonb_array_length(p.scope->'origins')
  AND NOT EXISTS (
      SELECT 1 FROM domain_challenges c
      WHERE c.pentest_id = p.id AND (c.state <> 'verified' OR c.expires_at <= now())
  );

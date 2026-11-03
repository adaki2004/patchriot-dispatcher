-- Staff may authorize a configured owned test site without manufacturing DNS
-- evidence. The grant belongs to this immutable request and its requester.
ALTER TABLE pentests ADD COLUMN staff_authorized_at TIMESTAMPTZ;
ALTER TABLE pentests ADD COLUMN staff_authorized_by UUID;
ALTER TABLE pentests ADD COLUMN staff_authorization_note TEXT;
ALTER TABLE pentests ADD CONSTRAINT pentests_staff_authorization_shape CHECK (
    (staff_authorized_at IS NULL AND staff_authorized_by IS NULL AND staff_authorization_note IS NULL)
    OR (staff_authorized_at IS NOT NULL AND staff_authorized_by IS NOT NULL
        AND staff_authorization_note IS NOT NULL AND length(staff_authorization_note) BETWEEN 1 AND 1500)
);
-- New requests have time to ask a developer to set DNS. Successful verification
-- narrows this deadline to at most 24 hours. Existing rows are unchanged.
ALTER TABLE pentests ALTER COLUMN expires_at SET DEFAULT now() + interval '7 days';

-- A paid review occupies a bounded queue slot but cannot lease any work until
-- authenticated core supplies the matching settled invoice. Existing demo and
-- free pilot reviews keep their current path.
ALTER TABLE reviews DROP CONSTRAINT reviews_state_check;
ALTER TABLE reviews ADD CONSTRAINT reviews_state_check
    CHECK (state IN ('awaiting_payment','queued','running','completed','needs_review','failed','cancelled'));

ALTER TABLE reviews ADD COLUMN payment_terms JSONB;
ALTER TABLE reviews ADD COLUMN payment_expires_at TIMESTAMPTZ;
ALTER TABLE reviews ADD COLUMN funded_invoice_id UUID UNIQUE;
ALTER TABLE reviews ADD COLUMN funded_at TIMESTAMPTZ;
ALTER TABLE reviews ADD CONSTRAINT reviews_payment_shape CHECK (
    (payment_terms IS NULL AND payment_expires_at IS NULL AND funded_invoice_id IS NULL AND funded_at IS NULL AND state <> 'awaiting_payment')
    OR
    (mode = 'website_agent' AND payment_terms IS NOT NULL AND payment_expires_at IS NOT NULL AND
        ((funded_invoice_id IS NULL AND funded_at IS NULL AND state IN ('awaiting_payment','failed','cancelled'))
        OR (funded_invoice_id IS NOT NULL AND funded_at IS NOT NULL AND state <> 'awaiting_payment')))
);

-- A live assessment reserves capacity before quoting and starts only after
-- core confirms funding, under the same expiry/retry rules as source reviews.
ALTER TABLE reviews DROP CONSTRAINT reviews_payment_shape;
ALTER TABLE reviews ADD CONSTRAINT reviews_payment_shape CHECK (
    (payment_terms IS NULL AND payment_expires_at IS NULL AND funded_invoice_id IS NULL AND funded_at IS NULL AND state <> 'awaiting_payment')
    OR
    (mode IN ('website_agent','source_agent','pentest_agent') AND payment_terms IS NOT NULL AND payment_expires_at IS NOT NULL AND
        ((funded_invoice_id IS NULL AND funded_at IS NULL AND state IN ('awaiting_payment','failed','cancelled'))
        OR (funded_invoice_id IS NOT NULL AND funded_at IS NOT NULL AND state <> 'awaiting_payment')))
);

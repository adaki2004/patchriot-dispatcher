-- Customer snapshots require a separate staff approval, explicit operator opt-in
-- and requester consent to three exact devices. Existing demo approvals do not
-- grant private work access.
ALTER TABLE devices ADD COLUMN private_work_approved BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN website_reviews BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE device_events DROP CONSTRAINT device_events_action_check;
ALTER TABLE device_events ADD CHECK (action IN ('paired','approved','revoked','private_approved','private_revoked'));

ALTER TABLE reviews DROP CONSTRAINT reviews_scenario_check;
ALTER TABLE reviews ADD CHECK (scenario IN ('access_control_v1','website_snapshot_v1'));
ALTER TABLE reviews DROP CONSTRAINT reviews_mode_check;
ALTER TABLE reviews ADD CHECK (mode IN ('owned_fixture','owned_agent','website_agent'));
ALTER TABLE reviews ADD COLUMN site_check_id UUID REFERENCES site_checks(id);
ALTER TABLE reviews ADD COLUMN website_context JSONB;
ALTER TABLE reviews ADD COLUMN consent_at TIMESTAMPTZ;
ALTER TABLE reviews ADD CHECK ((mode = 'website_agent') = (scenario = 'website_snapshot_v1'));
ALTER TABLE reviews ADD CHECK ((mode = 'website_agent') = (site_check_id IS NOT NULL AND website_context IS NOT NULL AND consent_at IS NOT NULL));
CREATE INDEX reviews_site ON reviews(site_check_id, created_at DESC) WHERE site_check_id IS NOT NULL;

ALTER TABLE review_steps ADD COLUMN assigned_device_id UUID REFERENCES devices(id);
ALTER TABLE review_steps ADD COLUMN evidence_complete BOOLEAN;
ALTER TABLE work_leases ADD COLUMN evidence_complete BOOLEAN;

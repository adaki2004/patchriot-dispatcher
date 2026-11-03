-- New live assessments keep waiting separate from each role's execution clock.
-- Existing reviews retain the deadlines agreed when they were created.
ALTER TABLE reviews ADD COLUMN per_role_timing BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE reviews ADD CONSTRAINT reviews_per_role_timing_mode
    CHECK (NOT per_role_timing OR mode = 'pentest_agent');

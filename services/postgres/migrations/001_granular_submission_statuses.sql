-- Migration: replace 4-state status model with 6-state granular model
--
-- Old values: submitted | evaluating (unused) | ready | failed
-- New values: submitted | validating | validated | evaluating | evaluated | error
--
-- Run this against a live database that was initialized with the old schema.
-- The init script (database_schema.sql) has already been updated for fresh installs.

BEGIN;

ALTER TABLE submissions DROP CONSTRAINT submissions_status_check;

UPDATE submissions SET status = 'validated' WHERE status = 'ready';
UPDATE submissions SET status = 'error'     WHERE status = 'failed';

ALTER TABLE submissions ADD CONSTRAINT submissions_status_check
    CHECK (status IN ('submitted', 'validating', 'validated', 'evaluating', 'evaluated', 'error'));

COMMIT;

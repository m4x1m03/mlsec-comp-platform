--------------------------------------------------
-- USERS
--------------------------------------------------
-- TODO: In the future this should not be hard coded but pulled from YAML somehow
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL, -- do we want to use TEXT instead of VARCHAR 
    email TEXT UNIQUE NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    disabled_at TIMESTAMPTZ NULL -- NULL = active
);


--------------------------------------------------
-- AUTH IDENTITIES 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS auth_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    provider TEXT NOT NULL,                -- google, local, github
    provider_subject TEXT,                 -- google sub if applicable
    password_hash TEXT,                    -- ignored if oauth

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_auth_user ON auth_identities(user_id);


--------------------------------------------------
-- USER SESSIONS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);


--------------------------------------------------
-- ADMIN ACTION TOKENS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS admin_action_tokens (
    session_id UUID PRIMARY KEY REFERENCES user_sessions(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_admin_action_tokens_expires_at ON admin_action_tokens(expires_at);


--------------------------------------------------
-- AUDIT LOGS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    email TEXT,
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN,
    message TEXT,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);


--------------------------------------------------
-- SUBMISSION CONTROL
--------------------------------------------------
CREATE TABLE IF NOT EXISTS submission_control (
    id INT PRIMARY KEY CHECK (id = 1),
    manual_closed BOOLEAN NOT NULL DEFAULT FALSE,
    close_at TIMESTAMPTZ NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID NULL REFERENCES users(id) ON DELETE SET NULL
);

INSERT INTO submission_control (id)
VALUES (1)
ON CONFLICT (id) DO NOTHING;


--------------------------------------------------
-- SUBMISSIONS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    submission_type TEXT NOT NULL CHECK (
        submission_type IN ('defense', 'attack')
    ),

    version TEXT NOT NULL,
    display_name TEXT,

    status TEXT NOT NULL CHECK (
        status IN ('submitted', 'validating', 'validated', 'evaluating', 'evaluated', 'error')
    ),

    is_functional BOOLEAN,
    functional_error TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_submissions_user ON submissions(user_id);
CREATE INDEX idx_submissions_type ON submissions(submission_type);
CREATE INDEX idx_submissions_status_type ON submissions(status, submission_type);


--------------------------------------------------
-- DEFENSE SUBMISSIONS DETAILS 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS defense_submission_details (
    submission_id UUID PRIMARY KEY
        REFERENCES submissions(id) ON DELETE CASCADE,

    source_type TEXT NOT NULL CHECK (
        source_type IN ('docker', 'github', 'zip')
    ),

    docker_image TEXT,
    git_repo TEXT,

    object_key TEXT, -- MinIO/S3 location
    sha256 TEXT,

    -- Ensure exactly one source field is populated based on source_type
    CONSTRAINT check_source_fields CHECK (
        (source_type = 'docker' AND docker_image IS NOT NULL AND git_repo IS NULL AND object_key IS NULL) OR
        (source_type = 'github' AND git_repo IS NOT NULL AND docker_image IS NULL AND object_key IS NULL) OR
        (source_type = 'zip' AND object_key IS NOT NULL AND docker_image IS NULL AND git_repo IS NULL)
    )
);

CREATE INDEX idx_defense_details_source_type ON defense_submission_details(source_type);


--------------------------------------------------
-- ATTACK SUBMISSION DETAILS 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_submission_details (
    submission_id UUID PRIMARY KEY
        REFERENCES submissions(id) ON DELETE CASCADE,

    zip_object_key TEXT NOT NULL,
    zip_sha256 TEXT,
    file_count INT,
    extracted_at TIMESTAMPTZ
);


--------------------------------------------------
-- ATTACK FILES 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attack_submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,

    original_file_id UUID
        REFERENCES attack_files(id),

    object_key TEXT NOT NULL,
    filename TEXT,
    byte_size BIGINT,
    sha256 TEXT NOT NULL,

    is_malware BOOLEAN, -- ground truth label

    behavior_status TEXT, -- unknown / same / different / error
    behavior_report_ref TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_attack_files_submission
ON attack_files(attack_submission_id);


--------------------------------------------------
-- ATTACK TEMPLATE
--------------------------------------------------
CREATE TABLE IF NOT EXISTS attack_template (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_key  TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    file_count  INT  NOT NULL DEFAULT 0,
    uploaded_by UUID REFERENCES users(id),
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_attack_template_active ON attack_template(is_active, uploaded_at DESC);


--------------------------------------------------
-- TEMPLATE FILE REPORTS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS template_file_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    template_id UUID NOT NULL
        REFERENCES attack_template(id) ON DELETE CASCADE,

    filename TEXT NOT NULL,           -- relative path within the attack template
    object_key TEXT NOT NULL,         -- MinIO path for this template file
    sha256 TEXT NOT NULL,
    sandbox_report_ref TEXT,          -- backend-specific analysis ID (e.g. VT analysis ID)
    behash TEXT,                      -- VT behavioral hash; NULL until analysis completes
    behavioral_signals JSONB,         -- extracted behavioral indicators; NULL until analysis completes

    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(template_id, filename)
);

CREATE INDEX idx_template_file_reports_template ON template_file_reports(template_id);


--------------------------------------------------
-- ACTIVE SUBMISSIONS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS active_submissions (
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,

    submission_type TEXT NOT NULL
        CHECK (submission_type IN ('defense','attack')),

    submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (user_id, submission_type)
);


--------------------------------------------------
-- EVALUATIONS RUNS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS evaluation_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    defense_submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,

    attack_submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,

    scope TEXT, -- zip | s3 | both
    status TEXT CHECK (
        status IN ('queued','running','done','failed')
    ),

    include_behavior_different BOOLEAN,
    error TEXT,
    duration_ms INT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for evaluation_runs queries
CREATE INDEX idx_evaluation_runs_defense_attack 
ON evaluation_runs(defense_submission_id, attack_submission_id);
CREATE INDEX idx_evaluation_runs_status 
ON evaluation_runs(status);


--------------------------------------------------
-- EVALUATION FILE RESULTS 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS evaluation_file_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    evaluation_run_id UUID NOT NULL
        REFERENCES evaluation_runs(id) ON DELETE CASCADE,

    attack_file_id UUID NOT NULL
        REFERENCES attack_files(id) ON DELETE CASCADE,

    model_output SMALLINT, -- 0 benign / 1 malware
    score FLOAT,
    error TEXT,
    evaded_reason TEXT,   -- NULL | 'ram_limit' | 'time_limit'
    duration_ms INT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


--------------------------------------------------
-- EVALUATION PAIR SCORES 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS evaluation_pair_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    defense_submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,

    attack_submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,

    latest_evaluation_run_id UUID
        REFERENCES evaluation_runs(id),

    zip_score_avg NUMERIC,
    n_files_scored INT,
    n_files_error INT,

    include_behavior_different BOOLEAN,

    computed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(defense_submission_id, attack_submission_id)
);

-- Indexes to speed leaderboard aggregation by submission
CREATE INDEX IF NOT EXISTS idx_eval_pair_scores_attack
ON evaluation_pair_scores(attack_submission_id);

-- Notify API when leaderboard-relevant scores change
CREATE OR REPLACE FUNCTION notify_leaderboard_change()
RETURNS trigger AS $$
DECLARE
    payload json;
BEGIN
    IF (TG_OP = 'DELETE') THEN
        payload = json_build_object(
            'table', TG_TABLE_NAME,
            'op', TG_OP,
            'defense_submission_id', OLD.defense_submission_id,
            'attack_submission_id', OLD.attack_submission_id
        );
    ELSE
        payload = json_build_object(
            'table', TG_TABLE_NAME,
            'op', TG_OP,
            'defense_submission_id', NEW.defense_submission_id,
            'attack_submission_id', NEW.attack_submission_id
        );
    END IF;

    PERFORM pg_notify('leaderboard_changes', payload::text);
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_leaderboard_scores_notify ON evaluation_pair_scores;
CREATE TRIGGER trg_leaderboard_scores_notify
AFTER INSERT OR UPDATE OR DELETE ON evaluation_pair_scores
FOR EACH ROW EXECUTE FUNCTION notify_leaderboard_change();


--------------------------------------------------
-- JOBS 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    job_type TEXT NOT NULL, 
    status TEXT NOT NULL CHECK (
        status IN ('queued','running','done','failed')
    ),

    requested_by_user_id UUID
        REFERENCES users(id),

    payload JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_jobs_status ON jobs(status);


--------------------------------------------------
-- HEURVAL SAMPLE SETS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS heurval_sample_sets (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    object_key     TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    malware_count  INT  NOT NULL DEFAULT 0,
    goodware_count INT  NOT NULL DEFAULT 0,
    uploaded_by    UUID REFERENCES users(id),
    uploaded_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active      BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX idx_heurval_sets_active ON heurval_sample_sets(is_active, uploaded_at DESC);


--------------------------------------------------
-- HEURVAL SAMPLES
--------------------------------------------------
CREATE TABLE IF NOT EXISTS heurval_samples (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sample_set_id UUID NOT NULL
        REFERENCES heurval_sample_sets(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    object_key    TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    is_malware    BOOLEAN NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_heurval_samples_set ON heurval_samples(sample_set_id);


--------------------------------------------------
-- HEURVAL RESULTS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS heurval_results (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    defense_submission_id UUID NOT NULL
        REFERENCES submissions(id) ON DELETE CASCADE,
    sample_set_id         UUID NOT NULL
        REFERENCES heurval_sample_sets(id),
    malware_tpr           NUMERIC,
    malware_fpr           NUMERIC,
    goodware_tpr          NUMERIC,
    goodware_fpr          NUMERIC,
    computed_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(defense_submission_id, sample_set_id)
);


--------------------------------------------------
-- HEURVAL FILE RESULTS
--------------------------------------------------
CREATE TABLE IF NOT EXISTS heurval_file_results (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    heurval_result_id UUID NOT NULL
        REFERENCES heurval_results(id) ON DELETE CASCADE,
    sample_id         UUID NOT NULL
        REFERENCES heurval_samples(id),
    model_output      SMALLINT,
    evaded_reason     TEXT,
    duration_ms       INT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_heurval_file_results_result ON heurval_file_results(heurval_result_id);

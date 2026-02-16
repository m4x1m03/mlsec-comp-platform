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
        status IN ('submitted', 'evaluating', 'ready', 'failed')
    ),

    is_functional BOOLEAN,
    functional_error TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ NULL
);

CREATE INDEX idx_submissions_user ON submissions(user_id);
CREATE INDEX idx_submissions_type ON submissions(submission_type);


--------------------------------------------------
-- DEFENSE SUBMISSIONS DETAILS 
--------------------------------------------------
CREATE TABLE IF NOT EXISTS defense_submission_details (
    submission_id UUID PRIMARY KEY
        REFERENCES submissions(id) ON DELETE CASCADE,

    source_type TEXT NOT NULL, -- docker | github | zip

    docker_image TEXT,
    git_repo TEXT,

    object_key TEXT, -- MinIO/S3 location
    sha256 TEXT
);


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

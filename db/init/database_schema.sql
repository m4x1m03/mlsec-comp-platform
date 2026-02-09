--------------------------------------------------
-- USERS
--------------------------------------------------

-- TODO: In the future this should not be hard coded but pulled from YAML somehow
CREATE TABLE IF NOT EXISTS users (
    -- do we want to generate uuids? 
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, -- allows us to just insert a new user
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

--------------------------------------------------
-- DEFENSE SUBMISSIONS
--------------------------------------------------

CREATE TABLE IF NOT EXISTS defense_submissions (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    docker_hub_link TEXT,
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_defense_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

-- IMPORTANT: Index foreign keys
CREATE INDEX IF NOT EXISTS idx_defense_user
ON defense_submissions(user_id);

--------------------------------------------------
-- OFFENSE SAMPLES
--------------------------------------------------

CREATE TABLE IF NOT EXISTS offense_samples (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_offense_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_offense_user
ON offense_samples(user_id);

--------------------------------------------------
-- EVALUATIONS 
--------------------------------------------------
/*

--------------------------------------------------
-- UNDER CONSTRUCTION 
--------------------------------------------------

THIS IS NOT A PART OF THE DB YET BUT WILL BE SOON

CREATE TABLE IF NOT EXISTS evaluations (
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    defense_submission_id INT NOT NULL,
    offense_sample_id INT NOT NULL,
    score FLOAT,
    status VARCHAR(20) DEFAULT 'pending',
    started_at TIMESTAMP,
    completed_at TIMESTAMP,

    CONSTRAINT fk_eval_defense
        FOREIGN KEY (defense_submission_id)
        REFERENCES defense_submissions(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_eval_offense
        FOREIGN KEY (offense_sample_id)
        REFERENCES offense_samples(id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_eval_defense
ON evaluations(defense_submission_id);

CREATE INDEX IF NOT EXISTS idx_eval_offense
ON evaluations(offense_sample_id);
*/

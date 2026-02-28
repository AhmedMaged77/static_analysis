ALTER ROLE strelka SET client_encoding TO 'utf8';
ALTER ROLE strelka SET default_transaction_isolation TO 'read committed';
ALTER ROLE strelka SET timezone TO 'UTC';

GRANT ALL PRIVILEGES ON DATABASE analysis_db TO strelka;

-- 🔑 THIS IS THE IMPORTANT PART
GRANT USAGE, CREATE ON SCHEMA public TO strelka;
ALTER SCHEMA public OWNER TO strelka;

CREATE TABLE IF NOT EXISTS analysis_results (
    sha256 VARCHAR(64) PRIMARY KEY,
    file_name VARCHAR(255),
    strelka_output JSON,
    score INTEGER,
    verdict VARCHAR(50),
    reasons JSON,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_analysis_results_sha256
ON analysis_results (sha256);

-- Orbit initial schema

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Repositories table
CREATE TABLE repositories (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            VARCHAR(255) NOT NULL,
    url             TEXT NOT NULL UNIQUE,
    provider        VARCHAR(50) NOT NULL, -- 'github' or 'gitlab'
    default_branch  VARCHAR(255) NOT NULL DEFAULT 'main',
    schedule        VARCHAR(100) NOT NULL DEFAULT '0 */6 * * *',
    auth_token      TEXT NOT NULL DEFAULT '',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_scanned_at TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Scan results table
CREATE TABLE scan_results (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    status          VARCHAR(50) NOT NULL DEFAULT 'pending',
    total_deps      INTEGER NOT NULL DEFAULT 0,
    outdated_deps   INTEGER NOT NULL DEFAULT 0,
    vulnerable_deps INTEGER NOT NULL DEFAULT 0,
    duration        BIGINT NOT NULL DEFAULT 0, -- nanoseconds
    error           TEXT,
    started_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_scan_results_repository_id ON scan_results(repository_id);
CREATE INDEX idx_scan_results_started_at ON scan_results(started_at DESC);

-- Dependencies table
CREATE TABLE dependencies (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repository_id   UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_result_id  UUID NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    name            VARCHAR(500) NOT NULL,
    current_version VARCHAR(100) NOT NULL,
    latest_version  VARCHAR(100) NOT NULL DEFAULT '',
    ecosystem       VARCHAR(50) NOT NULL, -- 'npm', 'PyPI', 'NuGet'
    manifest_file   TEXT NOT NULL,
    is_outdated     BOOLEAN NOT NULL DEFAULT false,
    is_direct       BOOLEAN NOT NULL DEFAULT true,
    update_type     VARCHAR(20) NOT NULL DEFAULT 'none', -- 'major', 'minor', 'patch', 'none'
    last_checked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dependencies_repository_id ON dependencies(repository_id);
CREATE INDEX idx_dependencies_scan_result_id ON dependencies(scan_result_id);
CREATE INDEX idx_dependencies_ecosystem ON dependencies(ecosystem);

-- Vulnerabilities table
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    dependency_id   UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
    osv_id          VARCHAR(100) NOT NULL,
    aliases         TEXT[] DEFAULT '{}',
    summary         TEXT NOT NULL,
    details         TEXT DEFAULT '',
    severity        VARCHAR(20) NOT NULL DEFAULT 'unknown',
    fixed_version   VARCHAR(100),
    refs            TEXT[] DEFAULT '{}',
    published_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vulnerabilities_dependency_id ON vulnerabilities(dependency_id);
CREATE INDEX idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulnerabilities_osv_id ON vulnerabilities(osv_id);

CREATE TABLE git_hosts (
    id         UUID PRIMARY KEY,
    kind       VARCHAR(30)  NOT NULL,
    name       VARCHAR(100) NOT NULL,
    base_url   TEXT         NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- base_url is stored with a lowercased host; Azure organization and
-- collection names are case-insensitive too, so the whole URL is unique
-- regardless of case.
CREATE UNIQUE INDEX git_hosts_base_url_lower_key ON git_hosts (lower(base_url));

ALTER TABLE access_tokens ALTER COLUMN provider TYPE VARCHAR(30);
ALTER TABLE access_tokens ADD COLUMN git_host_id UUID REFERENCES git_hosts(id) ON DELETE CASCADE;
ALTER TABLE repositories  ADD COLUMN git_host_id UUID REFERENCES git_hosts(id) ON DELETE RESTRICT;

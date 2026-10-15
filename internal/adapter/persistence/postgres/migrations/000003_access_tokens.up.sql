CREATE TABLE IF NOT EXISTS access_tokens (
    id UUID PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    provider VARCHAR(20) NOT NULL DEFAULT 'github',
    token TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

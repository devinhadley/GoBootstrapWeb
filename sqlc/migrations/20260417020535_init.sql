-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    email CITEXT NOT NULL UNIQUE CHECK (char_length(email) BETWEEN 1 AND 320),
    password_hash VARCHAR(255) NOT NULL,
    signed_up_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE sessions (
    id BYTEA PRIMARY KEY CHECK (octet_length(id) = 16),
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    renewal_expires_at TIMESTAMPTZ NOT NULL,
    CHECK (created_at <= idle_expires_at),
    CHECK (created_at <= renewal_expires_at),
    CHECK (idle_expires_at <= absolute_expires_at),
    CHECK (renewal_expires_at <= absolute_expires_at)
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_idle_expires_at ON sessions(idle_expires_at);
CREATE INDEX idx_sessions_absolute_expires_at ON sessions(absolute_expires_at);
CREATE INDEX idx_sessions_renewal_expires_at ON sessions(renewal_expires_at);

-- +goose Down
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;

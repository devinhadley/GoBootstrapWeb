-- +goose Up
CREATE TYPE auth_action AS ENUM ('login', 'password_reset', 'email_reset', 'reauthentication');
CREATE TYPE auth_outcome AS ENUM ('succeeded', 'failed');

CREATE TABLE auth_attempts (
  id BIGSERIAL PRIMARY KEY,
  action auth_action NOT NULL,
  email  TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  outcome auth_outcome NOT NULL
);

CREATE INDEX idx_auth_attempts_action_email_created_at
ON auth_attempts(action, email, created_at);

-- +goose Down
DROP TABLE IF EXISTS auth_attempts;
DROP TYPE IF EXISTS auth_outcome;
DROP TYPE IF EXISTS auth_action;

-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id,
    idle_expires_at,
    absolute_expires_at,
    renewal_expires_at
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
)
RETURNING id, user_id, created_at, idle_expires_at, absolute_expires_at, renewal_expires_at;

-- name: GetSessionByID :one
SELECT id, user_id, created_at, idle_expires_at, absolute_expires_at, renewal_expires_at
FROM sessions
WHERE id = $1;

-- name: DeleteSessionByID :exec
DELETE FROM sessions
WHERE id = $1;

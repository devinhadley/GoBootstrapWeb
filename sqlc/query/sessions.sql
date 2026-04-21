-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id
) VALUES (
    $1,
    $2
)
RETURNING id, user_id, created_at, last_seen_at, last_refreshed_at;

-- name: GetSessionByID :one
SELECT id, user_id, created_at, last_seen_at, last_seen_at
FROM sessions
WHERE id = $1;

-- name: DeleteSessionByID :exec
DELETE FROM sessions
WHERE id = $1;

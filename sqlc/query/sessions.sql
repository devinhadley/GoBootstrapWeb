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
SELECT *
FROM sessions
WHERE id = $1;

-- name: DeleteSessionByID :exec
DELETE FROM sessions
WHERE id = $1;

-- name: GetSessionCountByUser :one
SELECT COUNT(*)
FROM sessions
WHERE user_id = $1;

-- name: UpdateSessionIDByID :one
UPDATE sessions
SET id = $2
WHERE id = $1
RETURNING *;

-- name: UpdateSessionLastSeenToNow :one
UPDATE sessions
SET last_seen_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteLeastRecentlyUsedSessionByUser :exec
DELETE
FROM sessions
WHERE id = (
  SELECT s.id
  FROM sessions s
  WHERE s.user_id = $1
  ORDER BY s.last_seen_at ASC
  LIMIT 1
);


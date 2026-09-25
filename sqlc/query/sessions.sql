-- name: CreateSession :one
INSERT INTO sessions (
    id,
    user_id
) VALUES (
    $1,
    $2
)
RETURNING *;

-- name: GetSession :one
SELECT s.*
FROM sessions s
JOIN users u on s.user_id = u.id 
WHERE s.id = $1 AND u.is_active = TRUE;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE id = $1;

-- name: GetSessionCountByUser :one
SELECT COUNT(*)
FROM sessions
WHERE user_id = $1;

-- name: UpdateSessionIDAndRefreshedAt :one
UPDATE sessions
SET id = $2, last_refreshed_at = NOW()
WHERE id = $1
RETURNING *;

-- name: UpdateSessionLastSeenToNow :one
UPDATE sessions
SET last_seen_at = NOW()
WHERE id = $1
RETURNING *;

-- name: DeleteLeastRecentlyUsedSessionForUser :exec
DELETE FROM sessions
WHERE id = (
  SELECT s.id
  FROM sessions s
  WHERE s.user_id = $1
  ORDER BY s.last_seen_at ASC
  LIMIT 1
);

-- name: DeleteAllSessionsForUser :exec
DELETE FROM sessions
WHERE user_id = $1;

-- name: CreatePasswordResetRequest :one
INSERT INTO password_reset_requests (
  id, user_id
) VALUES ( $1, $2 )
RETURNING *;

-- name: ConsumePasswordResetRequest :one
DELETE FROM password_reset_requests
WHERE id = $1
RETURNING *;

-- name: DeletePasswordResetRequestsForUser :exec
DELETE FROM password_reset_requests
WHERE user_id = $1;

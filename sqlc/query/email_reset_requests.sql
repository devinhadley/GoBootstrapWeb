-- name: CreateEmailResetRequest :one
INSERT INTO email_reset_requests (
  id, user_id, new_email
) VALUES ( $1, $2, $3 )
RETURNING *;

-- name: ConsumeEmailResetRequest :one
DELETE FROM email_reset_requests
WHERE id = $1
RETURNING *;

-- name: DeleteEmailResetRequestsForUser :exec
DELETE FROM email_reset_requests
WHERE user_id = $1;

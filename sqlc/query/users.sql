-- name: CreateUser :one
INSERT INTO users (
    email,
    password_hash
) VALUES (
    $1,
    $2
)
RETURNING id, email, password_hash, signed_up_at, is_active;

-- name: GetUserByEmail :one
SELECT id, email, password_hash, signed_up_at, is_active
FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT id, email, password_hash, signed_up_at, is_active
FROM users
WHERE id = $1;

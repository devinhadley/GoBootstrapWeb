// Package service contains all application logic and validation for handlers.
// Services are segmented by corresponding DB table.
package service

import (
	"context"
	"errors"
	"strings"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/utils"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/matthewhartstonge/argon2"
)

// TODO: Add weak password validation!

var (
	ErrInvalidSignUpInput = errors.New("invalid sign-up input")
	ErrInvalidLogInInput  = errors.New("invalid log-in input")
	ErrEmailTaken         = errors.New("email already in use")
	ErrInvalidEmail       = errors.New("email is not valid")
	ErrPasswordHashing    = errors.New("password hashing not implemented")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
}

type UserService struct {
	queries UserQueries
}

type AuthenticateBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewUserService(queries UserQueries) *UserService {
	return &UserService{queries: queries}
}

func trimAndRequireValue(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}

	return trimmed, true
}

func (s *UserService) SignUp(ctx context.Context, input AuthenticateBody) (db.User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return db.User{}, ErrInvalidSignUpInput
	}

	password, ok := trimAndRequireValue(input.Password)
	if !ok {
		return db.User{}, ErrInvalidSignUpInput
	}

	ok, email = utils.NormalizeAndValidateEmail(email)
	if !ok {
		return db.User{}, ErrInvalidEmail
	}

	argon := argon2.MemoryConstrainedDefaults()

	passwordHash, err := argon.HashEncoded([]byte(password))
	if err != nil {
		return db.User{}, err
	}

	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Email:        email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if pgErr.ConstraintName == "users_email_key" {
				return db.User{}, ErrEmailTaken
			}
		}

		return db.User{}, err
	}

	return user, nil
}

func (s *UserService) LogIn(ctx context.Context, input AuthenticateBody) (db.User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return db.User{}, ErrInvalidLogInInput
	}

	password, ok := trimAndRequireValue(input.Password)
	if !ok {
		return db.User{}, ErrInvalidLogInInput
	}

	ok, email = utils.NormalizeAndValidateEmail(email)
	if !ok {
		return db.User{}, ErrInvalidEmail
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrInvalidCredentials
		}
		return db.User{}, err
	}

	ok, err = argon2.VerifyEncoded([]byte(password), []byte(user.PasswordHash))
	if err != nil {
		return db.User{}, err
	}
	if !ok {
		return db.User{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *UserService) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	return s.queries.GetUserByID(ctx, id)
}

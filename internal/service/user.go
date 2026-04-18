package service

import (
	"context"
	"errors"
	"strings"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/matthewhartstonge/argon2"
)

var (
	ErrInvalidSignUpInput = errors.New("invalid sign-up input")
	ErrInvalidLogInInput  = errors.New("invalid log-in input")
	ErrEmailTaken         = errors.New("email already in use")
	ErrPasswordHashing    = errors.New("password hashing not implemented")
	ErrUserNotFound       = errors.New("user with email doesn't exist")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
}

type UserService struct {
	queries UserQueries
}

type SignUpInput struct {
	Email    string
	Password string
}

func NewUserService(queries UserQueries) *UserService {
	return &UserService{queries: queries}
}

func (s *UserService) SignUp(ctx context.Context, input SignUpInput) (db.User, error) {
	email := strings.TrimSpace(input.Email)
	password := strings.TrimSpace(input.Password)

	if email == "" || password == "" {
		return db.User{}, ErrInvalidSignUpInput
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

func (s *UserService) Authenticate(ctx context.Context, email string, password string) (db.User, error) {
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)

	if email == "" || password == "" {
		return db.User{}, ErrInvalidLogInInput
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, ErrUserNotFound
		}
		return db.User{}, err
	}

	ok, err := argon2.VerifyEncoded([]byte(password), []byte(user.PasswordHash))
	if err != nil {
		return db.User{}, err
	}
	if !ok {
		return db.User{}, ErrInvalidCredentials
	}

	return user, nil
}

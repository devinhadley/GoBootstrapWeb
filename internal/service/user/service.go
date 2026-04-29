// Package user contains user-related application logic and validation.
package user

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

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
	ErrorPasswordEmpty    = errors.New("password cannot be empty")
	ErrorPasswordShort    = errors.New("password cannot be empty")
	ErrorPasswordLong     = errors.New("password cannot be empty")
	ErrorPasswordCommon   = errors.New("password is too common")
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
}

type Service struct {
	queries         UserQueries
	commonPasswords commonPasswords
}

type AuthenticateBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func NewService(queries UserQueries) *Service {
	return &Service{queries: queries, commonPasswords: getCommonPasswords()}
}

// TODO: Add common passwords test.
func (s *Service) SignUp(ctx context.Context, input AuthenticateBody) (db.User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return db.User{}, ErrInvalidSignUpInput
	}

	err := s.isValidPassword(input.Password)
	if err != nil {
		return db.User{}, err
	}

	ok, email = utils.NormalizeAndValidateEmail(email)
	if !ok {
		return db.User{}, ErrInvalidEmail
	}

	argon := argon2.MemoryConstrainedDefaults()

	passwordHash, err := argon.HashEncoded([]byte(input.Password))
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

func (s *Service) LogIn(ctx context.Context, input AuthenticateBody) (db.User, error) {
	// TODO: If user not found, still verify a dummy hash to avoid timing attacks...
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return db.User{}, ErrInvalidLogInInput
	}

	ok = !isEmpty(input.Password)
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

	ok, err = argon2.VerifyEncoded([]byte(input.Password), []byte(user.PasswordHash))
	if err != nil {
		return db.User{}, err
	}
	if !ok {
		return db.User{}, ErrInvalidCredentials
	}

	return user, nil
}

func (s *Service) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	return s.queries.GetUserByID(ctx, id)
}

func trimAndRequireValue(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}

	return trimmed, true
}

func isEmpty(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == ""
}

// TODO: Review OWASP and implement.
func (s *Service) isValidPassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrorPasswordEmpty
	}

	if utf8.RuneCountInString(password) < 12 {
		return ErrorPasswordShort
	}

	if utf8.RuneCountInString(password) > 256 {
		return ErrorPasswordLong
	}

	if s.commonPasswords.isCommonPassword(password) {
		return ErrorPasswordCommon
	}

	return nil
}

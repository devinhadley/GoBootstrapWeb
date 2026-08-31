// Package user contains user-related application logic and validation.
package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/pgerr"
	"devinhadley/gobootstrapweb/internal/service/email"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matthewhartstonge/argon2"
)

var (
	ErrEmailBlank         = errors.New("invalid sign-up input")
	ErrInvalidLogInInput  = errors.New("invalid log-in input")
	ErrEmailTaken         = errors.New("email already in use")
	ErrInvalidEmail       = errors.New("email is not valid")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordEmpty      = errors.New("password cannot be empty")
	ErrPasswordShort      = errors.New("password cannot be empty")
	ErrPasswordLong       = errors.New("password cannot be empty")
	ErrPasswordCommon     = errors.New("password is too common")
	ErrUserNotFound       = errors.New("user not found")
	ErrRateLimit          = errors.New("too many attempts for action")
	ErrInvalidResetToken  = errors.New("invalid or expired reset token")
)

const (
	rateLimitLoginDurationMinutes = 10
	rateLimitLoginAttemptsAllowed = 10

	passwordResetTokenDurationMinutes = 15
	emailResetTokenDurationMinutes    = 15

	passwordResetRateLimitShortWindowMinutes = 15
	passwordResetRateLimitLongWindowMinutes  = 120
	passwordResetRateLimitShortAllowed       = 2
	passwordResetRateLimitLongAllowed        = 3

	emailResetRateLimitShortWindowMinutes = 15
	emailResetRateLimitLongWindowMinutes  = 120
	emailResetRateLimitShortAllowed       = 2
	emailResetRateLimitLongAllowed        = 3
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
	CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CountTieredAuthAttempts(ctx context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error)
	CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
	CreatePasswordResetRequest(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	ConsumePasswordResetRequest(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error
	CreateEmailResetRequest(ctx context.Context, arg db.CreateEmailResetRequestParams) (db.EmailResetRequest, error)
	ConsumeEmailResetRequest(ctx context.Context, id []byte) (db.EmailResetRequest, error)
	UpdateEmail(ctx context.Context, arg db.UpdateEmailParams) error
}

type Service struct {
	queries         UserQueries
	runWithTx       RunUserQueriesInTxFn
	commonPasswords commonPasswords
	config          Config
	emailService    email.Service
}

type AuthenticateBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthenticatedPasswordResetBody struct {
	Password    string `json:"password"`
	NewPassword string `json:"newPassword"`
}

type CreatePasswordResetRequestBody struct {
	Email string `json:"email"`
}

type ResetPasswordFromResetRequestBody struct {
	NewPassword string `json:"newPassword"`
}

type CreateEmailResetRequestBody struct {
	Password string `json:"password"`
	NewEmail string `json:"newEmail"`
}

type Config struct {
	PasswordResetURL string
	EmailResetURL    string
}

func NewService(queries UserQueries, runWithTx RunUserQueriesInTxFn, emailService email.Service, config Config) *Service {
	if len(config.PasswordResetURL) > 0 && !strings.HasSuffix(config.PasswordResetURL, "/") {
		config.PasswordResetURL += "/"
	}
	if len(config.EmailResetURL) > 0 && !strings.HasSuffix(config.EmailResetURL, "/") {
		config.EmailResetURL += "/"
	}

	return &Service{queries: queries, runWithTx: runWithTx, emailService: emailService, commonPasswords: getCommonPasswords(), config: config}
}

func (s *Service) SignUp(ctx context.Context, input AuthenticateBody) (User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return User{}, ErrEmailBlank
	}

	err := s.isValidPassword(input.Password)
	if err != nil {
		return User{}, err
	}

	email, ok = normalizeAndValidateEmail(email)
	if !ok {
		return User{}, ErrInvalidEmail
	}

	passwordHash, err := createPasswordHash(input.Password)
	if err != nil {
		return User{}, fmt.Errorf("when hashing password during sign up: %w", err)
	}

	user, err := s.queries.CreateUser(ctx, db.CreateUserParams{
		Email:        email,
		PasswordHash: string(passwordHash),
	})
	if err != nil {
		if pgerr.IsUniqueViolation(err) {
			return User{}, ErrEmailTaken
		}

		return User{}, fmt.Errorf("creating user: %w", err)
	}

	return UserFromDB(user), nil
}

func (s *Service) LogIn(ctx context.Context, input AuthenticateBody) (User, error) {
	email, ok := trimAndRequireValue(input.Email)
	if !ok {
		return User{}, ErrInvalidLogInInput
	}

	if input.Password == "" {
		return User{}, ErrInvalidLogInInput
	}

	email, ok = normalizeAndValidateEmail(email)
	if !ok {
		return User{}, ErrInvalidEmail
	}

	isLimited, err := s.isLoginRateLimited(ctx, email)
	if err != nil {
		return User{}, fmt.Errorf("checking if email ratelimited: %w", err)
	}

	if isLimited {
		return User{}, ErrRateLimit
	}

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return s.failLoginAttempt(ctx, email)
		}
		return User{}, fmt.Errorf("getting user by email: %w", err)
	}

	if !user.IsActive {
		return s.failLoginAttempt(ctx, email)
	}

	ok, err = verifyPassword(input.Password, user.PasswordHash)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return s.failLoginAttempt(ctx, email)
	}

	err = s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeSucceeded)
	if err != nil {
		log.Printf("creating successful auth login attempt: %v", err)
	}

	return UserFromDB(user), nil
}

func (s *Service) ResetPasswordForAuthenticatedUser(ctx context.Context, usr User, input AuthenticatedPasswordResetBody) error {
	err := s.verifyReauthentication(ctx, usr, input.Password)
	if err != nil {
		return err
	}

	err = s.isValidPassword(input.NewPassword)
	if err != nil {
		return err
	}

	newPasswordHash, err := createPasswordHash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing password during authenticated reset: %w", err)
	}

	err = s.queries.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
		ID:           usr.DBUser().ID,
		PasswordHash: string(newPasswordHash),
	})
	if err != nil {
		return fmt.Errorf("updating password hash during authenticated password reset: %w", err)
	}

	return nil
}

func (s *Service) CreatePasswordResetRequest(ctx context.Context, reqBody CreatePasswordResetRequestBody) error {
	email, ok := normalizeAndValidateEmail(reqBody.Email)
	if !ok {
		return ErrInvalidEmail
	}

	isRateLimited, err := s.isCreatePasswordResetRateLimited(ctx, email)
	if err != nil {
		return fmt.Errorf("checking if password reset request rate limited: %w", err)
	}

	if isRateLimited {
		return ErrRateLimit
	}

	usr, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			err = s.createAuthAttempt(ctx, db.AuthActionPasswordReset, email, db.AuthOutcomeFailed)
			if err != nil {
				log.Printf("creating auth attempt for reset request: %v", err)
			}
			return ErrUserNotFound
		}

		return fmt.Errorf("getting user by email when creating password reset request: %w", err)
	}

	resetToken := make([]byte, 16)
	_, err = rand.Read(resetToken)
	if err != nil {
		return fmt.Errorf("generating random bytes for password reset token: %w", err)
	}

	sum := sha256.Sum256(resetToken)
	_, err = s.queries.CreatePasswordResetRequest(ctx, db.CreatePasswordResetRequestParams{
		ID:     sum[:],
		UserID: usr.ID,
	})
	if err != nil {
		return fmt.Errorf("creating password reset request: %w", err)
	}

	encodedToken := base64.RawURLEncoding.EncodeToString(resetToken)
	urlWithToken := fmt.Sprintf("%v?token=%v", s.config.PasswordResetURL, encodedToken)
	err = s.emailService.SendMail(email, "Password Reset", urlWithToken)
	if err != nil {
		return fmt.Errorf("failed to send passwor reset email: %w", err)
	}

	err = s.createAuthAttempt(ctx, db.AuthActionPasswordReset, email, db.AuthOutcomeSucceeded)
	if err != nil {
		log.Printf("creating auth attempt for reset request: %v", err)
	}

	return nil
}

func (s *Service) ResetPasswordFromResetRequest(ctx context.Context, token string, input ResetPasswordFromResetRequestBody) (int64, error) {
	err := s.isValidPassword(input.NewPassword)
	if err != nil {
		return 0, err
	}

	resetToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, ErrInvalidResetToken
	}

	sum := sha256.Sum256(resetToken)

	var userID int64
	err = s.runWithTx(ctx, func(qWithTx UserQueries) error {
		resetRequest, err := qWithTx.ConsumePasswordResetRequest(ctx, sum[:])
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidResetToken
			}

			return fmt.Errorf("consuming password reset request: %w", err)
		}

		expiresAt := resetRequest.CreatedAt.Time.Add(passwordResetTokenDurationMinutes * time.Minute)
		if time.Now().After(expiresAt) {
			// TODO: Cleanup expired tokens...
			// Txn aborts so wont be deleted.
			return ErrInvalidResetToken
		}

		newPasswordHash, err := createPasswordHash(input.NewPassword)
		if err != nil {
			return fmt.Errorf("hashing password during reset from token: %w", err)
		}

		err = qWithTx.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
			ID:           resetRequest.UserID,
			PasswordHash: string(newPasswordHash),
		})
		if err != nil {
			return fmt.Errorf("updating password hash during reset from token: %w", err)
		}

		userID = resetRequest.UserID

		return nil
	})
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (s *Service) CreateEmailResetRequest(ctx context.Context, usr User, input CreateEmailResetRequestBody) error {
	newEmail, ok := normalizeAndValidateEmail(input.NewEmail)
	if !ok {
		return ErrInvalidEmail
	}

	currentEmail := usr.DBUser().Email

	isRateLimited, err := s.isCreateEmailResetRateLimited(ctx, currentEmail)
	if err != nil {
		return fmt.Errorf("checking if create email reset request rate limited: %w", err)
	}

	if isRateLimited {
		return ErrRateLimit
	}

	err = s.verifyReauthentication(ctx, usr, input.Password)
	if err != nil {
		return err
	}

	if newEmail == currentEmail {
		return ErrEmailTaken
	}

	_, err = s.queries.GetUserByEmail(ctx, newEmail)
	if err == nil {
		return ErrEmailTaken
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("checking if new email is already in use: %w", err)
	}

	resetToken := make([]byte, 16)
	_, err = rand.Read(resetToken)
	if err != nil {
		return fmt.Errorf("generating random bytes for email reset token: %w", err)
	}

	sum := sha256.Sum256(resetToken)
	_, err = s.queries.CreateEmailResetRequest(ctx, db.CreateEmailResetRequestParams{
		ID:       sum[:],
		UserID:   usr.DBUser().ID,
		NewEmail: newEmail,
	})
	if err != nil {
		return fmt.Errorf("creating email reset request: %w", err)
	}

	encodedToken := base64.RawURLEncoding.EncodeToString(resetToken)
	urlWithToken := fmt.Sprintf("%v?token=%v", s.config.EmailResetURL, encodedToken)
	err = s.emailService.SendMail(newEmail, "Email Reset", urlWithToken)
	if err != nil {
		return fmt.Errorf("failed to send email reset email: %w", err)
	}

	err = s.emailService.SendMail(currentEmail, "Email Change Requested", "A change to your account email was requested. If this wasn't you, please secure your account.")
	if err != nil {
		log.Printf("failed to send email reset notification to old address: %v", err)
	}

	err = s.createAuthAttempt(ctx, db.AuthActionEmailReset, currentEmail, db.AuthOutcomeSucceeded)
	if err != nil {
		log.Printf("creating auth attempt for email reset request: %v", err)
	}

	return nil
}

func (s *Service) ResetEmailFromResetRequest(ctx context.Context, token string) (int64, error) {
	resetToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return 0, ErrInvalidResetToken
	}

	sum := sha256.Sum256(resetToken)

	var userID int64
	err = s.runWithTx(ctx, func(qWithTx UserQueries) error {
		resetRequest, err := qWithTx.ConsumeEmailResetRequest(ctx, sum[:])
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidResetToken
			}

			return fmt.Errorf("consuming email reset request: %w", err)
		}

		expiresAt := resetRequest.CreatedAt.Time.Add(emailResetTokenDurationMinutes * time.Minute)
		if time.Now().After(expiresAt) {
			// TODO: Cleanup expired tokens...
			// Txn aborts so wont be deleted.
			return ErrInvalidResetToken
		}

		err = qWithTx.UpdateEmail(ctx, db.UpdateEmailParams{
			ID:    resetRequest.UserID,
			Email: resetRequest.NewEmail,
		})
		if err != nil {
			if pgerr.IsUniqueViolation(err) {
				return ErrEmailTaken
			}

			return fmt.Errorf("updating email during reset from token: %w", err)
		}

		userID = resetRequest.UserID

		return nil
	})
	if err != nil {
		return 0, err
	}

	return userID, nil
}

func (s *Service) GetUserByID(ctx context.Context, id int64) (User, error) {
	user, err := s.queries.GetUserByID(ctx, id)
	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		return User{}, fmt.Errorf("getting user by id: %w", err)

	}
	return UserFromDB(user), nil
}

func trimAndRequireValue(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", false
	}

	return trimmed, true
}

func (s *Service) isValidPassword(password string) error {
	if strings.TrimSpace(password) == "" {
		return ErrPasswordEmpty
	}

	if utf8.RuneCountInString(password) <= 12 {
		return ErrPasswordShort
	}

	if utf8.RuneCountInString(password) > 256 {
		return ErrPasswordLong
	}

	if s.commonPasswords.isCommonPassword(password) {
		return ErrPasswordCommon
	}

	return nil
}

func (s *Service) isLoginRateLimited(ctx context.Context, email string) (bool, error) {
	return s.isFailedAttemptRateLimited(ctx, db.AuthActionLogin, email, rateLimitLoginDurationMinutes*time.Minute, rateLimitLoginAttemptsAllowed)
}

func (s *Service) isReauthenticationRateLimited(ctx context.Context, email string) (bool, error) {
	return s.isFailedAttemptRateLimited(ctx, db.AuthActionReauthentication, email, rateLimitLoginDurationMinutes*time.Minute, rateLimitLoginAttemptsAllowed)
}

func (s *Service) isFailedAttemptRateLimited(ctx context.Context, action db.AuthAction, email string, window time.Duration, allowed int64) (bool, error) {
	timeBefore := time.Now().Add(-window)

	attemptsForEmail, err := s.queries.CountFailedAuthAttemptsSince(ctx, db.CountFailedAuthAttemptsSinceParams{
		Action: action,
		Email:  email,
		CreatedAt: pgtype.Timestamptz{
			Time:  timeBefore,
			Valid: true,
		},
	})
	if err != nil {
		return false, err
	}

	return attemptsForEmail >= allowed, nil
}

func (s *Service) isCreatePasswordResetRateLimited(ctx context.Context, email string) (bool, error) {
	return s.isTieredRateLimited(ctx, db.AuthActionPasswordReset, email, passwordResetRateLimitShortWindowMinutes*time.Minute, passwordResetRateLimitLongWindowMinutes*time.Minute, passwordResetRateLimitShortAllowed, passwordResetRateLimitLongAllowed)
}

func (s *Service) isCreateEmailResetRateLimited(ctx context.Context, email string) (bool, error) {
	return s.isTieredRateLimited(ctx, db.AuthActionEmailReset, email, emailResetRateLimitShortWindowMinutes*time.Minute, emailResetRateLimitLongWindowMinutes*time.Minute, emailResetRateLimitShortAllowed, emailResetRateLimitLongAllowed)
}

func (s *Service) isTieredRateLimited(ctx context.Context, action db.AuthAction, email string, shortWindow, longWindow time.Duration, shortAllowed, longAllowed int64) (bool, error) {
	now := time.Now()

	count, err := s.queries.CountTieredAuthAttempts(ctx, db.CountTieredAuthAttemptsParams{
		Action: action,
		RecentDate: pgtype.Timestamptz{
			Time:  now.Add(-shortWindow),
			Valid: true,
		},
		OldDate: pgtype.Timestamptz{
			Time:  now.Add(-longWindow),
			Valid: true,
		},
		Email: email,
	})
	if err != nil {
		return false, err
	}

	return count.RecentCount >= shortAllowed || count.OldCount >= longAllowed, nil
}

func (s *Service) createAuthAttempt(ctx context.Context, action db.AuthAction, email string, outcome db.AuthOutcome) error {
	err := s.queries.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  action,
		Email:   email,
		Outcome: outcome,
	})
	if err != nil {
		return fmt.Errorf("creating login auth attempt: %w", err)
	}

	return nil
}

func (s *Service) failLoginAttempt(ctx context.Context, email string) (User, error) {
	if err := s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeFailed); err != nil {
		return User{}, err
	}
	return User{}, ErrInvalidCredentials
}

func (s *Service) verifyReauthentication(ctx context.Context, usr User, password string) error {
	email := usr.DBUser().Email

	isLimited, err := s.isReauthenticationRateLimited(ctx, email)
	if err != nil {
		return fmt.Errorf("checking if reauthentication rate limited: %w", err)
	}

	if isLimited {
		return ErrRateLimit
	}

	ok, err := verifyPassword(password, usr.DBUser().PasswordHash)
	if err != nil {
		return err
	}

	if !ok {
		if err := s.createAuthAttempt(ctx, db.AuthActionReauthentication, email, db.AuthOutcomeFailed); err != nil {
			log.Printf("creating auth attempt for reauthentication: %v", err)
		}
		return ErrInvalidCredentials
	}

	if err := s.createAuthAttempt(ctx, db.AuthActionReauthentication, email, db.AuthOutcomeSucceeded); err != nil {
		log.Printf("creating auth attempt for reauthentication: %v", err)
	}

	return nil
}

func normalizeAndValidateEmail(input string) (string, bool) {
	email := strings.TrimSpace(input)

	if email == "" || len(email) > 254 {
		return "", false
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return "", false
	}
	if addr.Address != email {
		return "", false
	}

	if strings.Count(email, "@") != 1 {
		return "", false
	}

	parts := strings.Split(email, "@")
	local := parts[0]
	domain := parts[1]

	if local == "" || domain == "" {
		return "", false
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return "", false
	}
	if !strings.Contains(domain, ".") {
		return "", false
	}

	normalized := local + "@" + strings.ToLower(domain)
	return normalized, true
}

func createPasswordHash(password string) ([]byte, error) {
	argon := argon2.MemoryConstrainedDefaults()

	passwordHash, err := argon.HashEncoded([]byte(password))
	if err != nil {
		return nil, err
	}

	return passwordHash, nil
}

func verifyPassword(password string, encodedHash string) (bool, error) {
	ok, err := argon2.VerifyEncoded([]byte(password), []byte(encodedHash))
	if err != nil {
		return false, fmt.Errorf("validating password hash: %w", err)
	}

	return ok, nil
}

// Package user contains user-related application logic and validation.
package user

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/pgerr"
	"devinhadley/gobootstrapweb/internal/service/email"

	"github.com/jackc/pgx/v5"
	"github.com/matthewhartstonge/argon2"
	"golang.org/x/sync/semaphore"
)

var (
	ErrEmailBlank         = errors.New("invalid sign-up input")
	ErrInvalidLogInInput  = errors.New("invalid log-in input")
	ErrEmailTaken         = errors.New("email already in use")
	ErrInvalidEmail       = errors.New("email is not valid")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordEmpty      = errors.New("password cannot be empty")
	ErrPasswordShort      = errors.New("password is too short")
	ErrPasswordLong       = errors.New("password is too long")
	ErrPasswordCommon     = errors.New("password is too common")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidResetToken  = errors.New("invalid or expired reset token")
	ErrHashingBusy        = errors.New("too many concurrent password hashes")
)

const (
	passwordResetTokenDuration = 15 * time.Minute
	emailResetTokenDuration    = 15 * time.Minute
)

const (
	passwordResetCompleteEmailSubject = "Your Password Was Reset"
	passwordResetCompleteEmailBody    = "Your password was successfully reset. If this wasn't you, please secure your account."

	passwordResetRequestEmailSubject = "Password Reset Request"

	emailResetRequestEmailSubject = "Email Reset Request"

	emailResetRequestedNotificationSubject = "Email Change Requested"
	emailResetRequestedNotificationBody    = "A change to your account email was requested. If this wasn't you, please secure your account."
)

type UserQueries interface {
	CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmail(ctx context.Context, email string) (db.User, error)
	GetUserByID(ctx context.Context, id int64) (db.User, error)
	CreatePasswordResetRequest(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	ConsumePasswordResetRequest(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error
	CreateEmailResetRequest(ctx context.Context, arg db.CreateEmailResetRequestParams) (db.EmailResetRequest, error)
	ConsumeEmailResetRequest(ctx context.Context, id []byte) (db.EmailResetRequest, error)
	UpdateEmail(ctx context.Context, arg db.UpdateEmailParams) error
	DeletePasswordResetRequestsForUser(ctx context.Context, userID int64) error
	DeleteEmailResetRequestsForUser(ctx context.Context, userID int64) error
}

type Service struct {
	queries         UserQueries
	runWithTx       RunUserQueriesInTxFn
	commonPasswords commonPasswords
	config          Config
	emailService    email.Service
	hashSlots       *semaphore.Weighted // Argon is expensive, restrict the number of concurrent hashes as to not exhaust memory.
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
	PasswordResetURL    string
	EmailResetURL       string
	MaxConcurrentHashes int64 // Each hash holds passwordHashConfig.MemoryCost of RAM while it runs.
}

func NewService(queries UserQueries, runWithTx RunUserQueriesInTxFn, emailService email.Service, config Config) *Service {
	if len(config.PasswordResetURL) > 0 && !strings.HasSuffix(config.PasswordResetURL, "/") {
		config.PasswordResetURL += "/"
	}
	if len(config.EmailResetURL) > 0 && !strings.HasSuffix(config.EmailResetURL, "/") {
		config.EmailResetURL += "/"
	}

	if config.MaxConcurrentHashes <= 0 {
		panic("user service: MaxConcurrentHashes must be > 0")
	}

	return &Service{
		queries:         queries,
		runWithTx:       runWithTx,
		emailService:    emailService,
		commonPasswords: getCommonPasswords(),
		config:          config,
		hashSlots:       semaphore.NewWeighted(config.MaxConcurrentHashes),
	}
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

	passwordHash, err := s.createPasswordHash(input.Password)
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

	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrInvalidCredentials
		}
		return User{}, fmt.Errorf("getting user by email: %w", err)
	}

	if !user.IsActive {
		return User{}, ErrInvalidCredentials
	}

	ok, err = s.verifyPassword(input.Password, user.PasswordHash)
	if err != nil {
		return User{}, err
	}
	if !ok {
		return User{}, ErrInvalidCredentials
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

	newPasswordHash, err := s.createPasswordHash(input.NewPassword)
	if err != nil {
		return fmt.Errorf("hashing password during authenticated reset: %w", err)
	}

	err = s.runWithTx(ctx, func(qWithTx UserQueries, sessionsWithTx SessionDeleter) error {
		err := qWithTx.UpdatePasswordHash(ctx, db.UpdatePasswordHashParams{
			ID:           usr.DBUser().ID,
			PasswordHash: string(newPasswordHash),
		})
		if err != nil {
			return fmt.Errorf("updating password hash during authenticated password reset: %w", err)
		}

		err = sessionsWithTx.DeleteAllSessionsForUser(ctx, usr.DBUser().ID)
		if err != nil {
			return fmt.Errorf("deleting sessions during authenticated password reset: %w", err)
		}

		return deleteOutstandingResetRequests(ctx, qWithTx, usr.DBUser().ID)
	})
	if err != nil {
		return err
	}

	err = s.emailService.SendMail(usr.DBUser().Email, passwordResetCompleteEmailSubject, passwordResetCompleteEmailBody)
	if err != nil {
		slog.Error("sending password reset notification", "err", err)
	}

	return nil
}

func (s *Service) CreatePasswordResetRequest(ctx context.Context, reqBody CreatePasswordResetRequestBody) error {
	email, ok := normalizeAndValidateEmail(reqBody.Email)
	if !ok {
		return ErrInvalidEmail
	}

	usr, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
	err = s.emailService.SendMail(email, passwordResetRequestEmailSubject, urlWithToken)
	if err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}

	return nil
}

func (s *Service) ResetPasswordFromResetRequest(ctx context.Context, token string, input ResetPasswordFromResetRequestBody) error {
	err := s.isValidPassword(input.NewPassword)
	if err != nil {
		return err
	}

	resetToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidResetToken
	}

	sum := sha256.Sum256(resetToken)

	var userID int64
	err = s.runWithTx(ctx, func(qWithTx UserQueries, sessionsWithTx SessionDeleter) error {
		resetRequest, err := qWithTx.ConsumePasswordResetRequest(ctx, sum[:])
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidResetToken
			}

			return fmt.Errorf("consuming password reset request: %w", err)
		}

		expiresAt := resetRequest.CreatedAt.Time.Add(passwordResetTokenDuration)
		if time.Now().After(expiresAt) {
			// TODO: Cleanup expired tokens...
			// Txn aborts so wont be deleted.
			return ErrInvalidResetToken
		}

		newPasswordHash, err := s.createPasswordHash(input.NewPassword)
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

		err = sessionsWithTx.DeleteAllSessionsForUser(ctx, resetRequest.UserID)
		if err != nil {
			return fmt.Errorf("deleting sessions during password reset from token: %w", err)
		}

		userID = resetRequest.UserID
		return deleteOutstandingResetRequests(ctx, qWithTx, resetRequest.UserID)
	})
	if err != nil {
		return err
	}

	usr, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		slog.Error("getting user for password reset notification", "err", err, "user_id", userID)
		return nil
	}

	err = s.emailService.SendMail(usr.Email, passwordResetCompleteEmailSubject, passwordResetCompleteEmailBody)
	if err != nil {
		slog.Error("sending password reset notification", "err", err)
	}

	return nil
}

func (s *Service) CreateEmailResetRequest(ctx context.Context, usr User, input CreateEmailResetRequestBody) error {
	newEmail, ok := normalizeAndValidateEmail(input.NewEmail)
	if !ok {
		return ErrInvalidEmail
	}

	currentEmail := usr.DBUser().Email

	err := s.verifyReauthentication(ctx, usr, input.Password)
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
	err = s.emailService.SendMail(newEmail, emailResetRequestEmailSubject, urlWithToken)
	if err != nil {
		return fmt.Errorf("failed to send email reset email: %w", err)
	}

	err = s.emailService.SendMail(
		currentEmail,
		emailResetRequestedNotificationSubject,
		emailResetRequestedNotificationBody,
	)
	if err != nil {
		slog.Error("sending email reset notification to old address", "err", err, "user_id", usr.DBUser().ID)
	}

	return nil
}

func (s *Service) ResetEmailFromResetRequest(ctx context.Context, token string) error {
	resetToken, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return ErrInvalidResetToken
	}

	sum := sha256.Sum256(resetToken)

	return s.runWithTx(ctx, func(qWithTx UserQueries, sessionsWithTx SessionDeleter) error {
		resetRequest, err := qWithTx.ConsumeEmailResetRequest(ctx, sum[:])
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrInvalidResetToken
			}

			return fmt.Errorf("consuming email reset request: %w", err)
		}

		expiresAt := resetRequest.CreatedAt.Time.Add(emailResetTokenDuration)
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

		err = sessionsWithTx.DeleteAllSessionsForUser(ctx, resetRequest.UserID)
		if err != nil {
			return fmt.Errorf("deleting sessions during email reset from token: %w", err)
		}

		return deleteOutstandingResetRequests(ctx, qWithTx, resetRequest.UserID)
	})
}

// A credential change must also kill pending resets, otherwise "secure your account" by
// resetting the password wouldn't stop an attacker's in-flight email change.
func deleteOutstandingResetRequests(ctx context.Context, q UserQueries, userID int64) error {
	err := q.DeletePasswordResetRequestsForUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("deleting outstanding password reset requests: %w", err)
	}

	err = q.DeleteEmailResetRequestsForUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("deleting outstanding email reset requests: %w", err)
	}

	return nil
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

func (s *Service) verifyReauthentication(ctx context.Context, usr User, password string) error {
	ok, err := s.verifyPassword(password, usr.DBUser().PasswordHash)
	if err != nil {
		return err
	}

	if !ok {
		return ErrInvalidCredentials
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

// OWASP's minimum recommended argon2id configuration.
var passwordHashConfig = argon2.Config{
	HashLength:  32,
	SaltLength:  16,
	TimeCost:    2,
	MemoryCost:  19 * 1024, // KiB
	Parallelism: 1,
	Mode:        argon2.ModeArgon2id,
	Version:     argon2.Version13,
}

func (s *Service) createPasswordHash(password string) ([]byte, error) {
	if !s.hashSlots.TryAcquire(1) {
		slog.Error("password hash slots exhausted, consider increasing MaxConcurrentHashes", "op", "create")
		return nil, ErrHashingBusy // Ideally this never happens. Fail hard, log, & right size later.
	}
	defer s.hashSlots.Release(1)

	argon := passwordHashConfig

	passwordHash, err := argon.HashEncoded([]byte(password))
	if err != nil {
		return nil, err
	}

	return passwordHash, nil
}

func (s *Service) verifyPassword(password string, encodedHash string) (bool, error) {
	if !s.hashSlots.TryAcquire(1) {
		slog.Error("password hash slots exhausted, consider increasing MaxConcurrentHashes", "op", "verify")
		return false, ErrHashingBusy // Ideally this never happens. Fail hard, log, & right size later.
	}
	defer s.hashSlots.Release(1)

	ok, err := argon2.VerifyEncoded([]byte(password), []byte(encodedHash))
	if err != nil {
		return false, fmt.Errorf("validating password hash: %w", err)
	}

	return ok, nil
}

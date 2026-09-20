// Integration contains all integration tests and helpers. It is one package to streamline shared test dependencies like DB.
package integration

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/server"
	"devinhadley/gobootstrapweb/internal/service/email"
	"devinhadley/gobootstrapweb/internal/service/ratelimit"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

type userIntegrationDeps struct {
	pool           *pgxpool.Pool
	queries        *db.Queries
	userService    *user.Service
	sessionService *session.Service
	emailService   *email.SliceEmailService
	handler        http.Handler
	clock          *fakeClock
}

// fakeClock is a mutable, controllable time source, so tests can advance
// past a rate limit's window without sleeping for real.
type fakeClock struct {
	someTime time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{someTime: time.Now()}
}

func (c *fakeClock) Now() time.Time {
	return c.someTime
}

func (c *fakeClock) Advance(d time.Duration) {
	c.someTime = c.someTime.Add(d)
}

func TestSignUpIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("sign up succeeds and persists user", testSignUpSucceedsAndPersistsUser)
	t.Run("duplicate email returns bad request and does not create second user", testSignUpDuplicateEmail)
	t.Run("invalid email returns bad request and does not persist user", testSignUpRejectsInvalidEmail)
	t.Run("blank email returns bad request and does not persist user", testSignUpRejectsBlankEmail)
	t.Run("blank password returns bad request and does not persist user", testSignUpRejectsBlankPassword)
	t.Run("short password returns bad request and does not persist user", testSignUpRejectsShortPassword)
	t.Run("long password returns bad request and does not persist user", testSignUpRejectsLongPassword)
	t.Run("common password returns bad request and does not persist user", testSignUpRejectsCommonPassword)
}

func TestLogInIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("login succeeds with valid credentials and creates session", testSuccessfulLogin)
	t.Run("returns unauthorized when user does not exist", testLogInReturnsUnauthorizedWhenUserDoesNotExist)
	t.Run("returns unauthorized when password is incorrect and doesnt create session", testLogInReturnsUnauthorizedWhenPasswordIsIncorrect)
	t.Run("test rejects invalid email", testLogInRejectsInvalidEmail)
}

func TestGetUserIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("get user succeeds with authenticated user", testGetUserSucceedsWithAuthenticatedUser)
}

func TestPasswordResetIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	// authenticated password reset.
	t.Run("password reset succeeds with authenticated user and deactivates sessions", testAuthenticatedPasswordResetSucceeds)
	t.Run("password reset fails with incorrect password and doesnt deactivate sessions", testAuthenticatedPasswordResetFailsWithWrongPassword)
	t.Run("password reset fails with weak password and doesnt deactivate sessions", testAuthenticatedPasswordResetFailsWithWeakPassword)
	t.Run("password reset fails without authenticated user", testAuthenticatedPasswordResetFailsWithoutAuthenticatedUser)

	// token based password reset.
	t.Run("can create password reset request", testCanCreatePasswordResetRequest)
	t.Run("creating password reset request for unknown user returns 204", testCreatingPasswordResetRequestForUnknownUserReturns204)

	t.Run("password reset suceeds with a valid reset token and deactivates sessions", testPasswordResetSucceedsWithValidResetTokenAndDeactivatesSessions)
	t.Run("cant reset password with incorrect token", testCantResetPasswordWithIncorrectToken)
	t.Run("cant reset password with already used token", testCantResetPasswordWithAlreadyUsedToken)
}

func TestEmailResetIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("email reset request succeeds and sends emails", testEmailResetRequestSucceeds)
	t.Run("email reset confirm succeeds and deactivates sessions", testEmailResetConfirmSucceeds)
	t.Run("email reset request fails with incorrect password and doesnt deactivate sessions", testEmailResetRequestFailsWithWrongPassword)
	t.Run("email reset request fails when new email already in use", testEmailResetRequestFailsWhenNewEmailAlreadyInUse)
	t.Run("email reset request fails without authenticated user", testEmailResetRequestFailsWithoutAuthenticatedUser)
	t.Run("email reset confirm fails with invalid token", testEmailResetConfirmFailsWithInvalidToken)
}

func TestRateLimitIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("login is rate limited by email after 10 attempts in 15 minutes", testLogInRateLimitedByEmail)
	t.Run("authenticated password reset is rate limited by user after 5 attempts in an hour", testAuthenticatedPasswordResetRateLimitedByUser)
	t.Run("password reset request is rate limited by email after 3 attempts in an hour", testPasswordResetRequestRateLimitedByEmail)
	t.Run("email reset request is rate limited by user after 3 attempts in an hour", testEmailResetRequestRateLimitedByUser)
	t.Run("password reset request rate limit key is case insensitive", testPasswordResetRequestRateLimitIsCaseInsensitive)
}

func testLogInRateLimitedByEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "rate-limit-login@example.com"
	correctPassword := "correct-password-12345"

	if _, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: correctPassword,
	}); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	for range 10 {
		rec := performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
			"email":    email,
			"password": "wrong-password",
		})
		assertStatus(t, rec, http.StatusUnauthorized)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": "wrong-password",
	})
	assertStatus(t, rec, http.StatusTooManyRequests)

	rec = performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": correctPassword,
	})
	assertStatus(t, rec, http.StatusTooManyRequests)

	// logInLimit's window is 15 minutes: once it elapses, the same email can
	// log in again.
	deps.clock.Advance(15*time.Minute + time.Second)

	rec = performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": correctPassword,
	})
	assertStatus(t, rec, http.StatusNoContent)
}

func testAuthenticatedPasswordResetRateLimitedByUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "rate-limit-password-reset@example.com"
	currentPassword := "current-password-12345"
	incorrectPassword := "incorrect-password-12345"

	_, sessionCookie := signUpWithSessions(t, deps, email, currentPassword, 1)

	for range 5 {
		rec := performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
			"password":    incorrectPassword,
			"newPassword": "new-password-12345",
		}, sessionCookie)
		assertStatus(t, rec, http.StatusUnauthorized)
	}

	rec := performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
		"password":    incorrectPassword,
		"newPassword": "new-password-12345",
	}, sessionCookie)
	assertStatus(t, rec, http.StatusTooManyRequests)

	// authedPasswordResetLimit's window is 1 hour: once it elapses, the same
	// user can attempt a password reset again.
	deps.clock.Advance(1*time.Hour + time.Second)

	rec = performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
		"password":    currentPassword,
		"newPassword": "new-password-12345",
	}, sessionCookie)
	assertStatus(t, rec, http.StatusNoContent)
}

func testPasswordResetRequestRateLimitedByEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "rate-limit-password-reset-request@example.com"

	if _, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "original-password-12345",
	}); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	for range 3 {
		rec := performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
			"email": email,
		})
		assertStatus(t, rec, http.StatusNoContent)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})
	assertStatus(t, rec, http.StatusTooManyRequests)

	// passwordResetRequestLimit's window is 1 hour: once it elapses, the
	// same email can request a reset again.
	deps.clock.Advance(1*time.Hour + time.Second)

	rec = performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})
	assertStatus(t, rec, http.StatusNoContent)
}

func testEmailResetRequestRateLimitedByUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	currentEmail := "rate-limit-email-reset@example.com"
	currentPassword := "current-password-12345"
	incorrectPassword := "incorrect-password-12345"

	_, sessionCookie := signUpWithSessions(t, deps, currentEmail, currentPassword, 1)

	for range 3 {
		rec := performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
			"password": incorrectPassword,
			"newEmail": "rate-limit-email-reset-new@example.com",
		}, sessionCookie)
		assertStatus(t, rec, http.StatusUnauthorized)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
		"password": incorrectPassword,
		"newEmail": "rate-limit-email-reset-new@example.com",
	}, sessionCookie)
	assertStatus(t, rec, http.StatusTooManyRequests)

	// emailResetRequestLimit's window is 1 hour: once it elapses, the same
	// user can request an email reset again.
	deps.clock.Advance(1*time.Hour + time.Second)

	rec = performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
		"password": currentPassword,
		"newEmail": "rate-limit-email-reset-new@example.com",
	}, sessionCookie)
	assertStatus(t, rec, http.StatusNoContent)
}

func testPasswordResetRequestRateLimitIsCaseInsensitive(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "rate-limit-casing@example.com"

	if _, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "original-password-12345",
	}); err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	for range 3 {
		rec := performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
			"email": "Rate-Limit-Casing@Example.com",
		})
		assertStatus(t, rec, http.StatusNoContent)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
		"email": strings.ToLower("Rate-Limit-Casing@Example.com"),
	})
	assertStatus(t, rec, http.StatusTooManyRequests)

	otherEmail := "rate-limit-casing-other@example.com"
	if _, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    otherEmail,
		Password: "original-password-12345",
	}); err != nil {
		t.Fatalf("failed to seed second user: %v", err)
	}

	rec = performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
		"email": otherEmail,
	})
	assertStatus(t, rec, http.StatusNoContent)
}

func testSignUpSucceedsAndPersistsUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "signup@example.com",
		"password": "example-password",
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", input)
	assertStatus(t, rec, http.StatusNoContent)

	storedUser, err := deps.queries.GetUserByEmail(context.Background(), input["email"])
	if err != nil {
		t.Fatalf("failed to load user from database: %v", err)
	}

	if storedUser.ID == 0 {
		t.Fatal("expected stored user id to be non-zero")
	}

	if storedUser.Email != input["email"] {
		t.Fatalf("got stored email %q, want %q", storedUser.Email, input["email"])
	}

	assertPasswordMatchesHash(t, input["password"], storedUser.PasswordHash)

	count, err := deps.queries.GetSessionCountByUser(context.Background(), storedUser.ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 1 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 1)
	}

	assertSessionCookieExists(t, rec)
}

func testSignUpDuplicateEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "duplicate@example.com",
		"password": "example-password",
	}

	first := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", input)
	assertStatus(t, first, http.StatusNoContent)

	second := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", input)
	assertStatus(t, second, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, second)
	if gotErr.Email != "email already in use" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email already in use")
	}

	userCount := countUsersByEmail(t, deps.pool, input["email"])
	if userCount != 1 {
		t.Fatalf("got %d users for email %q, want 1", userCount, input["email"])
	}
}

func testSignUpRejectsBlankEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", map[string]string{
		"email":    "",
		"password": "example-password",
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email may not be blank" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email may not be blank")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsBlankPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "blank-password@example.com"
	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", map[string]string{
		"email":    email,
		"password": "",
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password can't be empty" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password can't be empty")
	}

	assertNoUserWithEmail(t, deps.queries, email)
}

func testSignUpRejectsCommonPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", map[string]string{
		"email":    "test@example.com",
		"password": "123456789101112",
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password too common" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password too common")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsShortPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", map[string]string{
		"email":    "short-password@example.com",
		"password": "12345678901",
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password must be 13 or more characters" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password must be 12 or more characters")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsLongPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", map[string]string{
		"email":    "long-password@example.com",
		"password": strings.Repeat("a", 257),
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password must be 256 charactrs or less" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password must be 256 charactrs or less")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSignUpRejectsInvalidEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "invalid"
	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/signup", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email is not valid" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email is not valid")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testSuccessfulLogin(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()
	email := "test@example.com"

	user, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "example-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	assertStatus(t, rec, http.StatusNoContent)

	// Session created for the user.
	count, err := deps.queries.GetSessionCountByUser(ctx, user.DBUser().ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 1 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 1)
	}

	assertSessionCookieExists(t, rec)
}

func testLogInRejectsInvalidEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	email := "invalid"

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email is not valid" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email is not valid")
	}

	assertNoSessionCookie(t, rec)
}

func testLogInReturnsUnauthorizedWhenUserDoesNotExist(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	email := "missing@example.com"

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	assertStatus(t, rec, http.StatusUnauthorized)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	assertNoSessionCookie(t, rec)
}

func testLogInReturnsUnauthorizedWhenPasswordIsIncorrect(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()
	email := "wrong-password@example.com"

	user, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/user/login", map[string]string{
		"email":    email,
		"password": "incorrect-password",
	})

	assertStatus(t, rec, http.StatusUnauthorized)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	// Session not created for the user.
	count, err := deps.queries.GetSessionCountByUser(ctx, user.DBUser().ID)
	if err != nil {
		t.Fatalf("got error %v when getting session count", err)
	}

	if count != 0 {
		t.Fatalf("got number of sessions for user %v wanted %v", count, 0)
	}

	assertNoSessionCookie(t, rec)
}

func testGetUserSucceedsWithAuthenticatedUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	createdUser, sessionCookie := signUpWithSessions(t, deps, "whoami@example.com", "example-password-12345", 1)

	rec := performJsonRequest(deps.handler, http.MethodGet, "/user", map[string]any{}, sessionCookie)
	assertStatus(t, rec, http.StatusOK)

	var got getUserResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode whoami response: %v", err)
	}

	if got.ID != createdUser.DBUser().ID {
		t.Fatalf("got user id %d, want %d", got.ID, createdUser.DBUser().ID)
	}

	if got.Email != createdUser.DBUser().Email {
		t.Fatalf("got email %q, want %q", got.Email, createdUser.DBUser().Email)
	}
}

func testAuthenticatedPasswordResetSucceeds(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-authenticated@example.com"
	currentPassword := "current-password-12345"
	newPassword := "new-password-12345"

	createdUser, sessionCookie := signUpWithSessions(t, deps, email, currentPassword, 3)

	rec := performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
		"password":    currentPassword,
		"newPassword": newPassword,
	}, sessionCookie)

	assertStatus(t, rec, http.StatusNoContent)

	foundClearedCookie := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			foundClearedCookie = true
			if cookie.Value != "" {
				t.Fatalf("expected cleared session cookie value, got %q", cookie.Value)
			}
			if cookie.MaxAge != -1 {
				t.Fatalf("expected cleared session cookie max age -1, got %d", cookie.MaxAge)
			}
		}
	}

	if !foundClearedCookie {
		t.Fatal("expected handler to clear session cookie")
	}

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after password reset: %v", err)
	}

	assertPasswordMatchesHash(t, newPassword, storedUser.PasswordHash)

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after reset: %v", err)
	}
	if activeCountAfter != 0 {
		t.Fatalf("got %d active sessions after reset, want 0", activeCountAfter)
	}
}

func testAuthenticatedPasswordResetFailsWithWrongPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-authenticated-fails@example.com"
	currentPassword := "current-password-12345"
	incorrectPassword := "incorrect-password-12345"
	newPassword := "new-password-12345"

	createdUser, sessionCookie := signUpWithSessions(t, deps, email, currentPassword, 1)

	rec := performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
		"password":    incorrectPassword,
		"newPassword": newPassword,
	}, sessionCookie)

	assertStatus(t, rec, http.StatusUnauthorized)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	// NOTE:
	// response recorder only records cookies added by response
	// so when server makes no changes we're good to go...
	assertNoSessionCookie(t, rec)

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after failed password reset: %v", err)
	}
	if storedUser.PasswordHash != createdUser.DBUser().PasswordHash {
		t.Fatal("stored password hash changed after failed password reset")
	}

	// get session count is active sessions!
	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after reset: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after reset, want 1", activeCountAfter)
	}
}

func testAuthenticatedPasswordResetFailsWithWeakPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-authenticated-weak@example.com"
	currentPassword := "current-password-12345"
	commonNewPassword := "123456789101112"

	createdUser, sessionCookie := signUpWithSessions(t, deps, email, currentPassword, 1)

	rec := performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
		"password":    currentPassword,
		"newPassword": commonNewPassword,
	}, sessionCookie)

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Password != "password too common" {
		t.Fatalf("got password error %q, want %q", gotErr.Password, "password too common")
	}

	assertNoSessionCookie(t, rec)

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after failed password reset: %v", err)
	}
	if storedUser.PasswordHash != createdUser.DBUser().PasswordHash {
		t.Fatal("stored password hash changed after failed password reset")
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after reset: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after reset, want 1", activeCountAfter)
	}
}

func testAuthenticatedPasswordResetFailsWithoutAuthenticatedUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.handler, http.MethodPut, "/user/password", map[string]string{
		"password":    "current-password-12345",
		"newPassword": "new-password-12345",
	})

	assertStatus(t, rec, http.StatusUnauthorized)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr != (apiErrorResponse{}) {
		t.Fatalf("got error response %+v, want empty response", gotErr)
	}

	assertNoSessionCookie(t, rec)
}

func testCanCreatePasswordResetRequest(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-request@example.com"
	password := "original-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})

	assertStatus(t, rec, http.StatusNoContent)

	resetRequestCount := countPasswordResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 1 {
		t.Fatalf("got %d password reset requests for user %v, want %d", resetRequestCount, createdUser.DBUser().ID, 1)
	}

	if len(deps.emailService.Emails) != 1 {
		t.Fatalf("got %d sent emails, want %d", len(deps.emailService.Emails), 1)
	}

	sentEmail := deps.emailService.Emails[0]
	if sentEmail.ToEmail != email {
		t.Fatalf("got sent email to %q, want %q", sentEmail.ToEmail, email)
	}

	if sentEmail.Subject != "Password Reset Request" {
		t.Fatalf("got sent email subject %q, want %q", sentEmail.Subject, "Password Reset Request")
	}

	if !strings.Contains(sentEmail.Body, "?token=") {
		t.Fatalf("expected sent email body to contain token query parameter, got %q", sentEmail.Body)
	}
}

func testCreatingPasswordResetRequestForUnknownUserReturns204(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "missing-password-reset@example.com"

	rec := performJsonRequest(deps.handler, http.MethodPost, "/password-reset", map[string]string{
		"email": email,
	})

	assertStatus(t, rec, http.StatusNoContent)

	resetRequestCount := countPasswordResetRequests(t, deps.pool)
	if resetRequestCount != 0 {
		t.Fatalf("got %d password reset requests, want 0", resetRequestCount)
	}
}

func testPasswordResetSucceedsWithValidResetTokenAndDeactivatesSessions(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-valid-token@example.com"
	currentPassword := "current-password-12345"
	newPassword := "new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create first active session: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create second active session: %v", err)
	}

	err = deps.userService.CreatePasswordResetRequest(ctx, user.CreatePasswordResetRequestBody{Email: email})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	if len(deps.emailService.Emails) != 1 {
		t.Fatalf("got %d sent emails, want %d", len(deps.emailService.Emails), 1)
	}
	resetToken := extractTokenFromResetBody(deps.emailService.Emails[0].Body)
	if resetToken == "" {
		t.Fatalf("failed to extract reset token from email body %q", deps.emailService.Emails[0].Body)
	}

	rec := performJsonRequest(deps.handler, http.MethodPut, "/password-reset?token="+resetToken, map[string]string{
		"newPassword": newPassword,
	})
	assertStatus(t, rec, http.StatusNoContent)

	userAfterPassReset, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after token reset: %v", err)
	}

	assertPasswordMatchesHash(t, newPassword, userAfterPassReset.PasswordHash)

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after token reset: %v", err)
	}
	if activeCountAfter != 0 {
		t.Fatalf("got %d active sessions after token reset, want 0", activeCountAfter)
	}

	rawToken, err := base64.RawURLEncoding.DecodeString(resetToken)
	if err != nil {
		t.Fatalf("failed to decode reset token for post-reset verification: %v", err)
	}
	tokenHash := sha256.Sum256(rawToken)
	_, err = deps.queries.ConsumePasswordResetRequest(ctx, tokenHash[:])
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected consumed reset token to be deleted, got err: %v", err)
	}
}

func testCantResetPasswordWithIncorrectToken(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-incorrect-token@example.com"
	currentPassword := "current-password-12345"
	newPassword := "new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create first active session: %v", err)
	}

	err = deps.userService.CreatePasswordResetRequest(ctx, user.CreatePasswordResetRequestBody{Email: email})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPut, "/password-reset?token=incorrect-reset-token", map[string]string{
		"newPassword": newPassword,
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "invalid or expired reset token" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "invalid or expired reset token")
	}

	assertNoSessionCookie(t, rec)

	storedUser, err := deps.queries.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("failed to fetch user after failed token reset: %v", err)
	}
	if storedUser.PasswordHash != createdUser.DBUser().PasswordHash {
		t.Fatal("stored password hash changed after failed token reset")
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after failed token reset: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after failed token reset, want %d", activeCountAfter, 1)
	}

	resetRequestCountAfter := countPasswordResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCountAfter != 1 {
		t.Fatalf("got %d password reset requests after failed token reset, want %d", resetRequestCountAfter, 1)
	}
}

func testCantResetPasswordWithAlreadyUsedToken(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	email := "password-reset-used-token@example.com"
	currentPassword := "current-password-12345"
	firstNewPassword := "first-new-password-12345"
	secondNewPassword := "second-new-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    email,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	err = deps.userService.CreatePasswordResetRequest(ctx, user.CreatePasswordResetRequestBody{Email: email})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	resetToken := extractTokenFromResetBody(deps.emailService.Emails[0].Body)
	if resetToken == "" {
		t.Fatalf("failed to extract reset token from email body %q", deps.emailService.Emails[0].Body)
	}

	_, err = deps.userService.ResetPasswordFromResetRequest(ctx, resetToken, user.ResetPasswordFromResetRequestBody{
		NewPassword: firstNewPassword,
	})
	if err != nil {
		t.Fatalf("ResetPasswordFromResetRequest returned error on first use: %v", err)
	}

	_, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create first active session: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPut, "/password-reset?token="+resetToken, map[string]string{
		"newPassword": secondNewPassword,
	})

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "invalid or expired reset token" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "invalid or expired reset token")
	}

	activeSessionCount, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("got error when getting session count %v", err)
	}

	if activeSessionCount != 1 {
		t.Fatalf("got active session count %d, want %d", activeSessionCount, 1)
	}
}

func testEmailResetRequestSucceeds(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	currentEmail := "email-reset-request-success@example.com"
	newEmail := "email-reset-request-success-new@example.com"
	currentPassword := "current-password-12345"

	createdUser, sessionCookie := signUpWithSessions(t, deps, currentEmail, currentPassword, 2)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
		"password": currentPassword,
		"newEmail": newEmail,
	}, sessionCookie)

	assertStatus(t, rec, http.StatusNoContent)

	if len(deps.emailService.Emails) != 2 {
		t.Fatalf("got %d sent emails, want %d", len(deps.emailService.Emails), 2)
	}

	newEmailMessage := deps.emailService.Emails[0]
	if newEmailMessage.ToEmail != newEmail {
		t.Fatalf("got first email recipient %q, want %q", newEmailMessage.ToEmail, newEmail)
	}
	if newEmailMessage.Subject != "Email Reset Request" {
		t.Fatalf("got first email subject %q, want %q", newEmailMessage.Subject, "Email Reset Request")
	}
	wantPrefix := "http://example.com/email-reset/?token="
	if !strings.HasPrefix(newEmailMessage.Body, wantPrefix) {
		t.Fatalf("got first email body %q, want prefix %q", newEmailMessage.Body, wantPrefix)
	}

	oldEmailMessage := deps.emailService.Emails[1]
	if oldEmailMessage.ToEmail != currentEmail {
		t.Fatalf("got second email recipient %q, want %q", oldEmailMessage.ToEmail, currentEmail)
	}
	if oldEmailMessage.Subject != "Email Change Requested" {
		t.Fatalf("got second email subject %q, want %q", oldEmailMessage.Subject, "Email Change Requested")
	}

	resetRequestCount := countEmailResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 1 {
		t.Fatalf("got %d email reset requests after request, want %d", resetRequestCount, 1)
	}

	resetToken := extractTokenFromResetBody(newEmailMessage.Body)
	if resetToken == "" {
		t.Fatalf("failed to extract reset token from email body %q", newEmailMessage.Body)
	}

	// Email is not changed yet, only requested.
	if _, err := deps.queries.GetUserByEmail(ctx, currentEmail); err != nil {
		t.Fatalf("failed to fetch user by current email after request: %v", err)
	}
}

func testEmailResetConfirmSucceeds(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	currentEmail := "email-reset-confirm-success@example.com"
	newEmail := "email-reset-confirm-success-new@example.com"
	currentPassword := "current-password-12345"

	createdUser, _ := signUpWithSessions(t, deps, currentEmail, currentPassword, 2)

	err := deps.userService.CreateEmailResetRequest(ctx, createdUser, user.CreateEmailResetRequestBody{
		Password: currentPassword,
		NewEmail: newEmail,
	})
	if err != nil {
		t.Fatalf("CreateEmailResetRequest returned error: %v", err)
	}

	if len(deps.emailService.Emails) != 2 {
		t.Fatalf("got %d sent emails, want %d", len(deps.emailService.Emails), 2)
	}

	resetToken := extractTokenFromResetBody(deps.emailService.Emails[0].Body)
	if resetToken == "" {
		t.Fatalf("failed to extract reset token from email body %q", deps.emailService.Emails[0].Body)
	}

	confirmRec := performJsonRequest(deps.handler, http.MethodPut, "/email-reset?token="+resetToken, nil)
	assertStatus(t, confirmRec, http.StatusNoContent)

	if _, err := deps.queries.GetUserByEmail(ctx, newEmail); err != nil {
		t.Fatalf("failed to fetch user by new email after confirm: %v", err)
	}

	assertNoUserWithEmail(t, deps.queries, currentEmail)

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after confirm: %v", err)
	}
	if activeCountAfter != 0 {
		t.Fatalf("got %d active sessions after confirm, want 0", activeCountAfter)
	}

	rawToken, err := base64.RawURLEncoding.DecodeString(resetToken)
	if err != nil {
		t.Fatalf("failed to decode reset token for post-confirm verification: %v", err)
	}
	tokenHash := sha256.Sum256(rawToken)
	_, err = deps.queries.ConsumeEmailResetRequest(ctx, tokenHash[:])
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected consumed email reset token to be deleted, got err: %v", err)
	}
}

func testEmailResetRequestFailsWithWrongPassword(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	currentEmail := "email-reset-wrong-password@example.com"
	currentPassword := "current-password-12345"
	incorrectPassword := "incorrect-password-12345"
	newEmail := "email-reset-wrong-password-new@example.com"

	createdUser, sessionCookie := signUpWithSessions(t, deps, currentEmail, currentPassword, 1)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
		"password": incorrectPassword,
		"newEmail": newEmail,
	}, sessionCookie)

	assertStatus(t, rec, http.StatusUnauthorized)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}

	assertNoSessionCookie(t, rec)

	if len(deps.emailService.Emails) != 0 {
		t.Fatalf("got %d sent emails, want 0", len(deps.emailService.Emails))
	}

	resetRequestCount := countEmailResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 0 {
		t.Fatalf("got %d email reset requests, want 0", resetRequestCount)
	}

	activeCountAfter, err := deps.queries.GetSessionCountByUser(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to get active session count after failed request: %v", err)
	}
	if activeCountAfter != 1 {
		t.Fatalf("got %d active sessions after failed request, want 1", activeCountAfter)
	}
}

func testEmailResetRequestFailsWhenNewEmailAlreadyInUse(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	requesterEmail := "email-reset-taken-requester@example.com"
	requesterPassword := "current-password-12345"
	takenEmail := "email-reset-taken@example.com"

	createdUser, sessionCookie := signUpWithSessions(t, deps, requesterEmail, requesterPassword, 1)

	_, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    takenEmail,
		Password: "other-password-12345",
	})
	if err != nil {
		t.Fatalf("failed to create existing test user: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
		"password": requesterPassword,
		"newEmail": takenEmail,
	}, sessionCookie)

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email already in use" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email already in use")
	}

	if len(deps.emailService.Emails) != 0 {
		t.Fatalf("got %d sent emails, want 0", len(deps.emailService.Emails))
	}

	resetRequestCount := countEmailResetRequestsByUserID(t, deps.pool, createdUser.DBUser().ID)
	if resetRequestCount != 0 {
		t.Fatalf("got %d email reset requests, want 0", resetRequestCount)
	}

	storedUser, err := deps.queries.GetUserByEmail(ctx, requesterEmail)
	if err != nil {
		t.Fatalf("failed to fetch requesting user after failed request: %v", err)
	}
	if storedUser.Email != requesterEmail {
		t.Fatalf("got requester email %q, want unchanged %q", storedUser.Email, requesterEmail)
	}
}

func testEmailResetRequestFailsWithoutAuthenticatedUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJsonRequest(deps.handler, http.MethodPost, "/email-reset", map[string]string{
		"password": "current-password-12345",
		"newEmail": "email-reset-unauthenticated-new@example.com",
	})

	assertStatus(t, rec, http.StatusUnauthorized)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr != (apiErrorResponse{}) {
		t.Fatalf("got error response %+v, want empty response", gotErr)
	}

	assertNoSessionCookie(t, rec)

	if len(deps.emailService.Emails) != 0 {
		t.Fatalf("got %d sent emails, want 0", len(deps.emailService.Emails))
	}
}

func testEmailResetConfirmFailsWithInvalidToken(t *testing.T) {
	deps := setupUserIntegrationDeps(t)
	ctx := context.Background()

	currentEmail := "email-reset-invalid-token@example.com"
	currentPassword := "current-password-12345"

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    currentEmail,
		Password: currentPassword,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	rec := performJsonRequest(deps.handler, http.MethodPut, "/email-reset?token=incorrect-reset-token", nil)

	assertStatus(t, rec, http.StatusBadRequest)

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "invalid or expired reset token" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "invalid or expired reset token")
	}

	storedUser, err := deps.queries.GetUserByEmail(ctx, currentEmail)
	if err != nil {
		t.Fatalf("failed to fetch user after failed confirm: %v", err)
	}
	if storedUser.ID != createdUser.DBUser().ID {
		t.Fatalf("got user id %v, want %v", storedUser.ID, createdUser.DBUser().ID)
	}
}

func setupUserIntegrationDeps(t *testing.T) userIntegrationDeps {
	t.Helper()

	pool := getIntegrationTestPool(t)

	t.Cleanup(func() {
		cleanupIntegrationTables(t, pool)
	})

	queries := db.New(pool)
	sliceEmailService := &email.SliceEmailService{}
	txnGenerator := user.CreateUserServiceTxnGenerator(pool, queries)
	sessionService := session.NewService(queries)
	userService := user.NewService(queries, txnGenerator, sliceEmailService, user.Config{
		PasswordResetURL: "http://example.com/password-reset",
		EmailResetURL:    "http://example.com/email-reset",
	})
	clock := newFakeClock()
	limiter := ratelimit.NewInMemoryLimiter(clock.Now)

	handler := server.NewMux(userService, sessionService, limiter)

	return userIntegrationDeps{
		pool:           pool,
		queries:        queries,
		userService:    userService,
		sessionService: sessionService,
		emailService:   sliceEmailService,
		handler:        handler,
		clock:          clock,
	}
}

func decodeErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) apiErrorResponse {
	t.Helper()

	var got apiErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	return got
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()

	if rec.Code != want {
		t.Fatalf("got status %d, want %d", rec.Code, want)
	}
}

func assertPasswordMatchesHash(t *testing.T, password string, hash string) {
	t.Helper()

	matches, err := argon2.VerifyEncoded([]byte(password), []byte(hash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error: %v", err)
	}
	if !matches {
		t.Fatal("password does not match stored hash")
	}
}

// signUpWithSessions signs up a user, creates sessionCount active sessions for
// them, and returns the created user along with a session cookie for the most
// recently created session.
func signUpWithSessions(t *testing.T, deps userIntegrationDeps, emailAddr string, password string, sessionCount int) (user.User, *http.Cookie) {
	t.Helper()
	ctx := context.Background()

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    emailAddr,
		Password: password,
	})
	if err != nil {
		t.Fatalf("failed to create test user: %v", err)
	}

	var requestSession session.CreateSessionResult
	for range sessionCount {
		requestSession, err = deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
		if err != nil {
			t.Fatalf("failed to create active session: %v", err)
		}
	}

	sessionCookie := &http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(requestSession.RawID),
		Expires:  requestSession.Session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	return createdUser, sessionCookie
}

func assertSessionCookieExists(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			if cookie.Value == "" {
				t.Fatal("session cookie id has empty value")
			}

			if cookie.Expires.Before(time.Now()) {
				t.Fatalf("Expected session cookie to expire after now, but got %v", cookie.Expires)
			}
			return
		}
	}

	t.Fatal("expected response to include session cookie id")
}

func assertNoSessionCookie(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			t.Fatal("expected response to not include session cookie id")
		}
	}
}

func assertNoUserWithEmail(t *testing.T, queries *db.Queries, email string) {
	t.Helper()

	_, err := queries.GetUserByEmail(context.Background(), email)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected no user with email %q, got err %v", email, err)
	}
}

func countUsersByEmail(t *testing.T, pool *pgxpool.Pool, email string) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count users by email: %v", err)
	}

	return count
}

func countUsers(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM users").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count users: %v", err)
	}

	return count
}

func countPasswordResetRequestsByUserID(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM password_reset_requests WHERE user_id = $1", userID).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count password reset requests for user %v: %v", userID, err)
	}

	return count
}

func countEmailResetRequestsByUserID(t *testing.T, pool *pgxpool.Pool, userID int64) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM email_reset_requests WHERE user_id = $1", userID).Scan(&count)
	if err != nil {
		t.Fatalf("failed to count email reset requests for user %v: %v", userID, err)
	}

	return count
}

func countPasswordResetRequests(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()

	var count int
	err := pool.QueryRow(context.Background(), "SELECT COUNT(*) FROM password_reset_requests").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count password reset requests: %v", err)
	}

	return count
}

func updatePasswordResetReqCreatedAtForUserID(t *testing.T, pool *pgxpool.Pool, userID int64, date time.Time) {
	t.Helper()

	tag, err := pool.Exec(context.Background(), "UPDATE password_reset_requests SET created_at = $1 WHERE user_id = $2", date, userID)
	if err != nil {
		t.Fatalf("failed to update password_reset_requests created_at for user %v: %v", userID, err)
	}

	if tag.RowsAffected() == 0 {
		t.Fatalf("expected to update password_reset_requests created_at for user %v, updated 0 rows", userID)
	}
}

func extractTokenFromResetBody(body string) string {
	parts := strings.Split(body, "?token=")
	if len(parts) < 2 {
		return ""
	}

	token := strings.TrimSpace(parts[len(parts)-1])
	if token == "" {
		return ""
	}

	return token
}

type apiErrorResponse struct {
	Error    string `json:"error"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type getUserResponse struct {
	ID    int64  `json:"id"`
	Email string `json:"email"`
}

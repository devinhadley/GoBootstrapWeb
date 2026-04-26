package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils/testutil"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

// TODO: Add weak password validation!
type userIntegrationDeps struct {
	pool        *pgxpool.Pool
	queries     *db.Queries
	userService *user.Service
	signUp      http.HandlerFunc
	login       http.HandlerFunc
}

func TestSignUpIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("sign up succeeds and persists user", testSignUpSucceedsAndPersistsUser)
	t.Run("duplicate email returns bad request and does not create second user", testSignUpDuplicateEmail)
	t.Run("invalid email returns bad request and does not persist user", testSignUpRejectsInvalidEmail)
	t.Run("blank email or password returns bad request and does not persist user", testSignUpRejectsBlankEmailOrPassword)
}

func TestLogInIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration tests in short mode")
	}

	t.Run("login rejects invalid email", testLogInRejectsInvalidEmail)
	t.Run("login succeeds with valid credentials", testLogInSucceeds)
	t.Run("returns bad request when user does not exist", testLogInReturnsBadRequestWhenUserDoesNotExist)
	t.Run("returns bad request when password is incorrect", testLogInReturnsBadRequestWhenPasswordIsIncorrect)
}

func testSignUpSucceedsAndPersistsUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "signup@example.com",
		"password": "example-password",
	}

	rec := testutil.PerformJSONRequest(deps.signUp, http.MethodPost, "/signup", input)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

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

	ok, err := argon2.VerifyEncoded([]byte(input["password"]), []byte(storedUser.PasswordHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error: %v", err)
	}

	if !ok {
		t.Fatal("stored password hash does not match input password")
	}
}

func testSignUpDuplicateEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "duplicate@example.com",
		"password": "example-password",
	}

	first := testutil.PerformJSONRequest(deps.signUp, http.MethodPost, "/signup", input)
	if first.Code != http.StatusOK {
		t.Fatalf("first sign up got status %d, want %d", first.Code, http.StatusOK)
	}

	second := testutil.PerformJSONRequest(deps.signUp, http.MethodPost, "/signup", input)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("second sign up got status %d, want %d", second.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, second)
	if gotErr.Email != "email already in use" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email already in use")
	}

	userCount := countUsersByEmail(t, deps.pool, input["email"])
	if userCount != 1 {
		t.Fatalf("got %d users for email %q, want 1", userCount, input["email"])
	}
}

func testSignUpRejectsBlankEmailOrPassword(t *testing.T) {
	testCases := []struct {
		name        string
		email       string
		password    string
		assertEmail string
	}{
		{name: "blank email", email: "", password: "example-password", assertEmail: ""},
		{name: "blank password", email: "blank-password@example.com", password: "", assertEmail: "blank-password@example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps := setupUserIntegrationDeps(t)

			rec := testutil.PerformJSONRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
				"email":    tc.email,
				"password": tc.password,
			})

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
			}

			gotErr := decodeErrorResponse(t, rec)
			if gotErr.Error != "email and password may not be blank" {
				t.Fatalf("got error %q, want %q", gotErr.Error, "email and password may not be blank")
			}

			if tc.assertEmail == "" {
				userCount := countUsers(t, deps.pool)
				if userCount != 0 {
					t.Fatalf("got %d users in database, want 0", userCount)
				}
				return
			}

			assertNoUserWithEmail(t, deps.queries, tc.assertEmail)
		})
	}
}

func testSignUpRejectsInvalidEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	email := "invalid"
	rec := testutil.PerformJSONRequest(deps.signUp, http.MethodPost, "/signup", map[string]string{
		"email":    email,
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email is not valid" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email is not valid")
	}

	userCount := countUsers(t, deps.pool)
	if userCount != 0 {
		t.Fatalf("got %d users in database, want 0", userCount)
	}
}

func testLogInSucceeds(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	_, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	storedUser, err := deps.queries.GetUserByEmail(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("failed to load seeded user from database: %v", err)
	}

	if storedUser.Email != "test@example.com" {
		t.Fatalf("got stored email %q, want %q", storedUser.Email, "test@example.com")
	}

	if storedUser.PasswordHash == "" {
		t.Fatal("expected stored password hash to be present")
	}

	rec := testutil.PerformJSONRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    "test@example.com",
		"password": "example-password",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	// TODO: Assert session created.
}

func testLogInRejectsInvalidEmail(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := testutil.PerformJSONRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    "invalid",
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Email != "email is not valid" {
		t.Fatalf("got email error %q, want %q", gotErr.Email, "email is not valid")
	}
}

func testLogInReturnsBadRequestWhenUserDoesNotExist(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := testutil.PerformJSONRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    "missing@example.com",
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}
}

func testLogInReturnsBadRequestWhenPasswordIsIncorrect(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	_, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "wrong-password@example.com",
		Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	rec := testutil.PerformJSONRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    "wrong-password@example.com",
		"password": "incorrect-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	gotErr := decodeErrorResponse(t, rec)
	if gotErr.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", gotErr.Error, "authentication failed")
	}
}

func setupUserIntegrationDeps(t *testing.T) userIntegrationDeps {
	t.Helper()

	dsn := testutil.GetIntegrationTestDSN(t)

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("failed to create database pool: %v", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatalf("failed to ping database: %v", err)
	}

	t.Cleanup(func() {
		testutil.CleanupIntegrationTables(t, pool)
		pool.Close()
	})

	queries := db.New(pool)
	userService := user.NewService(queries)
	sessionService := session.NewService(queries)

	return userIntegrationDeps{
		pool:        pool,
		queries:     queries,
		userService: userService,
		signUp:      CreateSignUpHandler(userService, sessionService),
		login:       CreateLoginHandler(userService, sessionService),
	}
}

type apiErrorResponse struct {
	Error string `json:"error"`
	Email string `json:"email"`
}

func decodeErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) apiErrorResponse {
	t.Helper()

	var got apiErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	return got
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

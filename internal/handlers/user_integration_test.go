package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/matthewhartstonge/argon2"
)

const integrationTestDSNEnvVar = "INTEGRATION_TEST_DB_DSN"

type userIntegrationDeps struct {
	pool        *pgxpool.Pool
	queries     *db.Queries
	userService *service.UserService
	signUp      http.HandlerFunc
	login       http.HandlerFunc
}

func TestSignUpIntegration(t *testing.T) {
	t.Run("sign up succeeds and persists user", testSignUpSucceedsAndPersistsUser)
}

func TestLogInIntegration(t *testing.T) {
	t.Run("login succeeds with valid credentials", testLogInSucceeds)
	t.Run("returns bad request when user does not exist", testLogInReturnsBadRequestWhenUserDoesNotExist)
}

func testSignUpSucceedsAndPersistsUser(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	input := map[string]string{
		"email":    "signup@example.com",
		"password": "example-password",
	}

	rec := performJSONRequest(deps.signUp, http.MethodPost, "/signup", input)
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

func testLogInSucceeds(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	_, err := deps.userService.SignUp(context.Background(), service.SignUpInput{
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

	rec := performJSONRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    "test@example.com",
		"password": "example-password",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusOK)
	}

	// TODO: Assert session created.
}

func testLogInReturnsBadRequestWhenUserDoesNotExist(t *testing.T) {
	deps := setupUserIntegrationDeps(t)

	rec := performJSONRequest(deps.login, http.MethodPost, "/login", map[string]string{
		"email":    "missing@example.com",
		"password": "example-password",
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}

	var got errorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}

	if got.Error != "authentication failed" {
		t.Fatalf("got error %q, want %q", got.Error, "authentication failed")
	}
}

func setupUserIntegrationDeps(t *testing.T) userIntegrationDeps {
	t.Helper()

	dsn := os.Getenv(integrationTestDSNEnvVar)
	if dsn == "" {
		t.Errorf("%s is required for integration tests", integrationTestDSNEnvVar)
	}

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("failed to create database pool: %v", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Fatalf("failed to ping database: %v", err)
	}

	queries := db.New(pool)
	userService := service.NewUserService(queries)

	t.Cleanup(func() {
		cleanupIntegrationTables(t, pool)
		pool.Close()
	})

	return userIntegrationDeps{
		pool:        pool,
		queries:     queries,
		userService: userService,
		signUp:      CreateSignUpHandler(userService),
		login:       CreateLoginHandler(userService),
	}
}

func cleanupIntegrationTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(context.Background(), "TRUNCATE TABLE sessions RESTART IDENTITY")
	if err != nil {
		t.Fatalf("failed to clean sessions table: %v", err)
	}

	_, err = pool.Exec(context.Background(), "TRUNCATE TABLE users RESTART IDENTITY")
	if err != nil {
		t.Fatalf("failed to clean users table: %v", err)
	}
}

func performJSONRequest(handler http.Handler, method string, path string, body any) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	return rec
}

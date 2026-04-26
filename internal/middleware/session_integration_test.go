package middleware

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"
	"devinhadley/gobootstrapweb/internal/utils/testutil"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestValidSession(t *testing.T) {
}

func TestExpiredSession(t *testing.T) {
}

func testValidSessionAuthenticatesCorrectUser(t *testing.T) {
	deps := getTestDependencies(t)

	createdUser, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	session, err := deps.sessionService.CreateSession(context.Background(), createdUser)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		user, err := UserFromContext(r.Context())
		if err != nil {
			t.Fatalf("failed to get user from context %v", err)
		}

		if createdUser.ID != user.ID {
			t.Fatalf("expected user from context to have id %v, got %v", createdUser.ID, user.ID)
		}

		utils.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := CreateSessionMiddleware(deps.userService, deps.sessionService, handler)

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(session.DBSession().ID),
		Expires:  session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := testutil.PerformJSONRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}
}

type sessionIntegrationTestDependencies struct {
	userService    user.Service
	sessionService session.Service
	queries        db.Queries
}

func getTestDependencies(t *testing.T) sessionIntegrationTestDependencies {
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

	return sessionIntegrationTestDependencies{queries: *queries, userService: *user.NewService(queries), sessionService: *session.NewService(queries)}
}

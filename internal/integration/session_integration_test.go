package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/email"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/web"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSessionMiddlewareCanAuthenticateIntegration(t *testing.T) {
	t.Run("a cookie with a valid session can be used to authenticate", testValidSessionAuthenticatesCorrectUser)
}

func TestSessionMiddlewareCannotAuthenticateIntegration(t *testing.T) {
	t.Run("a cookie with no session is not authenticated", testNoSessionCookieContinuesUnauthenticated)
	t.Run("a cookie with malformed session id is not authenticated", testMalformedSessionCookieContinuesUnauthenticated)
	t.Run("a cookie with valid format, but non-existant session id is not authenticated", testSessionIDNotFoundContinuesUnauthenticated)
	t.Run("a cookie with valid session, but inactive user is not authenticated", testValidSessionButUserInactive)
}

func TestExpiredSessionIntegration(t *testing.T) {
	t.Run("an absolutely expired session is deactivated and user not authenticated", testAbsoluteExpiration)
	t.Run("an idle expired session is deactivated and user not authenticated", testIdleExpiration)
}

func TestRotateSessionIntegration(t *testing.T) {
	t.Run("session outside rotation threshold rotates and sets new cookie", testSessionRotation)
}

func TestCreateSessionIntegration(t *testing.T) {
	t.Run("creating eleventh session deactivates only least recently used session", testCreateSessionDeactivatesOnlyLeastRecentlyUsedSessionWhenLimitExceeded)
}

func TestUpdateLastSeenIntegration(t *testing.T) {
	t.Run("update last seen succeeds when threshold reached", testUpdateLastSeenWhenThresholdReached)
}

func testValidSessionAuthenticatesCorrectUser(t *testing.T) {
	deps := getTestDependencies(t)
	ctx := context.Background()

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	createdSession, err := deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		user, err := middleware.UserFromRequest(r)
		if err != nil {
			t.Fatalf("failed to get user from context %v", err)
		}

		if createdUser.DBUser().ID != user.DBUser().ID {
			t.Fatalf("expected user from context to have id %v, got %v", createdUser.DBUser().ID, user.DBUser().ID)
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(createdSession.RawID),
		Expires:  createdSession.Session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	sessionAfterRequest, err := deps.sessionService.GetSession(ctx, createdSession.RawID)
	if err != nil {
		t.Fatalf("error when ensuring session still exists with same id %v", err)
	}

	// Ensure session ID and last seen remain the same...
	// I.e. no rotation and no last-seen update needed.
	if !bytes.Equal(sessionAfterRequest.DBSession().ID, createdSession.Session.DBSession().ID) {
		t.Fatalf("expected session id to remain %v, got %v", createdSession.Session.DBSession().ID, sessionAfterRequest.DBSession().ID)
	}

	// Ensure last seen at was not updated as it was within threshold...
	if !sessionAfterRequest.DBSession().LastSeenAt.Time.Equal(createdSession.Session.DBSession().LastSeenAt.Time) {
		t.Fatalf("expected last seen to remain %v, got %v", createdSession.Session.DBSession().LastSeenAt.Time, sessionAfterRequest.DBSession().LastSeenAt.Time)
	}
}

func testNoSessionCookieContinuesUnauthenticated(t *testing.T) {
	deps := getTestDependencies(t)
	handlerCalled := false

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := middleware.UserFromRequest(r)
		if !errors.Is(err, middleware.ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", middleware.ErrUserNotInContext, err)
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	res := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{})

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testMalformedSessionCookieContinuesUnauthenticated(t *testing.T) {
	deps := getTestDependencies(t)
	handlerCalled := false

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := middleware.UserFromRequest(r)
		if !errors.Is(err, middleware.ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", middleware.ErrUserNotInContext, err)
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    "!!!!",
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testSessionIDNotFoundContinuesUnauthenticated(t *testing.T) {
	deps := getTestDependencies(t)
	handlerCalled := false

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := middleware.UserFromRequest(r)
		if !errors.Is(err, middleware.ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", middleware.ErrUserNotInContext, err)
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString([]byte("missing-session!")),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}
}

func testValidSessionButUserInactive(t *testing.T) {
	deps := getTestDependencies(t)
	ctx := context.Background()
	handlerCalled := false

	usr, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-very-very-secure-password",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}

	createdSession, err := deps.sessionService.CreateSession(ctx, usr.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	query := `
	UPDATE users
	SET is_active = false
	WHERE id = $1;
	`
	tag, err := deps.pool.Exec(ctx, query, usr.DBUser().ID)
	if err != nil {
		t.Fatalf("err when setting user to inactive: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("expected 1 row to be affected but got %v", tag.RowsAffected())
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true

		_, err := middleware.UserFromRequest(r)
		if !errors.Is(err, middleware.ErrUserNotInContext) {
			t.Fatalf("expected error %v, got %v", middleware.ErrUserNotInContext, err)
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(createdSession.RawID),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	if !handlerCalled {
		t.Fatal("expected next handler to be called")
	}

	foundClearedCookie := false
	for _, cookie := range res.Result().Cookies() {
		if cookie.Name == "id" {
			foundClearedCookie = true
			if cookie.MaxAge != -1 {
				t.Fatalf("expected cleared session cookie max age -1, got %d", cookie.MaxAge)
			}
		}
	}

	if !foundClearedCookie {
		t.Fatal("expected middleware to clear session cookie")
	}

	assertSessionActiveState(t, deps, createdSession.Session.DBSession().ID, true)
}

func testAbsoluteExpiration(t *testing.T) {
	deps := getTestDependencies(t)

	createdUser, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	session, err := deps.sessionService.CreateSession(context.Background(), createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	makeSessionAbsolutelyExpired(t, deps, session.Session.DBSession().ID)

	handler := func(w http.ResponseWriter, r *http.Request) {
		currentUser, err := middleware.UserFromRequest(r)
		if currentUser != (user.User{}) {
			t.Fatalf("wanted empty user but got %v", currentUser)
		}
		if !errors.Is(err, middleware.ErrUserNotInContext) {
			t.Fatalf("wanted error %v but got %v", middleware.ErrUserNotInContext, err)
		}
		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(session.RawID),
		Expires:  session.Session.GetAbsoluteExpiration(), // not testing
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	rec := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("wanted response status code %v, got %v", http.StatusOK, rec.Result().StatusCode)
	}

	assertSessionActiveState(t, deps, session.Session.DBSession().ID, false)

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
		t.Fatal("expected middleware to clear session cookie")
	}
}

func testIdleExpiration(t *testing.T) {
	deps := getTestDependencies(t)

	createdUser, err := deps.userService.SignUp(context.Background(), user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	session, err := deps.sessionService.CreateSession(context.Background(), createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	makeSessionIdleExpired(t, deps, session.Session.DBSession().ID)

	handler := func(w http.ResponseWriter, r *http.Request) {
		currentUser, err := middleware.UserFromRequest(r)
		if currentUser != (user.User{}) {
			t.Fatalf("wanted empty user but got %v", currentUser)
		}
		if !errors.Is(err, middleware.ErrUserNotInContext) {
			t.Fatalf("wanted error %v but got %v", middleware.ErrUserNotInContext, err)
		}
		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(session.RawID),
		Expires:  session.Session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	rec := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("wanted response status code %v, got %v", http.StatusOK, rec.Result().StatusCode)
	}

	assertSessionActiveState(t, deps, session.Session.DBSession().ID, false)

	foundClearedCookie := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			foundClearedCookie = true
			if cookie.MaxAge != -1 {
				t.Fatalf("expected cleared session cookie max age -1, got %d", cookie.MaxAge)
			}
		}
	}

	if !foundClearedCookie {
		t.Fatal("expected middleware to clear session cookie")
	}
}

func testSessionRotation(t *testing.T) {
	deps := getTestDependencies(t)
	ctx := context.Background()

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}
	createdSession, err := deps.sessionService.CreateSession(context.Background(), createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	makeSessionNeedRefresh(t, deps, createdSession.Session.DBSession().ID)

	handler := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := middleware.UserFromRequest(r)
		if err != nil {
			t.Fatalf("wanted no error when getting user but got %v", err)
		}

		if user.DBUser().ID != createdUser.DBUser().ID {
			t.Fatalf("wanted user id %v but got %v", createdUser.DBUser().ID, user.DBUser().ID)
		}

		w.WriteHeader(http.StatusOK)
	}))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(createdSession.RawID),
		Expires:  createdSession.Session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	rec := performJsonRequest(handler, http.MethodPost, "/test", map[string]any{}, &sessionCookie)

	if rec.Result().StatusCode != http.StatusOK {
		t.Fatalf("wanted status %v but got %v", http.StatusOK, rec.Result().StatusCode)
	}

	var rotatedSessionID []byte
	foundRotatedCookie := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			foundRotatedCookie = true
			rotatedSessionID, err = base64.StdEncoding.DecodeString(cookie.Value)
			if err != nil {
				t.Fatalf("failed to decode rotated session cookie: %v", err)
			}
			break
		}
	}

	if !foundRotatedCookie {
		t.Fatal("expected middleware to set rotated session cookie")
	}

	sessionAfterRotation, err := deps.sessionService.GetSession(ctx, rotatedSessionID)
	if err != nil {
		t.Fatalf("failed to get rotated session %v", err)
	}

	_, err = deps.sessionService.GetSession(ctx, createdSession.RawID)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("expected old session id to be missing with %v but got %v", session.ErrSessionNotFound, err)
	}

	if bytes.Equal(sessionAfterRotation.DBSession().ID, createdSession.Session.DBSession().ID) {
		t.Fatalf("session id didn't change: %v", sessionAfterRotation.DBSession().ID)
	}

	if !sessionAfterRotation.DBSession().LastRefreshedAt.Time.After(createdSession.Session.DBSession().LastRefreshedAt.Time) {
		t.Fatalf("wanted last refresh date: %v to be later after update but got %v", createdSession.Session.DBSession().LastRefreshedAt.Time, sessionAfterRotation.DBSession().LastRefreshedAt.Time)
	}
}

func testCreateSessionDeactivatesOnlyLeastRecentlyUsedSessionWhenLimitExceeded(t *testing.T) {
	deps := getTestDependencies(t)
	ctx := context.Background()

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}

	sessions := make([]session.CreateSessionResult, 0, 10)
	for range 10 {
		createdSession, createErr := deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
		if createErr != nil {
			t.Fatalf("failed to create test session %v", createErr)
		}

		sessions = append(sessions, createdSession)
	}

	makeSessionLastSeenEarlier(t, deps, sessions[0].Session.DBSession().ID)

	eleventhSession, err := deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create eleventh session %v", err)
	}

	assertSessionActiveState(t, deps, sessions[0].Session.DBSession().ID, false)

	_, err = deps.sessionService.GetSession(ctx, sessions[0].RawID)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Fatalf("wanted error %v for deactivated session, got %v", session.ErrSessionNotFound, err)
	}

	for i := 1; i < len(sessions); i++ {
		assertSessionActiveState(t, deps, sessions[i].Session.DBSession().ID, true)
	}

	assertSessionActiveState(t, deps, eleventhSession.Session.DBSession().ID, true)
}

func testUpdateLastSeenWhenThresholdReached(t *testing.T) {
	deps := getTestDependencies(t)
	ctx := context.Background()

	createdUser, err := deps.userService.SignUp(ctx, user.AuthenticateBody{
		Email:    "test@example.com",
		Password: "a-password-!-9999",
	})
	if err != nil {
		t.Fatalf("failed to create test user %v", err)
	}

	createdSession, err := deps.sessionService.CreateSession(ctx, createdUser.DBUser().ID)
	if err != nil {
		t.Fatalf("failed to create test session %v", err)
	}

	makeSessionLastSeenEarlier(t, deps, createdSession.Session.DBSession().ID)

	refetchedSession, err := deps.sessionService.GetSession(ctx, createdSession.RawID)
	if err != nil {
		t.Fatalf("failed to fetch aged session %v", err)
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		currentUser, userErr := middleware.UserFromRequest(r)
		if userErr != nil {
			t.Fatalf("failed to get user from context %v", userErr)
		}

		if currentUser.DBUser().ID != createdUser.DBUser().ID {
			t.Fatalf("expected user from context to have id %v, got %v", createdUser.DBUser().ID, currentUser.DBUser().ID)
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{"status": "ok"})
	}

	sessionMiddleware := middleware.CreateSessionMiddleware(&deps.userService, &deps.sessionService, http.HandlerFunc(handler))

	sessionCookie := http.Cookie{
		Name:     "id",
		Value:    base64.StdEncoding.EncodeToString(createdSession.RawID),
		Expires:  createdSession.Session.GetAbsoluteExpiration(),
		HttpOnly: true,
		Path:     "/",
		Secure:   false,
	}

	res := performJsonRequest(sessionMiddleware, http.MethodGet, "/test", map[string]any{}, &sessionCookie)

	if res.Code != http.StatusOK {
		t.Fatalf("expected status ok, got %v", res.Code)
	}

	sessionAfterRequest, err := deps.sessionService.GetSession(ctx, createdSession.RawID)
	if err != nil {
		t.Fatalf("error when ensuring session still exists with same id %v", err)
	}

	if !bytes.Equal(sessionAfterRequest.DBSession().ID, createdSession.Session.DBSession().ID) {
		t.Fatalf("expected session id to remain %v, got %v", createdSession.Session.DBSession().ID, sessionAfterRequest.DBSession().ID)
	}

	if !sessionAfterRequest.DBSession().LastSeenAt.Time.After(refetchedSession.DBSession().LastSeenAt.Time) {
		t.Fatalf("expected last seen to be updated after %v, got %v", refetchedSession.DBSession().LastSeenAt.Time, sessionAfterRequest.DBSession().LastSeenAt.Time)
	}
}

func needsImplemented(t *testing.T) {
	t.Skip("needs implemented")
}

func makeSessionAbsolutelyExpired(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte) {
	t.Helper()

	fourMonthsAgo := time.Now().AddDate(0, -4, 0)

	query := `
	UPDATE sessions
	SET created_at = $2
	WHERE id = $1;
	`
	tag, err := deps.pool.Exec(context.Background(), query, sessionId, fourMonthsAgo)
	if err != nil {
		t.Fatalf("failed to make session absolutely expired %v", err)
	}

	if tag.RowsAffected() != 1 {
		t.Fatalf("wanted 1 row affected when expiring session, got %d", tag.RowsAffected())
	}
}

func makeSessionIdleExpired(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte) {
	t.Helper()

	fifteenDaysAgo := time.Now().AddDate(0, 0, -15)

	query := `
	UPDATE sessions
	SET created_at = $2,
	    last_seen_at = $2
	WHERE id = $1;
	`
	tag, err := deps.pool.Exec(context.Background(), query, sessionId, fifteenDaysAgo)
	if err != nil {
		t.Fatalf("failed to make session idle expired %v", err)
	}

	if tag.RowsAffected() != 1 {
		t.Fatalf("wanted 1 row affected when idling session, got %d", tag.RowsAffected())
	}
}

func makeSessionNeedRefresh(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte) {
	t.Helper()

	eightDaysAgo := time.Now().AddDate(0, 0, -8)

	query := `
	UPDATE sessions
	SET created_at = $2,
	    last_refreshed_at = $2
	WHERE id = $1;
	`
	tag, err := deps.pool.Exec(context.Background(), query, sessionId, eightDaysAgo)
	if err != nil {
		t.Fatalf("failed to make session idle expired %v", err)
	}

	if tag.RowsAffected() != 1 {
		t.Fatalf("wanted 1 row affected when idling session, got %d", tag.RowsAffected())
	}
}

func makeSessionLastSeenEarlier(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte) {
	t.Helper()

	aFewDaysEarlier := time.Now().AddDate(0, 0, -5)
	query := `
	UPDATE sessions
	SET created_at = $2,
	    last_seen_at = $2
	WHERE id = $1;
	`

	tag, err := deps.pool.Exec(context.Background(), query, sessionId, aFewDaysEarlier)
	if err != nil {
		t.Fatalf("error when making session last seen earlier: %v", err)
	}

	if tag.RowsAffected() != 1 {
		t.Fatalf("wanted 1 row affected when idling session, got %d", tag.RowsAffected())
	}
}

func assertSessionActiveState(t *testing.T, deps sessionIntegrationTestDependencies, sessionId []byte, expectedIsActive bool) {
	t.Helper()

	query := `
	SELECT is_active
	FROM sessions
	WHERE id = $1;
	`
	row := deps.pool.QueryRow(context.Background(), query, sessionId)

	var isActive bool
	err := row.Scan(&isActive)
	if err != nil {
		t.Fatalf("failed to get session is_active when asserting state %v", err)
	}

	if isActive != expectedIsActive {
		t.Fatalf("wanted session is_active %v, got %v", expectedIsActive, isActive)
	}
}

type sessionIntegrationTestDependencies struct {
	userService    user.Service
	sessionService session.Service
	pool           *pgxpool.Pool
	queries        db.Queries
}

func getTestDependencies(t *testing.T) sessionIntegrationTestDependencies {
	pool := getIntegrationTestPool(t)

	t.Cleanup(func() {
		cleanupIntegrationTables(t, pool)
	})

	queries := db.New(pool)
	txnGenerator := user.CreateUserServiceTxnGenerator(pool, queries)
	sessionService := session.NewService(queries)

	return sessionIntegrationTestDependencies{queries: *queries, userService: *user.NewService(queries, txnGenerator, email.MailHogService{}, user.Config{PasswordResetURL: "http://example.com/password-reset"}), sessionService: *sessionService, pool: pool}
}

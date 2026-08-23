package middleware

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5/pgtype"
)

func TestCreateSessionMiddlewareErrorFlows(t *testing.T) {
	t.Run("rotate session error proceeds as best effort", testRotateSessionErrorProceedsBestEffort)
	t.Run("expired session error still clears cookie and continues", testExpiredSessionExpireErrorClearsCookie)
	t.Run("update last seen error still authenticates", testUpdateLastSeenErrorStillAuthenticates)
}

func TestCreateSessionMiddlewareFlowControl(t *testing.T) {
	t.Run("rotation success updates last seen with rotated id", testRotationSuccessUpdatesLastSeenWithRotatedID)
}

func testRotateSessionErrorProceedsBestEffort(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("session-id-123456")
	rotateErr := errors.New("rotate failed")

	updateLastSeenCalled := false
	nextCalled := false

	mockUserID := int64(42)
	mockUser := user.UserFromDB(db.User{
		ID: mockUserID,
	})

	mockLastRefreshedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -8),
		Valid: true,
	}

	mockCreatedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -30),
		Valid: true,
	}

	mockLastSeenAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -3),
		Valid: true,
	}

	mockSession := session.SessionFromDB(
		db.Session{
			ID:              originalID,
			UserID:          mockUserID,
			CreatedAt:       mockCreatedAt,
			LastRefreshedAt: mockLastRefreshedAt,
			LastSeenAt:      mockLastSeenAt,
		},
	)

	userService := user.MockService{
		GetUserByIDFn: func(ctx context.Context, id int64) (user.User, error) {
			if id != mockUserID {
				t.Fatalf("wanted user id %v, got %v", mockUserID, id)
			}
			return mockUser, nil
		},
	}
	sessionService := session.MockService{
		GetSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			return mockSession, nil
		},
		ExpireSessionFn: func(ctx context.Context, sessionID []byte) error {
			t.Fatalf("expected expire session not to be called.")
			return nil
		},
		RotateSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			return session.Session{}, rotateErr
		},
		UpdateLastSeenFn: func(ctx context.Context, s session.Session) error {
			updateLastSeenCalled = true
			return nil
		},
	}

	handler := CreateSessionMiddleware(userService, sessionService, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		usr, err := UserFromRequest(r)
		if err != nil {
			t.Fatalf("expected authenticated user, got error %v", err)
		}
		if usr.DBUser().ID != 42 {
			t.Fatalf("expected user id 42, got %v", usr.DBUser().ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}
	if !updateLastSeenCalled {
		t.Fatal("expected update last seen to be called")
	}

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			t.Fatal("expected no rotated session cookie on rotate failure")
		}
	}
}

func testExpiredSessionExpireErrorClearsCookie(t *testing.T) {
	originalID := []byte("session-id-123456")
	expireErr := errors.New("expire failed")
	nextCalled := false

	mockCreatedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -91),
		Valid: true,
	}

	mockLastRefreshedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -8),
		Valid: true,
	}

	mockLastSeenAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -1),
		Valid: true,
	}

	mockSession := session.SessionFromDB(
		db.Session{
			ID:              originalID,
			UserID:          42,
			CreatedAt:       mockCreatedAt,
			LastRefreshedAt: mockLastRefreshedAt,
			LastSeenAt:      mockLastSeenAt,
		},
	)

	userService := user.MockService{}
	sessionService := session.MockService{
		GetSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			return mockSession, nil
		},
		ExpireSessionFn: func(ctx context.Context, sessionID []byte) error {
			return expireErr
		},
		RotateSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			t.Fatalf("expected rotate session not to be called")
			return session.Session{}, nil
		},
		UpdateLastSeenFn: func(ctx context.Context, s session.Session) error {
			t.Fatalf("expected update last seen not to be called")
			return nil
		},
	}

	handler := CreateSessionMiddleware(userService, sessionService, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		if _, err := UserFromRequest(r); !errors.Is(err, ErrUserNotInContext) {
			t.Fatalf("expected no user in context, got %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}

	foundClearedCookie := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "id" {
			foundClearedCookie = true
			if cookie.MaxAge != -1 {
				t.Fatalf("expected cleared cookie max age -1, got %d", cookie.MaxAge)
			}
		}
	}
	if !foundClearedCookie {
		t.Fatal("expected session cookie to be cleared")
	}
}

func testUpdateLastSeenErrorStillAuthenticates(t *testing.T) {
	originalID := []byte("session-id-123456")
	updateErr := errors.New("update last seen failed")
	nextCalled := false
	rotateCalled := false

	mockUserID := int64(42)
	mockUser := user.UserFromDB(db.User{
		ID: mockUserID,
	})

	mockCreatedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -2),
		Valid: true,
	}

	mockLastRefreshedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -8),
		Valid: true,
	}

	mockLastSeenAt := pgtype.Timestamptz{
		Time:  time.Now().Add(-25 * time.Minute),
		Valid: true,
	}

	mockSession := session.SessionFromDB(
		db.Session{
			ID:              originalID,
			UserID:          mockUserID,
			CreatedAt:       mockCreatedAt,
			LastRefreshedAt: mockLastRefreshedAt,
			LastSeenAt:      mockLastSeenAt,
		},
	)

	userService := user.MockService{
		GetUserByIDFn: func(ctx context.Context, id int64) (user.User, error) {
			if id != mockUserID {
				t.Fatalf("GetUserByID got id %v, want %v", id, mockUserID)
			}

			return mockUser, nil
		},
	}

	sessionService := session.MockService{
		GetSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			return mockSession, nil
		},
		ExpireSessionFn: func(ctx context.Context, sessionID []byte) error {
			t.Fatalf("expected expire session not to be called")
			return nil
		},
		RotateSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			rotateCalled = true
			return mockSession, nil
		},
		UpdateLastSeenFn: func(ctx context.Context, s session.Session) error {
			return updateErr
		},
	}

	handler := CreateSessionMiddleware(userService, sessionService, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		usr, err := UserFromRequest(r)
		if err != nil {
			t.Fatalf("expected authenticated user, got error %v", err)
		}
		if usr.DBUser().ID != 42 {
			t.Fatalf("expected user id 42, got %v", usr.DBUser().ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !nextCalled {
		t.Fatal("expected next handler to be called")
	}

	if !rotateCalled {
		t.Fatal("expected rotate session to be called")
	}
}

func testRotationSuccessUpdatesLastSeenWithRotatedID(t *testing.T) {
	originalID := []byte("session-id-123456")
	rotatedID := []byte("rotated-session-1")

	updateLastSeenCalled := false

	mockCreatedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -2),
		Valid: true,
	}

	mockLastSeenAt := pgtype.Timestamptz{
		Time:  time.Now().Add(-25 * time.Minute),
		Valid: true,
	}

	mockLastRefreshedAt := pgtype.Timestamptz{
		Time:  time.Now().AddDate(0, 0, -8),
		Valid: true,
	}

	rotatedLastRefreshedAt := pgtype.Timestamptz{
		Time:  time.Now(),
		Valid: true,
	}

	mockSession := session.SessionFromDB(db.Session{
		ID:              originalID,
		UserID:          42,
		CreatedAt:       mockCreatedAt,
		LastSeenAt:      mockLastSeenAt,
		LastRefreshedAt: mockLastRefreshedAt,
	})

	rotatedSession := session.SessionFromDB(db.Session{
		ID:              rotatedID,
		UserID:          42,
		CreatedAt:       mockCreatedAt,
		LastSeenAt:      mockLastSeenAt,
		LastRefreshedAt: rotatedLastRefreshedAt,
	})

	userService := user.MockService{}

	sessionService := session.MockService{
		GetSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			return mockSession, nil
		},
		ExpireSessionFn: func(ctx context.Context, sessionID []byte) error {
			t.Fatalf("expected expire session not to be called")
			return nil
		},
		RotateSessionFn: func(ctx context.Context, sessionID []byte) (session.Session, error) {
			return rotatedSession, nil
		},
		UpdateLastSeenFn: func(ctx context.Context, s session.Session) error {
			updateLastSeenCalled = true
			if string(s.DBSession().ID) != string(rotatedID) {
				t.Fatalf("UpdateLastSeen got id %v, want %v", s.DBSession().ID, rotatedID)
			}
			return nil
		},
	}

	handler := CreateSessionMiddleware(userService, sessionService, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.AddCookie(&http.Cookie{Name: "id", Value: base64.StdEncoding.EncodeToString(originalID)})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !updateLastSeenCalled {
		t.Fatal("expected update last seen to be called")
	}
}

func TestCreateGetUserFuncCachesUser(t *testing.T) {
	const userID int64 = 42

	callCount := 0
	wantUser := user.UserFromDB(db.User{ID: userID, Email: "test@example.com"})

	userService := user.MockService{
		GetUserByIDFn: func(ctx context.Context, id int64) (user.User, error) {
			callCount++
			if id != userID {
				t.Fatalf("GetUserByID got id %v, want %v", id, userID)
			}

			return wantUser, nil
		},
	}

	getUser := createGetUserFunc(userID, userService, context.Background())

	gotUserOne, err := getUser()
	if err != nil {
		t.Fatalf("first getUser() returned error: %v", err)
	}

	gotUserTwo, err := getUser()
	if err != nil {
		t.Fatalf("second getUser() returned error: %v", err)
	}

	if gotUserOne.DBUser().ID != wantUser.DBUser().ID {
		t.Fatalf("first getUser() got id %v, want %v", gotUserOne.DBUser().ID, wantUser.DBUser().ID)
	}

	if gotUserTwo.DBUser().ID != wantUser.DBUser().ID {
		t.Fatalf("second getUser() got id %v, want %v", gotUserTwo.DBUser().ID, wantUser.DBUser().ID)
	}

	if callCount != 1 {
		t.Fatalf("GetUserByID called %v times, want 1", callCount)
	}
}

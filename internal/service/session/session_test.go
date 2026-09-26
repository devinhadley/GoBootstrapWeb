package session

import (
	"context"
	"errors"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These tests cover DB-error and edge-case paths that are impractical to trigger
// against a real database in the integration suite (arbitrary write failures,
// FK violations, etc). Happy-path and business-logic behavior is covered there instead.

func TestCreateSession(t *testing.T) {
	t.Run("returns user not found for sessions user fk violation", testCreateSessionReturnsUserNotFound)
	t.Run("returns session count error", testCreateSessionReturnsSessionCountError)
	t.Run("returns delete least recently used session error", testCreateSessionReturnsDeleteLeastRecentlyUsedSessionError)
	t.Run("returns create session error", testCreateSessionReturnsCreateSessionError)
}

func TestUpdateLastSeen(t *testing.T) {
	t.Run("returns update error when threshold has elapsed", testUpdateLastSeenReturnsUpdateError)
}

func TestGetSession(t *testing.T) {
	t.Run("returns get session error", testGetSessionReturnsError)
}

func TestDeleteSession(t *testing.T) {
	t.Run("returns expire session error", testDeleteSessionReturnsError)
}

func testCreateSessionReturnsUserNotFound(t *testing.T) {
	ctx := context.Background()
	userID := int64(999)

	sessionService := NewService(&mockQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			return db.Session{}, &pgconn.PgError{
				Code: "23503",
			}
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got error %v, want %v", err, ErrUserNotFound)
	}
}

func testCreateSessionReturnsSessionCountError(t *testing.T) {
	ctx := context.Background()
	userID := int64(99)
	wantErr := errors.New("failed to get session count")

	sessionService := NewService(&mockQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			return 0, wantErr
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			t.Fatal("CreateSession should not be called when getting session count fails")
			return db.Session{}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionReturnsDeleteLeastRecentlyUsedSessionError(t *testing.T) {
	ctx := context.Background()
	userID := int64(42)
	wantErr := errors.New("failed to delete least recently used session")

	sessionService := NewService(&mockQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			return MaxNumberOfActiveSessions, nil
		},
		DeleteLeastRecentlyUsedSessionForUserFn: func(ctx context.Context, userID int64) error {
			return wantErr
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			t.Fatal("CreateSession should not be called when deleting least recently used session fails")
			return db.Session{}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionReturnsCreateSessionError(t *testing.T) {
	ctx := context.Background()
	userID := int64(7)
	wantErr := errors.New("failed to create session")

	sessionService := NewService(&mockQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.CreateSession(ctx, userID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testUpdateLastSeenReturnsUpdateError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("failed to update last seen")

	session := db.Session{
		ID: []byte("session-id"),
	}

	sessionService := NewService(&mockQueries{
		UpdateSessionLastSeenToNowFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	err := sessionService.UpdateLastSeen(ctx, SessionFromDB(session))
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testGetSessionReturnsError(t *testing.T) {
	ctx := context.Background()
	sessionID := []byte("session-id")
	wantErr := errors.New("failed to get session")

	sessionService := NewService(&mockQueries{
		GetSessionFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.GetSession(ctx, sessionID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testDeleteSessionReturnsError(t *testing.T) {
	ctx := context.Background()
	sessionID := []byte("session-id")
	wantErr := errors.New("failed to expire session")

	sessionService := NewService(&mockQueries{
		DeleteSessionFn: func(callCtx context.Context, id []byte) error {
			return wantErr
		},
	})

	err := sessionService.DeleteSession(ctx, sessionID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

type mockQueries struct {
	CreateSessionFn                         func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteLeastRecentlyUsedSessionForUserFn func(ctx context.Context, userID int64) error
	DeleteAllSessionsForUserFn              func(ctx context.Context, userID int64) error
	DeleteSessionFn                         func(ctx context.Context, id []byte) error
	GetSessionFn                            func(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUserFn                 func(ctx context.Context, userID int64) (int64, error)
	UpdateSessionLastSeenToNowFn            func(ctx context.Context, id []byte) (db.Session, error)
}

func (q *mockQueries) CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
	if q.CreateSessionFn != nil {
		return q.CreateSessionFn(ctx, arg)
	}

	return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *mockQueries) DeleteSession(ctx context.Context, id []byte) error {
	if q.DeleteSessionFn != nil {
		return q.DeleteSessionFn(ctx, id)
	}

	return nil
}

func (q *mockQueries) DeleteLeastRecentlyUsedSessionForUser(ctx context.Context, userID int64) error {
	if q.DeleteLeastRecentlyUsedSessionForUserFn != nil {
		return q.DeleteLeastRecentlyUsedSessionForUserFn(ctx, userID)
	}

	return nil
}

func (q *mockQueries) DeleteAllSessionsForUser(ctx context.Context, userID int64) error {
	if q.DeleteAllSessionsForUserFn != nil {
		return q.DeleteAllSessionsForUserFn(ctx, userID)
	}

	return nil
}

func (q *mockQueries) GetSession(ctx context.Context, id []byte) (db.Session, error) {
	if q.GetSessionFn != nil {
		return q.GetSessionFn(ctx, id)
	}

	return db.Session{}, pgx.ErrNoRows
}

func (q *mockQueries) GetSessionCountByUser(ctx context.Context, userID int64) (int64, error) {
	if q.GetSessionCountByUserFn != nil {
		return q.GetSessionCountByUserFn(ctx, userID)
	}

	return 0, nil
}

func (q *mockQueries) UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error) {
	if q.UpdateSessionLastSeenToNowFn != nil {
		return q.UpdateSessionLastSeenToNowFn(ctx, id)
	}

	return db.Session{ID: id}, nil
}

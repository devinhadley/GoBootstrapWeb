package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCreateSession(t *testing.T) {
	t.Run("can create a session", testCreateValidSession)
	t.Run("returns user not found for sessions user fk violation", testCreateSessionReturnsUserNotFound)
	t.Run("deletes oldest session when count is greater than ten", testCreateSessionDeletesOldestWhenSessionCountExceedsLimit)
}

func TestRotateSession(t *testing.T) {
	t.Run("rotates session id", testRotateSession)
	t.Run("returns update error", testRotateSessionReturnsUpdateError)
}

func TestIsSessionExpired(t *testing.T) {
	t.Run("returns false for active session", testIsSessionExpiredFalseForActiveSession)
	t.Run("returns true for absolute expiration", testIsSessionExpiredTrueForAbsoluteExpiration)
	t.Run("returns true for idle expiration", testIsSessionExpiredTrueForIdleExpiration)
}

func TestShouldRotateSession(t *testing.T) {
	t.Run("returns false when rotation not required", testShouldRotateSessionFalse)
	t.Run("returns true when rotation is required", testShouldRotateSessionTrue)
}

func testCreateValidSession(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 1}

	var createSessionArg db.CreateSessionParams

	sessionService := NewSessionService(&mockSessionQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			createSessionArg = arg

			if arg.UserID != user.ID {
				t.Fatalf("CreateSession got user id %v, want %v", arg.UserID, user.ID)
			}

			if len(arg.ID) != 16 {
				t.Fatalf("CreateSession got id length %d, want %d", len(arg.ID), 16)
			}

			return db.Session{
				ID:     arg.ID,
				UserID: arg.UserID,
			}, nil
		},
		DeleteLeastRecentlyUsedSessionByUserFn: func(ctx context.Context, userID int64) error {
			t.Fatalf("delete last recently used should not be called.")
			return nil
		},
	})

	session, err := sessionService.CreateSession(ctx, user)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	if session.UserID != user.ID {
		t.Fatalf("got user id %v, want %v", session.UserID, user.ID)
	}

	if len(session.ID) != 16 {
		t.Fatalf("got id length %d, want %d", len(session.ID), 16)
	}

	if !bytes.Equal(session.ID, createSessionArg.ID) {
		t.Fatal("returned session id does not match id passed to CreateSession")
	}
}

func testCreateSessionReturnsUserNotFound(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 999}

	sessionService := NewSessionService(&mockSessionQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			return db.Session{}, &pgconn.PgError{
				Code:           "23503",
				ConstraintName: "sessions_user_id_fkey",
			}
		},
	})

	_, err := sessionService.CreateSession(ctx, user)
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got error %v, want %v", err, ErrUserNotFound)
	}
}

func testCreateSessionDeletesOldestWhenSessionCountExceedsLimit(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 42}

	deleteOldestCalled := false

	sessionService := NewSessionService(&mockSessionQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			if userID != user.ID {
				t.Fatalf("GetSessionCountByUser got user id %v, want %v", userID, user.ID)
			}

			return 11, nil
		},
		DeleteLeastRecentlyUsedSessionByUserFn: func(ctx context.Context, userID int64) error {
			deleteOldestCalled = true

			if userID != user.ID {
				t.Fatalf("DeleteLeastRecentlyUsedSessionByUser got user id %v, want %v", userID, user.ID)
			}

			return nil
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			if !deleteOldestCalled {
				t.Fatal("DeleteLeastRecentlyUsedSessionByUser should be called before CreateSession")
			}

			return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, user)
	if err != nil {
		t.Fatalf("CreateSession returned error: %v", err)
	}

	if !deleteOldestCalled {
		t.Fatal("DeleteLeastRecentlyUsedSessionByUser was not called")
	}
}

func testRotateSession(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("current-session-id")

	var updateSessionIDArg db.UpdateSessionIDByIDParams

	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionIDByIDFn: func(ctx context.Context, arg db.UpdateSessionIDByIDParams) error {
			updateSessionIDArg = arg

			if !bytes.Equal(arg.ID, originalID) {
				t.Fatalf("UpdateSessionIDByID got id %v, want %v", arg.ID, originalID)
			}

			if len(arg.ID_2) != 16 {
				t.Fatalf("UpdateSessionIDByID got rotated id length %d, want %d", len(arg.ID_2), 16)
			}

			return nil
		},
	})

	rotatedID, err := sessionService.RotateSession(ctx, originalID)
	if err != nil {
		t.Fatalf("RotateSession returned error: %v", err)
	}

	if len(rotatedID) != 16 {
		t.Fatalf("got rotated id length %d, want %d", len(rotatedID), 16)
	}

	if !bytes.Equal(rotatedID, updateSessionIDArg.ID_2) {
		t.Fatal("returned rotated session id does not match id passed to UpdateSessionIDByID")
	}
}

func testRotateSessionReturnsUpdateError(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("current-session-id")
	wantErr := errors.New("failed update")

	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionIDByIDFn: func(ctx context.Context, arg db.UpdateSessionIDByIDParams) error {
			return wantErr
		},
	})

	_, err := sessionService.RotateSession(ctx, originalID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testIsSessionExpiredFalseForActiveSession(t *testing.T) {
	sessionService := NewSessionService(&mockSessionQueries{})

	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -10), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if sessionService.IsSessionExpired(session) {
		t.Fatal("expected session to be active")
	}
}

func testIsSessionExpiredTrueForAbsoluteExpiration(t *testing.T) {
	sessionService := NewSessionService(&mockSessionQueries{})

	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -91), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if !sessionService.IsSessionExpired(session) {
		t.Fatal("expected session to be expired by absolute expiration")
	}
}

func testIsSessionExpiredTrueForIdleExpiration(t *testing.T) {
	sessionService := NewSessionService(&mockSessionQueries{})

	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -10), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -15), Valid: true},
	}

	if !sessionService.IsSessionExpired(session) {
		t.Fatal("expected session to be expired by idle expiration")
	}
}

func testShouldRotateSessionFalse(t *testing.T) {
	sessionService := NewSessionService(&mockSessionQueries{})

	session := db.Session{
		LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if sessionService.ShouldRotateSession(session) {
		t.Fatal("expected session rotation not to be required")
	}
}

func testShouldRotateSessionTrue(t *testing.T) {
	sessionService := NewSessionService(&mockSessionQueries{})

	session := db.Session{
		LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -8), Valid: true},
	}

	if !sessionService.ShouldRotateSession(session) {
		t.Fatal("expected session rotation to be required")
	}
}

type mockSessionQueries struct {
	CreateSessionFn                        func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteLeastRecentlyUsedSessionByUserFn func(ctx context.Context, userID int64) error
	DeleteSessionByIDFn                    func(ctx context.Context, id []byte) error
	GetSessionByIDFn                       func(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUserFn                func(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDByIDFn                  func(ctx context.Context, arg db.UpdateSessionIDByIDParams) error
}

func (q *mockSessionQueries) CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
	if q.CreateSessionFn != nil {
		return q.CreateSessionFn(ctx, arg)
	}

	return db.Session{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *mockSessionQueries) DeleteSessionByID(ctx context.Context, id []byte) error {
	if q.DeleteSessionByIDFn != nil {
		return q.DeleteSessionByIDFn(ctx, id)
	}

	return nil
}

func (q *mockSessionQueries) DeleteLeastRecentlyUsedSessionByUser(ctx context.Context, userID int64) error {
	if q.DeleteLeastRecentlyUsedSessionByUserFn != nil {
		return q.DeleteLeastRecentlyUsedSessionByUserFn(ctx, userID)
	}

	return nil
}

func (q *mockSessionQueries) GetSessionByID(ctx context.Context, id []byte) (db.Session, error) {
	if q.GetSessionByIDFn != nil {
		return q.GetSessionByIDFn(ctx, id)
	}

	return db.Session{}, nil
}

func (q *mockSessionQueries) GetSessionCountByUser(ctx context.Context, userID int64) (int64, error) {
	if q.GetSessionCountByUserFn != nil {
		return q.GetSessionCountByUserFn(ctx, userID)
	}

	return 0, nil
}

func (q *mockSessionQueries) UpdateSessionIDByID(ctx context.Context, arg db.UpdateSessionIDByIDParams) error {
	if q.UpdateSessionIDByIDFn != nil {
		return q.UpdateSessionIDByIDFn(ctx, arg)
	}

	return nil
}

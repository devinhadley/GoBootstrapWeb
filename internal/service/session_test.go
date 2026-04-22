package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestCreateSession(t *testing.T) {
	t.Run("can create a session", testCreateValidSession)
	t.Run("returns user not found for sessions user fk violation", testCreateSessionReturnsUserNotFound)
	t.Run("deletes oldest session when count is greater than ten", testCreateSessionDeletesOldestWhenSessionCountExceedsLimit)
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

type mockSessionQueries struct {
	CreateSessionFn                        func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteLeastRecentlyUsedSessionByUserFn func(ctx context.Context, userID int64) error
	DeleteSessionByIDFn                    func(ctx context.Context, id []byte) error
	GetSessionByIDFn                       func(ctx context.Context, id []byte) (db.GetSessionByIDRow, error)
	GetSessionCountByUserFn                func(ctx context.Context, userID int64) (int64, error)
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

func (q *mockSessionQueries) GetSessionByID(ctx context.Context, id []byte) (db.GetSessionByIDRow, error) {
	if q.GetSessionByIDFn != nil {
		return q.GetSessionByIDFn(ctx, id)
	}

	return db.GetSessionByIDRow{}, nil
}

func (q *mockSessionQueries) GetSessionCountByUser(ctx context.Context, userID int64) (int64, error) {
	if q.GetSessionCountByUserFn != nil {
		return q.GetSessionCountByUserFn(ctx, userID)
	}

	return 0, nil
}

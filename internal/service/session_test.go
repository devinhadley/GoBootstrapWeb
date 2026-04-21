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
}

func testCreateValidSession(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 1}

	var createSessionArg db.CreateSessionParams

	sessionService := CreateSessionService(&mockSessionQueries{
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

	sessionService := CreateSessionService(&mockSessionQueries{
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

type mockSessionQueries struct {
	CreateSessionFn     func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteSessionByIDFn func(ctx context.Context, id []byte) error
	GetSessionByIDFn    func(ctx context.Context, id []byte) (db.Session, error)
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

func (q *mockSessionQueries) GetSessionByID(ctx context.Context, id []byte) (db.Session, error) {
	if q.GetSessionByIDFn != nil {
		return q.GetSessionByIDFn(ctx, id)
	}

	return db.Session{}, nil
}

package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCreateSession(t *testing.T) {
	t.Run("can create a session", testCreateValidSession)
	t.Run("returns user not found for sessions user fk violation", testCreateSessionReturnsUserNotFound)
	t.Run("returns session count error", testCreateSessionReturnsSessionCountError)
	t.Run("returns delete least recently used session error", testCreateSessionReturnsDeleteLeastRecentlyUsedSessionError)
	t.Run("returns create session error", testCreateSessionReturnsCreateSessionError)
	t.Run("deletes oldest session when count is greater than ten", testCreateSessionDeletesOldestWhenSessionCountExceedsLimit)
}

func TestRotateSession(t *testing.T) {
	t.Run("rotates session id", testRotateSession)
	t.Run("returns session not found when session is missing", testRotateSessionReturnsSessionNotFound)
	t.Run("returns update error", testRotateSessionReturnsUpdateError)
}

func TestIsSessionExpired(t *testing.T) {
	t.Run("returns false for active session", testIsSessionExpiredFalseForActiveSession)
	t.Run("returns true for absolute expiration", testIsSessionExpiredTrueForAbsoluteExpiration)
	t.Run("returns true for idle expiration", testIsSessionExpiredTrueForIdleExpiration)
}

func TestShouldRotateSession(t *testing.T) {
	t.Run("returns true when rotation is required", testShouldRotateSessionTrue)
	t.Run("returns false when rotation not required", testShouldRotateSessionFalse)
}

func TestUpdateLastSeen(t *testing.T) {
	t.Run("does not update when threshold has not elapsed", testUpdateLastSeenDoesNotUpdateBeforeThreshold)
	t.Run("updates last seen when threshold has elapsed", testUpdateLastSeenUpdatesAfterThreshold)
	t.Run("returns update error when threshold has elapsed", testUpdateLastSeenReturnsUpdateError)
}

func TestGetSession(t *testing.T) {
	t.Run("returns get session error", testGetSessionReturnsError)
}

func TestExpireSession(t *testing.T) {
	t.Run("returns expire session error", testExpireSessionReturnsError)
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

	rawSession := session.DBSession()

	if rawSession.UserID != user.ID {
		t.Fatalf("got user id %v, want %v", rawSession.UserID, user.ID)
	}

	if len(rawSession.ID) != 16 {
		t.Fatalf("got id length %d, want %d", len(rawSession.ID), 16)
	}

	if !bytes.Equal(rawSession.ID, createSessionArg.ID) {
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

func testCreateSessionReturnsSessionCountError(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 99}
	wantErr := errors.New("failed to get session count")

	sessionService := NewSessionService(&mockSessionQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			return 0, wantErr
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			t.Fatal("CreateSession should not be called when getting session count fails")
			return db.Session{}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, user)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionReturnsDeleteLeastRecentlyUsedSessionError(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 42}
	wantErr := errors.New("failed to delete least recently used session")

	sessionService := NewSessionService(&mockSessionQueries{
		GetSessionCountByUserFn: func(ctx context.Context, userID int64) (int64, error) {
			return MaxNumberOfActiveSessions, nil
		},
		DeleteLeastRecentlyUsedSessionByUserFn: func(ctx context.Context, userID int64) error {
			return wantErr
		},
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			t.Fatal("CreateSession should not be called when deleting least recently used session fails")
			return db.Session{}, nil
		},
	})

	_, err := sessionService.CreateSession(ctx, user)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testCreateSessionReturnsCreateSessionError(t *testing.T) {
	ctx := context.Background()
	user := db.User{ID: 7}
	wantErr := errors.New("failed to create session")

	sessionService := NewSessionService(&mockSessionQueries{
		CreateSessionFn: func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.CreateSession(ctx, user)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
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
		UpdateSessionIDByIDFn: func(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error) {
			updateSessionIDArg = arg

			if !bytes.Equal(arg.ID, originalID) {
				t.Fatalf("UpdateSessionIDByID got id %v, want %v", arg.ID, originalID)
			}

			if len(arg.ID_2) != 16 {
				t.Fatalf("UpdateSessionIDByID got rotated id length %d, want %d", len(arg.ID_2), 16)
			}

			return db.Session{ID: arg.ID_2}, nil
		},
	})

	updatedSessionResult, err := sessionService.RotateSession(ctx, originalID)
	if err != nil {
		t.Fatalf("RotateSession returned error: %v", err)
	}

	rawUpdatedSession := updatedSessionResult.DBSession()

	if len(rawUpdatedSession.ID) != 16 {
		t.Fatalf("got rotated id length %d, want %d", len(rawUpdatedSession.ID), 16)
	}

	if !bytes.Equal(rawUpdatedSession.ID, updateSessionIDArg.ID_2) {
		t.Fatal("returned rotated session id does not match id passed to UpdateSessionIDByID")
	}

	if bytes.Equal(rawUpdatedSession.ID, originalID) {
		t.Fatal("original id matches rotated session id.")
	}
}

func testRotateSessionReturnsUpdateError(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("current-session-id")
	wantErr := errors.New("failed update")

	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionIDByIDFn: func(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error) {
			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.RotateSession(ctx, originalID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testRotateSessionReturnsSessionNotFound(t *testing.T) {
	ctx := context.Background()
	originalID := []byte("missing-session-id")

	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionIDByIDFn: func(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error) {
			return db.Session{}, pgx.ErrNoRows
		},
	})

	_, err := sessionService.RotateSession(ctx, originalID)
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("got error %v, want %v", err, ErrSessionNotFound)
	}
}

func testIsSessionExpiredFalseForActiveSession(t *testing.T) {
	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -10), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if SessionFromDB(session).IsExpired() {
		t.Fatal("expected session to be active")
	}
}

func testIsSessionExpiredTrueForAbsoluteExpiration(t *testing.T) {
	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -91), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if !SessionFromDB(session).IsExpired() {
		t.Fatal("expected session to be expired by absolute expiration")
	}
}

func testIsSessionExpiredTrueForIdleExpiration(t *testing.T) {
	session := db.Session{
		CreatedAt:  pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -10), Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -15), Valid: true},
	}

	if !SessionFromDB(session).IsExpired() {
		t.Fatal("expected session to be expired by idle expiration")
	}
}

func testShouldRotateSessionFalse(t *testing.T) {
	session := db.Session{
		LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -1), Valid: true},
	}

	if SessionFromDB(session).ShouldRotate() {
		t.Fatal("expected session rotation not to be required")
	}
}

func testShouldRotateSessionTrue(t *testing.T) {
	session := db.Session{
		LastRefreshedAt: pgtype.Timestamptz{Time: time.Now().AddDate(0, 0, -8), Valid: true},
	}

	if !SessionFromDB(session).ShouldRotate() {
		t.Fatal("expected session rotation to be required")
	}
}

func testUpdateLastSeenDoesNotUpdateBeforeThreshold(t *testing.T) {
	ctx := context.Background()
	updateCalled := false

	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionLastSeenToNowFn: func(ctx context.Context, id []byte) (db.Session, error) {
			updateCalled = true
			return db.Session{}, nil
		},
	})

	session := db.Session{
		ID:         []byte("session-id"),
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().Add(-(20 * time.Minute) + time.Second), Valid: true},
	}

	err := sessionService.UpdateLastSeen(ctx, SessionFromDB(session))
	if err != nil {
		t.Fatalf("UpdateLastSeen returned error: %v", err)
	}

	if updateCalled {
		t.Fatal("expected last seen not to be updated before threshold")
	}
}

func testUpdateLastSeenUpdatesAfterThreshold(t *testing.T) {
	ctx := context.Background()

	session := db.Session{
		ID:         []byte("session-id"),
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().Add(-(20 * time.Minute) - time.Second), Valid: true},
	}

	updateCalled := false
	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionLastSeenToNowFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			updateCalled = true

			if callCtx != ctx {
				t.Fatal("UpdateSessionLastSeenToNow called with unexpected context")
			}

			if !bytes.Equal(id, session.ID) {
				t.Fatalf("UpdateSessionLastSeenToNow got id %v, want %v", id, session.ID)
			}

			return db.Session{ID: id}, nil
		},
	})

	err := sessionService.UpdateLastSeen(ctx, SessionFromDB(session))
	if err != nil {
		t.Fatalf("UpdateLastSeen returned error: %v", err)
	}

	if !updateCalled {
		t.Fatal("expected last seen to be updated after threshold")
	}
}

func testUpdateLastSeenReturnsUpdateError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("failed to update last seen")

	session := db.Session{
		ID:         []byte("session-id"),
		LastSeenAt: pgtype.Timestamptz{Time: time.Now().Add(-(20 * time.Minute) - time.Second), Valid: true},
	}

	sessionService := NewSessionService(&mockSessionQueries{
		UpdateSessionLastSeenToNowFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			if callCtx != ctx {
				t.Fatal("UpdateSessionLastSeenToNow called with unexpected context")
			}

			if !bytes.Equal(id, session.ID) {
				t.Fatalf("UpdateSessionLastSeenToNow got id %v, want %v", id, session.ID)
			}

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

	sessionService := NewSessionService(&mockSessionQueries{
		GetSessionByIDFn: func(callCtx context.Context, id []byte) (db.Session, error) {
			if callCtx != ctx {
				t.Fatal("GetSessionByID called with unexpected context")
			}

			if !bytes.Equal(id, sessionID) {
				t.Fatalf("GetSessionByID got id %v, want %v", id, sessionID)
			}

			return db.Session{}, wantErr
		},
	})

	_, err := sessionService.GetSession(ctx, sessionID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testExpireSessionReturnsError(t *testing.T) {
	ctx := context.Background()
	sessionID := []byte("session-id")
	wantErr := errors.New("failed to expire session")

	sessionService := NewSessionService(&mockSessionQueries{
		DeleteSessionByIDFn: func(callCtx context.Context, id []byte) error {
			if callCtx != ctx {
				t.Fatal("DeleteSessionByID called with unexpected context")
			}

			if !bytes.Equal(id, sessionID) {
				t.Fatalf("DeleteSessionByID got id %v, want %v", id, sessionID)
			}

			return wantErr
		},
	})

	err := sessionService.ExpireSession(ctx, sessionID)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

type mockSessionQueries struct {
	CreateSessionFn                        func(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteLeastRecentlyUsedSessionByUserFn func(ctx context.Context, userID int64) error
	DeleteSessionByIDFn                    func(ctx context.Context, id []byte) error
	GetSessionByIDFn                       func(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUserFn                func(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDByIDFn                  func(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error)
	UpdateSessionLastSeenToNowFn           func(ctx context.Context, id []byte) (db.Session, error)
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

func (q *mockSessionQueries) UpdateSessionIDByID(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error) {
	if q.UpdateSessionIDByIDFn != nil {
		return q.UpdateSessionIDByIDFn(ctx, arg)
	}

	return db.Session{ID: arg.ID_2}, nil
}

func (q *mockSessionQueries) UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error) {
	if q.UpdateSessionLastSeenToNowFn != nil {
		return q.UpdateSessionLastSeenToNowFn(ctx, id)
	}

	return db.Session{ID: id}, nil
}

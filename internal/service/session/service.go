package session

import (
	"context"
	"crypto/rand"
	"errors"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type SessionQueries interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteLeastRecentlyUsedSessionByUser(ctx context.Context, userID int64) error
	DeleteSessionByID(ctx context.Context, id []byte) error
	GetSessionByID(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUser(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDByID(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error)
	UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error)
}

type Service struct {
	queries SessionQueries
}

func NewService(queries SessionQueries) *Service {
	return &Service{
		queries: queries,
	}
}

var (
	ErrUserNotFound    = errors.New("user not found")
	ErrSessionNotFound = errors.New("session not found")
)

const MaxNumberOfActiveSessions = 10

func (s *Service) CreateSession(ctx context.Context, user db.User) (Session, error) {
	numSessions, err := s.queries.GetSessionCountByUser(ctx, user.ID)
	if err != nil {
		return Session{}, err
	}

	// TODO: Test this behavior especially in integration.
	// Limit number of active user sessions.
	if numSessions >= MaxNumberOfActiveSessions {
		err = s.queries.DeleteLeastRecentlyUsedSessionByUser(ctx, user.ID)
		if err != nil {
			return Session{}, err
		}
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return Session{}, err
	}

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:     sessionID,
		UserID: user.ID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" && pgErr.ConstraintName == "sessions_user_id_fkey" {
			return Session{}, ErrUserNotFound
		}

		return Session{}, err
	}

	return SessionFromDB(session), nil
}

func (s *Service) GetSession(ctx context.Context, sessionID []byte) (Session, error) {
	session, err := s.queries.GetSessionByID(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}

	return SessionFromDB(session), nil
}

func (s *Service) ExpireSession(ctx context.Context, sessionID []byte) error {
	return s.queries.DeleteSessionByID(ctx, sessionID)
}

func (s *Service) UpdateLastSeen(ctx context.Context, session Session) error {
	// Prevents us from updating the session on every request...
	if session.ShouldUpdateLastSeen() {
		_, err := s.queries.UpdateSessionLastSeenToNow(ctx, session.DBSession().ID)
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO: Wrap error with context.
// I.e. rotate session: %v
func (s *Service) RotateSession(ctx context.Context, sessionID []byte) (Session, error) {
	rotatedSessionID, err := generateSessionID()
	if err != nil {
		return Session{}, err
	}

	updatedSession, err := s.queries.UpdateSessionIDByID(ctx, db.UpdateSessionIDByIDParams{
		ID:   sessionID,
		ID_2: rotatedSessionID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}

		return Session{}, err
	}

	return SessionFromDB(updatedSession), nil
}

func generateSessionID() ([]byte, error) {
	sessionID := make([]byte, 16)
	_, err := rand.Read(sessionID)
	if err != nil {
		return nil, err
	}

	return sessionID, nil
}

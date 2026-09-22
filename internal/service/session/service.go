package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/pgerr"

	"github.com/jackc/pgx/v5"
)

type SessionQueries interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeactivateLeastRecentlyUsedSessionForUser(ctx context.Context, userID int64) error
	GetActiveSession(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUser(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDAndRefreshedAt(ctx context.Context, arg db.UpdateSessionIDAndRefreshedAtParams) (db.Session, error)
	UpdateSessionLastSeenToNow(ctx context.Context, id []byte) (db.Session, error)
	DeactivateSession(ctx context.Context, id []byte) error
	DeactivateAllSessionsForUser(ctx context.Context, userID int64) error
}

type Service struct {
	queries SessionQueries
}

type CreateSessionResult struct {
	Session Session
	RawID   []byte
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

func (s *Service) CreateSession(ctx context.Context, userID int64) (CreateSessionResult, error) {
	numSessions, err := s.queries.GetSessionCountByUser(ctx, userID)
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("getting session count: %w", err)
	}

	if numSessions >= MaxNumberOfActiveSessions {
		err = s.queries.DeactivateLeastRecentlyUsedSessionForUser(ctx, userID)
		if err != nil {
			return CreateSessionResult{}, fmt.Errorf("deactivating least recently used session: %w", err)
		}
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return CreateSessionResult{}, fmt.Errorf("generating session id: %w", err)
	}

	sum := sha256.Sum256(sessionID)
	idHash := sum[:]

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:     idHash,
		UserID: userID,
	})
	if err != nil {
		if pgerr.IsForeignKeyViolation(err) {
			return CreateSessionResult{}, ErrUserNotFound
		}

		return CreateSessionResult{}, fmt.Errorf("creating session: %w", err)
	}

	return CreateSessionResult{Session: SessionFromDB(session), RawID: sessionID}, nil
}

func (s *Service) GetSession(ctx context.Context, sessionID []byte) (Session, error) {
	sum := sha256.Sum256(sessionID)
	idHash := sum[:]

	session, err := s.queries.GetActiveSession(ctx, idHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, fmt.Errorf("getting session: %w", err)
	}

	return SessionFromDB(session), nil
}

// ExpireSession expects sessionID to already be the stored hash (e.g. DBSession().ID),
// not the raw session ID from the cookie — unlike GetSession, which hashes internally.
func (s *Service) ExpireSession(ctx context.Context, sessionID []byte) error {
	err := s.queries.DeactivateSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("expiring session: %w", err)
	}

	return nil
}

func (s *Service) UpdateLastSeen(ctx context.Context, session Session) error {
	// Prevents us from updating the session on every request...
	if session.ShouldUpdateLastSeen() {
		_, err := s.queries.UpdateSessionLastSeenToNow(ctx, session.DBSession().ID)
		if err != nil {
			return fmt.Errorf("updating session last seen: %w", err)
		}
	}
	return nil
}

func (s *Service) RotateSession(ctx context.Context, sessionID []byte) (Session, error) {
	rotatedSessionID, err := generateSessionID()
	if err != nil {
		return Session{}, err
	}
	rotatedSessionIDHash := sha256.Sum256(rotatedSessionID)

	updatedSession, err := s.queries.UpdateSessionIDAndRefreshedAt(ctx, db.UpdateSessionIDAndRefreshedAtParams{
		ID:   sessionID,
		ID_2: rotatedSessionIDHash[:],
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}

		return Session{}, fmt.Errorf("rotating session: %w", err)
	}

	updatedSession.ID = rotatedSessionID
	return SessionFromDB(updatedSession), nil
}

func (s *Service) DeactivateAllSessionsForUser(ctx context.Context, userID int64) error {
	err := s.queries.DeactivateAllSessionsForUser(ctx, userID)
	if err != nil {
		return err
	}
	return nil
}

func generateSessionID() ([]byte, error) {
	sessionID := make([]byte, 16)
	_, err := rand.Read(sessionID)
	if err != nil {
		return nil, err
	}

	return sessionID, nil
}

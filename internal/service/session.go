package service

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5/pgconn"
)

type SessionQueries interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteLeastRecentlyUsedSessionByUser(ctx context.Context, userID int64) error
	DeleteSessionByID(ctx context.Context, id []byte) error
	GetSessionByID(ctx context.Context, id []byte) (db.Session, error)
	GetSessionCountByUser(ctx context.Context, userID int64) (int64, error)
	UpdateSessionIDByID(ctx context.Context, arg db.UpdateSessionIDByIDParams) (db.Session, error)
}

type SessionService struct {
	queries SessionQueries
}

func NewSessionService(queries SessionQueries) *SessionService {
	return &SessionService{
		queries: queries,
	}
}

var ErrUserNotFound = errors.New("user not found")

const MaxNumberOfActiveSessions = 10

const (
	sessionAbsoluteExpirationDays = 90
	sessionIdleExpirationDays     = 14
	sessionRotationDays           = 7
)

func (s *SessionService) CreateSession(ctx context.Context, user db.User) (db.Session, error) {
	numSessions, err := s.queries.GetSessionCountByUser(ctx, user.ID)
	if err != nil {
		return db.Session{}, nil
	}

	// TODO: Test this behavior especially in integration.
	// Limit number of active user sessions.
	if numSessions >= MaxNumberOfActiveSessions {
		err = s.queries.DeleteLeastRecentlyUsedSessionByUser(ctx, user.ID)
		if err != nil {
			return db.Session{}, err
		}
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return db.Session{}, err
	}

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:     sessionID,
		UserID: user.ID,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" && pgErr.ConstraintName == "sessions_user_id_fkey" {
			return db.Session{}, ErrUserNotFound
		}

		return db.Session{}, err
	}

	return session, nil
}

func (s *SessionService) GetSession(ctx context.Context, sessionID []byte) (db.Session, error) {
	return s.queries.GetSessionByID(ctx, sessionID)
}

func (s *SessionService) ExpireSession(ctx context.Context, sessionID []byte) error {
	return s.queries.DeleteSessionByID(ctx, sessionID)
}

func (s *SessionService) IsSessionExpired(session db.Session) bool {
	now := time.Now()
	absoluteExpirationDate := session.CreatedAt.Time.AddDate(0, 0, sessionAbsoluteExpirationDays)
	if absoluteExpirationDate.Before(now) {
		return true
	}

	idleExpirationDate := session.LastSeenAt.Time.AddDate(0, 0, sessionIdleExpirationDays)
	return idleExpirationDate.Before(now)
}

func (s *SessionService) ShouldRotateSession(session db.Session) bool {
	rotationRequiredDate := session.LastRefreshedAt.Time.AddDate(0, 0, sessionRotationDays)
	return rotationRequiredDate.Before(time.Now())
}

func (s *SessionService) RotateSession(ctx context.Context, sessionID []byte) (db.Session, error) {
	rotatedSessionID, err := generateSessionID()
	if err != nil {
		return db.Session{}, err
	}

	updatedSession, err := s.queries.UpdateSessionIDByID(ctx, db.UpdateSessionIDByIDParams{
		ID:   sessionID,
		ID_2: rotatedSessionID,
	})
	if err != nil {
		return db.Session{}, err
	}

	return updatedSession, nil
}

func generateSessionID() ([]byte, error) {
	sessionID := make([]byte, 16)
	_, err := rand.Read(sessionID)
	if err != nil {
		return nil, err
	}

	return sessionID, nil
}

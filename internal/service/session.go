package service

import (
	"context"
	"crypto/rand"
	"errors"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5/pgconn"
)

// NOTE:
// Must Haves:
// 128 bit entropy id
// absolute expiration
// idle expiration
// id refresh

type SessionQueries interface {
	CreateSession(ctx context.Context, arg db.CreateSessionParams) (db.Session, error)
	DeleteSessionByID(ctx context.Context, id []byte) error
	GetSessionByID(ctx context.Context, id []byte) (db.Session, error)
}

type SessionService struct {
	queries SessionQueries
}

func CreateSessionService(queries SessionQueries) *SessionService {
	return &SessionService{
		queries: queries,
	}
}

var ErrUserNotFound = errors.New("user not found")

func (s *SessionService) CreateSession(ctx context.Context, user db.User) (db.Session, error) {
	sixteenRandomBytes := make([]byte, 16)
	_, err := rand.Read(sixteenRandomBytes)
	if err != nil {
		return db.Session{}, err
	}

	session, err := s.queries.CreateSession(ctx, db.CreateSessionParams{
		ID:     sixteenRandomBytes,
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

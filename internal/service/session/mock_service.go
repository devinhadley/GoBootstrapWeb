package session

import "context"

type MockService struct {
	CreateSessionFn            func(ctx context.Context, userID int64) (CreateSessionResult, error)
	GetSessionFn               func(ctx context.Context, sessionID []byte) (Session, error)
	DeleteSessionFn            func(ctx context.Context, sessionID []byte) error
	UpdateLastSeenFn           func(ctx context.Context, s Session) error
	RotateSessionFn            func(ctx context.Context, sessionID []byte) (Session, error)
	DeleteAllSessionsForUserFn func(ctx context.Context, userID int64) error
}

func (s MockService) CreateSession(ctx context.Context, userID int64) (CreateSessionResult, error) {
	if s.CreateSessionFn != nil {
		return s.CreateSessionFn(ctx, userID)
	}

	return CreateSessionResult{}, nil
}

func (s MockService) GetSession(ctx context.Context, sessionID []byte) (Session, error) {
	if s.GetSessionFn != nil {
		return s.GetSessionFn(ctx, sessionID)
	}

	return Session{}, nil
}

func (s MockService) DeleteSession(ctx context.Context, sessionID []byte) error {
	if s.DeleteSessionFn != nil {
		return s.DeleteSessionFn(ctx, sessionID)
	}

	return nil
}

func (s MockService) UpdateLastSeen(ctx context.Context, curSession Session) error {
	if s.UpdateLastSeenFn != nil {
		return s.UpdateLastSeenFn(ctx, curSession)
	}

	return nil
}

func (s MockService) RotateSession(ctx context.Context, sessionID []byte) (Session, error) {
	if s.RotateSessionFn != nil {
		return s.RotateSessionFn(ctx, sessionID)
	}

	return Session{}, nil
}

func (s MockService) DeleteAllSessionsForUser(ctx context.Context, userID int64) error {
	if s.DeleteAllSessionsForUserFn != nil {
		return s.DeleteAllSessionsForUserFn(ctx, userID)
	}

	return nil
}

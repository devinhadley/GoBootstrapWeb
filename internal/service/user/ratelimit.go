package user

import (
	"context"
	"fmt"
	"time"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5/pgtype"
)

const (
	rateLimitLoginDurationMinutes = 10
	rateLimitLoginAttemptsAllowed = 10

	passwordResetRateLimitShortWindowMinutes = 15
	passwordResetRateLimitLongWindowMinutes  = 120
	passwordResetRateLimitShortAllowed       = 2
	passwordResetRateLimitLongAllowed        = 3

	emailResetRateLimitShortWindowMinutes = 15
	emailResetRateLimitLongWindowMinutes  = 120
	emailResetRateLimitShortAllowed       = 2
	emailResetRateLimitLongAllowed        = 3
)

// TieredAttemptCounts holds attempt counts over two overlapping windows.
type TieredAttemptCounts struct {
	RecentCount int64
	OldCount    int64
}

// AuthAttemptStore records and counts authentication attempts.
// Implementations may be backed by Postgres, Redis, or memory.
type AuthAttemptStore interface {
	CountFailedAttemptsSince(ctx context.Context, action db.AuthAction, email string, since time.Time) (int64, error)
	CountTieredAttempts(ctx context.Context, action db.AuthAction, email string, recentSince, oldSince time.Time) (TieredAttemptCounts, error)
	RecordAttempt(ctx context.Context, action db.AuthAction, email string, outcome db.AuthOutcome) error
}

type authAttemptQueries interface {
	CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CountTieredAuthAttempts(ctx context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error)
	CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
}

type postgresAuthAttemptStore struct {
	q authAttemptQueries
}

func NewPostgresAuthAttemptStore(q authAttemptQueries) AuthAttemptStore {
	return &postgresAuthAttemptStore{q: q}
}

func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func (s *postgresAuthAttemptStore) CountFailedAttemptsSince(ctx context.Context, action db.AuthAction, email string, since time.Time) (int64, error) {
	return s.q.CountFailedAuthAttemptsSince(ctx, db.CountFailedAuthAttemptsSinceParams{
		Action:    action,
		Email:     email,
		CreatedAt: ts(since),
	})
}

func (s *postgresAuthAttemptStore) CountTieredAttempts(ctx context.Context, action db.AuthAction, email string, recentSince, oldSince time.Time) (TieredAttemptCounts, error) {
	row, err := s.q.CountTieredAuthAttempts(ctx, db.CountTieredAuthAttemptsParams{
		Action:     action,
		Email:      email,
		RecentDate: ts(recentSince),
		OldDate:    ts(oldSince),
	})
	if err != nil {
		return TieredAttemptCounts{}, err
	}

	return TieredAttemptCounts{RecentCount: row.RecentCount, OldCount: row.OldCount}, nil
}

func (s *postgresAuthAttemptStore) RecordAttempt(ctx context.Context, action db.AuthAction, email string, outcome db.AuthOutcome) error {
	return s.q.CreateLoginAuthAttempt(ctx, db.CreateLoginAuthAttemptParams{
		Action:  action,
		Email:   email,
		Outcome: outcome,
	})
}

func (s *Service) isFailedAttemptRateLimited(ctx context.Context, action db.AuthAction, email string, window time.Duration, allowed int64) (bool, error) {
	timeBefore := time.Now().Add(-window)

	attemptsForEmail, err := s.authAttempts.CountFailedAttemptsSince(ctx, action, email, timeBefore)
	if err != nil {
		return false, err
	}

	return attemptsForEmail >= allowed, nil
}

func (s *Service) isCreatePasswordResetRateLimited(ctx context.Context, email string) (bool, error) {
	return s.isTieredRateLimited(
		ctx,
		db.AuthActionPasswordReset,
		email,
		passwordResetRateLimitShortWindowMinutes*time.Minute,
		passwordResetRateLimitLongWindowMinutes*time.Minute,
		passwordResetRateLimitShortAllowed,
		passwordResetRateLimitLongAllowed,
	)
}

func (s *Service) isCreateEmailResetRateLimited(ctx context.Context, email string) (bool, error) {
	return s.isTieredRateLimited(
		ctx,
		db.AuthActionEmailReset,
		email,
		emailResetRateLimitShortWindowMinutes*time.Minute,
		emailResetRateLimitLongWindowMinutes*time.Minute,
		emailResetRateLimitShortAllowed,
		emailResetRateLimitLongAllowed,
	)
}

func (s *Service) isTieredRateLimited(
	ctx context.Context,
	action db.AuthAction,
	email string,
	shortWindow time.Duration,
	longWindow time.Duration,
	shortAllowed,
	longAllowed int64,
) (bool, error) {
	now := time.Now()

	count, err := s.authAttempts.CountTieredAttempts(ctx, action, email, now.Add(-shortWindow), now.Add(-longWindow))
	if err != nil {
		return false, err
	}

	return count.RecentCount >= shortAllowed || count.OldCount >= longAllowed, nil
}

func (s *Service) createAuthAttempt(ctx context.Context, action db.AuthAction, email string, outcome db.AuthOutcome) error {
	err := s.authAttempts.RecordAttempt(ctx, action, email, outcome)
	if err != nil {
		return fmt.Errorf("creating login auth attempt: %w", err)
	}

	return nil
}

func (s *Service) failLoginAttempt(ctx context.Context, email string) (User, error) {
	if err := s.createAuthAttempt(ctx, db.AuthActionLogin, email, db.AuthOutcomeFailed); err != nil {
		return User{}, err
	}
	return User{}, ErrInvalidCredentials
}

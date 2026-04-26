package session

import (
	"time"

	"devinhadley/gobootstrapweb/internal/db"
)

type Session struct {
	raw db.Session
}

func SessionFromDB(session db.Session) Session {
	return Session{raw: session}
}

func (s Session) GetAbsoluteExpiration() time.Time {
	return s.raw.CreatedAt.Time.AddDate(0, 0, SessionAbsoluteExpirationDays)
}

func (s Session) DBSession() db.Session {
	return s.raw
}

func (s Session) ShouldRotate() bool {
	rotationRequiredDate := s.raw.LastRefreshedAt.Time.AddDate(0, 0, sessionRotationDays)
	return rotationRequiredDate.Before(time.Now())
}

func (s Session) IsExpired() bool {
	now := time.Now()
	absoluteExpirationDate := s.GetAbsoluteExpiration()
	if absoluteExpirationDate.Before(now) {
		return true
	}

	idleExpirationDate := s.raw.LastSeenAt.Time.AddDate(0, 0, sessionIdleExpirationDays)
	return idleExpirationDate.Before(now)
}

func (s Session) ShouldUpdateLastSeen() bool {
	return time.Since(s.raw.LastSeenAt.Time).Minutes() > updateLastSeenAfterDurationMinutes
}

const (
	SessionAbsoluteExpirationDays      = 90
	sessionIdleExpirationDays          = 14
	sessionRotationDays                = 7
	updateLastSeenAfterDurationMinutes = 20
)

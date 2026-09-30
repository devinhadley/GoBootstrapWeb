package middleware // Middleware runs on every request, before the handler that fulfills the request.

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/web"
)

type contextKey struct {
	name string
}

var userContextKey = &contextKey{"user"}

// getUserFunc fetches the session's user on demand, using the caller's context.
// Only requests that actually resolve a user (via WithUser) query for it.
type getUserFunc func(ctx context.Context) (user.User, error)

// sessionAndUser is what CreateSessionMiddleware stores in context: the current
// session, resolved eagerly, and a way to fetch the user, resolved on demand.
type sessionAndUser struct {
	session session.Session
	getUser getUserFunc
}

type sessionMiddlewareService interface {
	GetSession(ctx context.Context, sessionID []byte) (session.Session, error)
	DeleteSession(ctx context.Context, sessionID []byte) error
	UpdateLastSeen(ctx context.Context, session session.Session) error
}

type userGetter interface {
	GetUserByID(ctx context.Context, id int64) (user.User, error)
}

type AuthenticatedHandlerFunc func(w http.ResponseWriter, r *http.Request, usr user.User, sess session.Session)

func WithUser(next AuthenticatedHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		su, ok := r.Context().Value(userContextKey).(sessionAndUser)
		if !ok {
			web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{})
			return
		}

		usr, err := su.getUser(r.Context())
		if err != nil {
			web.WriteAndReportInternalError(w, fmt.Errorf("resolving user: %w", err))
			return
		}

		next(w, r, usr, su.session)
	})
}

// CreateSessionMiddleware creates an http handler which uses the id (session id) cookie to expire sessions and authenticate the user.
func CreateSessionMiddleware(userService userGetter, sessionService sessionMiddlewareService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie("id")
		if err != nil {
			if err == http.ErrNoCookie {
				next.ServeHTTP(w, r)
				return
			}
			slog.Error("reading session cookie", "err", err)
			next.ServeHTTP(w, r)
			return
		}

		sessionID, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
		if err != nil {
			slog.Warn("failed to base64 decode session id")
			web.ClearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		curSession, err := sessionService.GetSession(r.Context(), sessionID)
		if err != nil {
			if err == session.ErrSessionNotFound {
				web.ClearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			slog.Error("fetching session", "err", err)
			next.ServeHTTP(w, r)
			return
		}

		if curSession.IsExpired() {
			err = sessionService.DeleteSession(r.Context(), curSession.DBSession().ID)
			if err != nil {
				slog.Error("deleting expired session", "err", err, "user_id", curSession.DBSession().UserID)
			}
			web.ClearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		err = sessionService.UpdateLastSeen(r.Context(), curSession)
		if err != nil {
			slog.Error("updating session last seen", "err", err, "user_id", curSession.DBSession().UserID)
		}

		// Note that get session only includes sessions for a user that is active.
		// That is, an inactive user will never be added to context.
		userID := curSession.DBSession().UserID
		AddLogAttrs(r.Context(), slog.Int64("user_id", userID))
		var getUser getUserFunc = func(ctx context.Context) (user.User, error) {
			return userService.GetUserByID(ctx, userID)
		}

		r = r.WithContext(context.WithValue(r.Context(), userContextKey, sessionAndUser{
			session: curSession,
			getUser: getUser,
		}))

		next.ServeHTTP(w, r)
	})
}

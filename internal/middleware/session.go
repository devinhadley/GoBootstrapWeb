package middleware // Middlware runs on every request, before the handler that fufills the request.

import (
	"context"
	"encoding/base64"
	"log"
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
	ExpireSession(ctx context.Context, sessionID []byte) error
	RotateSession(ctx context.Context, sessionID []byte) (session.Session, error)
	UpdateLastSeen(ctx context.Context, session session.Session) error
}

type userGetter interface {
	GetUserByID(ctx context.Context, id int64) (user.User, error)
}

// AuthenticatedHandlerFunc is an http handler which additionally receives the requesting
// user and their current session. Use WithUser to adapt one into an http.Handler.
type AuthenticatedHandlerFunc func(w http.ResponseWriter, r *http.Request, usr user.User, sess session.Session)

// WithUser requires an authenticated session and resolves the current user, passing both
// directly to next. Views using it don't need to resolve either or handle errors
// themselves: no session yields a 401, a user resolution failure a 500.
func WithUser(next AuthenticatedHandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		su, ok := r.Context().Value(userContextKey).(sessionAndUser)
		if !ok {
			web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{})
			return
		}

		usr, err := su.getUser(r.Context())
		if err != nil {
			log.Printf("resolving user: %v", err)
			web.WriteAndReportInternalError(w)
			return
		}

		next(w, r, usr, su.session)
	})
}

// CreateSessionMiddleware creates an http handler which uses the id (session id) cookie to expire sessions, rotate sessions, and authenticate the user.
func CreateSessionMiddleware(userService userGetter, sessionService sessionMiddlewareService, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie("id")
		if err != nil {
			if err == http.ErrNoCookie {
				next.ServeHTTP(w, r)
				return
			}
			log.Printf("Error when reading session cookie: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		sessionID, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
		if err != nil {
			log.Print("Failed to base64 decode a session id.")
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

			log.Printf("Error when fetching session: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		if curSession.IsExpired() {
			err = sessionService.ExpireSession(r.Context(), curSession.DBSession().ID)
			if err != nil {
				log.Printf("Error when expiring session: %v", err)
			}
			web.ClearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		if curSession.ShouldRotate() {
			rotatedSession, err := sessionService.RotateSession(r.Context(), curSession.DBSession().ID)
			if err != nil {
				log.Printf("Error when rotating session: %v", err)
			} else {
				curSession = rotatedSession
				web.AddSessionToCookie(w, curSession.DBSession().ID, curSession.GetAbsoluteExpiration())
			}
		}

		err = sessionService.UpdateLastSeen(r.Context(), curSession)
		if err != nil {
			log.Printf("Error when updating last seen for session: %v", err)
		}

		// Note that get session only includes sessions for a user that is active.
		// That is, an inactive user will never be added to context.
		userID := curSession.DBSession().UserID
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

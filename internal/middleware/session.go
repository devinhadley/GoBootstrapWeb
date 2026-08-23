package middleware // Middlware runs on every request, before the handler that fufills the request.

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/web"
)

type contextKey struct {
	name string
}

var (
	getUserContextKey   = &contextKey{"get-user"}
	ErrUserNotInContext = errors.New("user not found in request context")
)

type GetUserFunc func() (user.User, error)

type sessionMiddlewareService interface {
	GetSession(ctx context.Context, sessionID []byte) (session.Session, error)
	ExpireSession(ctx context.Context, sessionID []byte) error
	RotateSession(ctx context.Context, sessionID []byte) (session.Session, error)
	UpdateLastSeen(ctx context.Context, session session.Session) error
}

type userGetter interface {
	GetUserByID(ctx context.Context, id int64) (user.User, error)
}

func withGetUser(ctx context.Context, getUser GetUserFunc) context.Context {
	return context.WithValue(ctx, getUserContextKey, getUser)
}

func UserFromRequest(r *http.Request) (user.User, error) {
	getUser, ok := r.Context().Value(getUserContextKey).(GetUserFunc)
	if !ok {
		return user.User{}, ErrUserNotInContext
	}

	return getUser()
}

func isUserInRequest(r *http.Request) bool {
	_, ok := r.Context().Value(getUserContextKey).(GetUserFunc)
	return ok
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

		// Add a closure to the context which allows lazy fetch of the current user.
		// Note that get session only includes sessions for a user that is active.
		// That is, an in active user will never be added to context.
		requestCtx := r.Context()
		ctx := withGetUser(requestCtx, createGetUserFunc(curSession.DBSession().UserID, userService, requestCtx))
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func createGetUserFunc(userID int64, userService userGetter, ctx context.Context) func() (user.User, error) {
	var currentUser *user.User
	var fetchCurrentUserError error

	return func() (user.User, error) {
		if currentUser != nil {
			return *currentUser, nil
		}

		if fetchCurrentUserError != nil {
			return user.User{}, fetchCurrentUserError
		}

		usr, err := userService.GetUserByID(ctx, userID)
		if err != nil {
			fetchCurrentUserError = err
			return user.User{}, err
		}

		currentUser = &usr

		return usr, nil
	}
}

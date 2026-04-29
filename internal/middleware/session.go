package middleware // Middlware runs on every request, before the handler that fufills the request.

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"

	"github.com/jackc/pgx/v5"
)

type contextKey struct {
	name string
}

var (
	getUserContextKey   = &contextKey{"get-user"}
	ErrUserNotInContext = errors.New("user not found in request context")
)

type GetUserFunc func() (db.User, error)

func withGetUser(ctx context.Context, getUser GetUserFunc) context.Context {
	return context.WithValue(ctx, getUserContextKey, getUser)
}

func UserFromContext(ctx context.Context) (db.User, error) {
	getUser, ok := ctx.Value(getUserContextKey).(GetUserFunc)
	if !ok {
		return db.User{}, ErrUserNotInContext
	}

	return getUser()
}

// TODO: Add context to errors!
// I.e. retrieve session cookie: %v

// CreateSessionMiddleware creates an http handler which uses the id (session id) cookie to expire sessions, rotate sessions, and authenticate the user.
func CreateSessionMiddleware(userService *user.Service, sessionService *session.Service, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			utils.ClearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		session, err := sessionService.GetSession(r.Context(), sessionID)
		if err != nil {
			if err == pgx.ErrNoRows {
				utils.ClearSessionCookie(w)
				next.ServeHTTP(w, r)
				return
			}

			log.Printf("Error when fetching session: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		if session.IsExpired() {
			err = sessionService.ExpireSession(r.Context(), session.DBSession().ID)
			if err != nil {
				log.Printf("Error when expiring session: %v", err)
			}
			utils.ClearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		if session.ShouldRotate() {
			session, err = sessionService.RotateSession(r.Context(), session.DBSession().ID)
			if err != nil {
				log.Printf("Error when rotating session: %v", err)
				next.ServeHTTP(w, r)
				return
			}
			utils.AddSessionToCookie(w, session.DBSession().ID, session.GetAbsoluteExpiration())
		}

		err = sessionService.UpdateLastSeen(r.Context(), session)
		if err != nil {
			log.Printf("Error when updating last seen for session: %v", err)
		}

		// Add a closure to the context which allows lazy fetch of the current user.
		requestCtx := r.Context()
		ctx := withGetUser(requestCtx, createGetUserFunc(session.DBSession().UserID, userService, requestCtx))
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

func createGetUserFunc(userID int64, userService *user.Service, ctx context.Context) func() (db.User, error) {
	var currentUser *db.User
	var fetchCurrentUserError error

	return func() (db.User, error) {
		if currentUser != nil {
			return *currentUser, nil
		}

		if fetchCurrentUserError != nil {
			return db.User{}, fetchCurrentUserError
		}

		user, err := userService.GetUserByID(ctx, userID)
		if err != nil {
			fetchCurrentUserError = err
			return db.User{}, err
		}

		currentUser = &user

		return user, nil
	}
}

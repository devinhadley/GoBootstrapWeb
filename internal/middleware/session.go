package middleware // Middlware runs on every request, before the handler that fufills the request.

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service"
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

// TODO: Test me!

// CreateSessionMiddleware creates an http handler which uses the id (session id) cookie to expire sessions, rotate sessions, and authenticate the user.
func CreateSessionMiddleware(userService service.UserService, sessionService service.SessionService, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionCookie, err := r.Cookie("id")
		if err != nil {
			if err == http.ErrNoCookie {
				return
			}

			w.WriteHeader(http.StatusBadRequest)
			return
		}

		sessionID, err := base64.StdEncoding.DecodeString(sessionCookie.Value)
		if err != nil {
			log.Print("Failed to base64 decode a session id.")
			next.ServeHTTP(w, r)
			return
		}

		session, err := sessionService.GetSession(r.Context(), sessionID)
		if err != nil {
			if err == pgx.ErrNoRows {
				next.ServeHTTP(w, r)
				return
			}

			log.Printf("Error when fetching session: %v", err)
			next.ServeHTTP(w, r)
			return
		}

		if sessionService.IsSessionExpired(session) {
			err = sessionService.ExpireSession(r.Context(), session.ID)
			if err != nil {
				log.Printf("Error when expiring session: %v", err)
			}
			utils.ClearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		if sessionService.ShouldRotateSession(session) {
			session, err = sessionService.RotateSession(r.Context(), session.ID)
			if err != nil {
				log.Printf("Error when rotating session: %v", err)
				next.ServeHTTP(w, r)
			}
			utils.AddSessionToCookie(w, &session)
		}

		// Add a closure to the context which fetches, caches, and returns the current user.
		requestCtx := r.Context()
		userID := session.UserID

		var (
			currentUser           *db.User
			fetchCurrentUserError error
		)

		ctx := withGetUser(requestCtx, func() (db.User, error) {
			if currentUser != nil {
				return *currentUser, nil
			}

			if fetchCurrentUserError != nil {
				return db.User{}, fetchCurrentUserError
			}

			user, err := userService.GetUserByID(requestCtx, userID)
			if err != nil {
				fetchCurrentUserError = err
				return db.User{}, err
			}

			currentUser = &user

			return user, nil
		})
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

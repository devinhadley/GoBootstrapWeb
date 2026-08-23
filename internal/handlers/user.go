package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"context"
	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/web"
	"errors"
	"log"
	"net/http"
)

type sessionCreator interface {
	CreateSession(ctx context.Context, userID int64) (session.CreateSessionResult, error)
}

type sessionDeactivator interface {
	DeactivateAllSessionsForUser(ctx context.Context, userID int64) error
}

type signUpper interface {
	SignUp(ctx context.Context, input user.AuthenticateBody) (user.User, error)
}

type logInner interface {
	LogIn(ctx context.Context, input user.AuthenticateBody) (user.User, error)
}

type authenticatedPasswordResetter interface {
	ResetPasswordForAuthenticatedUser(ctx context.Context, usr user.User, input user.AuthenticatedPasswordResetBody) error
}

type passwordResetRequester interface {
	CreatePasswordResetRequest(ctx context.Context, reqBody user.CreatePasswordResetRequestBody) error
}

type tokenPasswordResetter interface {
	ResetPasswordFromResetRequest(ctx context.Context, token string, input user.ResetPasswordFromResetRequestBody) (int64, error)
}

type emailResetRequester interface {
	CreateEmailResetRequest(ctx context.Context, usr user.User, input user.CreateEmailResetRequestBody) error
}

type tokenEmailResetter interface {
	ResetEmailFromResetRequest(ctx context.Context, token string) (int64, error)
}

func CreateSignUpHandler(userService signUpper, sessionService sessionCreator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, ok := web.DecodeJSONBodyOrWriteError[user.AuthenticateBody](w, r)
		if !ok {
			return
		}

		usr, err := userService.SignUp(r.Context(), user.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if writeSignUpError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		newSession, err := sessionService.CreateSession(r.Context(), usr.DBUser().ID)
		if err != nil {
			web.WriteAndReportInternalError(w)
			return
		}
		web.AddSessionToCookie(w, newSession.RawID, newSession.Session.GetAbsoluteExpiration())

		w.WriteHeader(http.StatusNoContent)
	})
}

func CreateLoginHandler(userService logInner, sessionService sessionCreator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, ok := web.DecodeJSONBodyOrWriteError[user.AuthenticateBody](w, r)
		if !ok {
			return
		}

		usr, err := userService.LogIn(r.Context(), user.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if writeLogInError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		newSession, err := sessionService.CreateSession(r.Context(), usr.DBUser().ID)
		if err != nil {
			web.WriteAndReportInternalError(w)
			return
		}
		web.AddSessionToCookie(w, newSession.RawID, newSession.Session.GetAbsoluteExpiration())

		w.WriteHeader(http.StatusNoContent)
	})
}

func CreateGetUserHandler() http.Handler {
	return middleware.Requires(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		usr, err := middleware.UserFromRequest(r)
		if err != nil {
			log.Printf("when getting user from context for get user endpoint: %v", err)
			web.WriteAndReportInternalError(w)
			return
		}

		web.WriteJSONResponse(w, http.StatusOK, map[string]any{
			"id":    usr.DBUser().ID,
			"email": usr.DBUser().Email,
		})
	}), middleware.Authenticated)
}

func CreateAuthenticatedPasswordResetHandler(userService authenticatedPasswordResetter, sessionService sessionDeactivator) http.Handler {
	return middleware.Requires(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqBody, ok := web.DecodeJSONBodyOrWriteError[user.AuthenticatedPasswordResetBody](w, r)
			if !ok {
				return
			}

			usr, err := middleware.UserFromRequest(r)
			if err != nil {
				log.Printf("when getting user for authenticated password reset: %v", err)
				web.WriteAndReportInternalError(w)
				return
			}

			err = userService.ResetPasswordForAuthenticatedUser(r.Context(), usr, reqBody)
			if err != nil {
				if writeAuthenticatedPasswordResetError(w, err) {
					return
				}
				web.WriteAndReportInternalError(w)
				return
			}

			if err := sessionService.DeactivateAllSessionsForUser(r.Context(), usr.DBUser().ID); err != nil {
				log.Printf("deactivating all sessions during authenticated password reset: %v", err)
			}

			web.ClearSessionCookie(w)
			w.WriteHeader(http.StatusNoContent)
		}), middleware.Authenticated)
}

func CreatePasswordResetRequestHandler(userService passwordResetRequester) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, ok := web.DecodeJSONBodyOrWriteError[user.CreatePasswordResetRequestBody](w, r)
		if !ok {
			return
		}

		err := userService.CreatePasswordResetRequest(r.Context(), reqBody)
		if err != nil {
			if writeCreatePasswordResetRequestError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func CreateTokenPasswordResetHandler(userService tokenPasswordResetter, sessionService sessionDeactivator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		reqBody, ok := web.DecodeJSONBodyOrWriteError[user.ResetPasswordFromResetRequestBody](w, r)
		if !ok {
			return
		}

		userID, err := userService.ResetPasswordFromResetRequest(r.Context(), token, reqBody)
		if err != nil {
			if writeTokenPasswordResetError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		if err := sessionService.DeactivateAllSessionsForUser(r.Context(), userID); err != nil {
			log.Printf("deactivating all sessions during reset from token: %v", err)
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func CreateEmailResetRequestHandler(userService emailResetRequester) http.Handler {
	return middleware.Requires(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqBody, ok := web.DecodeJSONBodyOrWriteError[user.CreateEmailResetRequestBody](w, r)
			if !ok {
				return
			}

			usr, err := middleware.UserFromRequest(r)
			if err != nil {
				log.Printf("when getting user for email reset request: %v", err)
				web.WriteAndReportInternalError(w)
				return
			}

			err = userService.CreateEmailResetRequest(r.Context(), usr, reqBody)
			if err != nil {
				if writeCreateEmailResetRequestError(w, err) {
					return
				}

				web.WriteAndReportInternalError(w)
				return
			}

			w.WriteHeader(http.StatusNoContent)
		}), middleware.Authenticated)
}

func CreateTokenEmailResetHandler(userService tokenEmailResetter, sessionService sessionDeactivator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")

		userID, err := userService.ResetEmailFromResetRequest(r.Context(), token)
		if err != nil {
			if writeTokenEmailResetError(w, err) {
				return
			}

			web.WriteAndReportInternalError(w)
			return
		}

		if err := sessionService.DeactivateAllSessionsForUser(r.Context(), userID); err != nil {
			log.Printf("deactivating all sessions during email reset from token: %v", err)
		}

		w.WriteHeader(http.StatusNoContent)
	})
}

func writeSignUpError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrEmailBlank) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email may not be blank"})
		return true
	}

	if errors.Is(err, user.ErrEmailTaken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
		return true
	}

	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeLogInError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidCredentials) {
		web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication failed"})
		return true
	}

	if errors.Is(err, user.ErrInvalidLogInInput) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
		return true
	}

	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if errors.Is(err, user.ErrRateLimit) {
		web.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]any{"error": "try again later"})
		return true
	}

	return false
}

func writeAuthenticatedPasswordResetError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidCredentials) {
		web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication failed"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeCreatePasswordResetRequestError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if errors.Is(err, user.ErrRateLimit) {
		web.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]any{"error": "try again later"})
		return true
	}

	if errors.Is(err, user.ErrUserNotFound) {
		w.WriteHeader(http.StatusNoContent)
		return true
	}

	return false
}

func writeTokenPasswordResetError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidResetToken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid or expired reset token"})
		return true
	}

	if writeWeakPasswordError(w, err) {
		return true
	}

	return false
}

func writeCreateEmailResetRequestError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidEmail) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
		return true
	}

	if errors.Is(err, user.ErrEmailTaken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
		return true
	}

	if errors.Is(err, user.ErrInvalidCredentials) {
		web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{"error": "authentication failed"})
		return true
	}

	if errors.Is(err, user.ErrRateLimit) {
		web.WriteJSONResponse(w, http.StatusTooManyRequests, map[string]any{"error": "try again later"})
		return true
	}

	return false
}

func writeTokenEmailResetError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrInvalidResetToken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid or expired reset token"})
		return true
	}

	if errors.Is(err, user.ErrEmailTaken) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
		return true
	}

	return false
}

func writeWeakPasswordError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, user.ErrPasswordEmpty) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password can't be empty"})
		return true
	}

	if errors.Is(err, user.ErrPasswordShort) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 13 or more characters"})
		return true
	}

	if errors.Is(err, user.ErrPasswordLong) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 256 charactrs or less"})
		return true
	}

	if errors.Is(err, user.ErrPasswordCommon) {
		web.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password too common"})
		return true
	}

	return false
}

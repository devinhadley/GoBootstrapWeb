package server

import (
	"net/http"

	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/middleware"
	"devinhadley/gobootstrapweb/internal/service/ratelimit"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
)

func NewMux(userService *user.Service, sessionService *session.Service, limiter *ratelimit.InMemoryLimiter) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("GET /user", handlers.CreateGetUserHandler())
	mux.Handle("POST /user/signup", handlers.CreateSignUpHandler(userService, sessionService))
	mux.Handle("POST /user/login", handlers.CreateLoginHandler(userService, sessionService, limiter))
	mux.Handle("POST /user/logout", handlers.CreateLogoutHandler(sessionService))
	mux.Handle("PUT /user/password", handlers.CreateAuthenticatedPasswordResetHandler(userService, limiter))
	mux.Handle("POST /password-reset", handlers.CreatePasswordResetRequestHandler(userService, limiter))
	mux.Handle("PUT /password-reset", handlers.CreateTokenPasswordResetHandler(userService))
	mux.Handle("POST /email-reset", handlers.CreateEmailResetRequestHandler(userService, limiter))
	mux.Handle("PUT /email-reset", handlers.CreateTokenEmailResetHandler(userService))

	crossOriginProtection := http.NewCrossOriginProtection()

	return middleware.CreateRequestLoggingMiddleware(
		crossOriginProtection.Handler(
			middleware.CreateSessionMiddleware(userService, sessionService, mux),
		),
	)
}

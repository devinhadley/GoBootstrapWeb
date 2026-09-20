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
	mux.Handle("PUT /user/password", handlers.CreateAuthenticatedPasswordResetHandler(userService, sessionService, limiter))
	mux.Handle("POST /password-reset", handlers.CreatePasswordResetRequestHandler(userService, limiter))
	mux.Handle("PUT /password-reset", handlers.CreateTokenPasswordResetHandler(userService, sessionService))
	mux.Handle("POST /email-reset", handlers.CreateEmailResetRequestHandler(userService, limiter))
	mux.Handle("PUT /email-reset", handlers.CreateTokenEmailResetHandler(userService, sessionService))

	// Throwaway local UI for manually exercising the auth flows. See temp_ui/README.md.
	mux.Handle("GET /temp_ui/", http.StripPrefix("/temp_ui/", http.FileServer(http.Dir("temp_ui"))))

	return middleware.CreateSessionMiddleware(userService, sessionService, mux)
}

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/server"
	"devinhadley/gobootstrapweb/internal/service/email"
	"devinhadley/gobootstrapweb/internal/service/ratelimit"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"

	"github.com/jackc/pgx/v5/pgxpool"
)

func getEnvOrPanic(name string) string {
	value := os.Getenv(name)

	if value == "" {
		msg := fmt.Sprintf("missing required env var: %v", name)
		panic(msg)
	}

	return value
}

func main() {
	isProd := strings.ToLower(getEnvOrPanic("IS_PROD")) != "false"
	if isProd {
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	}

	// Init connection to DB.
	dsn := getEnvOrPanic("DB_DSN")
	dbConPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		slog.Error("failed to init database connection pool", "err", err)
		os.Exit(1)
	}
	defer dbConPool.Close()

	queries := db.New(dbConPool)

	var mailService email.Service
	if isProd {
		slog.Error("no production email service configured")
		os.Exit(1)
	} else {
		mailService = email.MailHogService{}
	}

	passwordResetURL := getEnvOrPanic("PASSWORD_RESET_URL")
	emailResetURL := getEnvOrPanic("EMAIL_RESET_URL")
	txnGenerator := user.CreateUserServiceTxnGenerator(dbConPool, queries)

	sessionService := session.NewService(queries)
	userService := user.NewService(queries, txnGenerator, mailService, user.Config{
		PasswordResetURL: passwordResetURL,
		EmailResetURL:    emailResetURL,
	})
	limiter := ratelimit.NewInMemoryLimiter(time.Now, 100_000)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           server.NewMux(userService, sessionService, limiter),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	err = srv.ListenAndServe()
	slog.Error("server stopped", "err", err)
	os.Exit(1)
}

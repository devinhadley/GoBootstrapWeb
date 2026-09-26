package main

import (
	"context"
	"fmt"
	"log"
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
	// Init connection to DB.
	dsn := getEnvOrPanic("DB_DSN")
	dbConPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to init database connecton pool %v", err)
	}
	defer dbConPool.Close()

	queries := db.New(dbConPool)

	isProd := strings.ToLower(getEnvOrPanic("IS_PROD")) != "false"
	var mailService email.Service
	if isProd {
		log.Fatalf("no production email service configured.")
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

	http.ListenAndServe(":8080", server.NewMux(userService, sessionService, limiter))
}

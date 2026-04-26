package main

import (
	"context"
	"log"
	"net/http"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/handlers"
	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	// Init connection to DB.
	dsn := utils.GetEnvOrExit("DB_DSN")
	dbConPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to init database connecton pool %v", err)
	}
	defer dbConPool.Close()

	queries := db.New(dbConPool)

	mux := http.NewServeMux()

	userService := user.NewService(queries)
	sessionService := session.NewService(queries)

	mux.Handle("POST /signup", handlers.CreateSignUpHandler(userService, sessionService))
	mux.Handle("POST /login", handlers.CreateSignUpHandler(userService, sessionService))

	http.ListenAndServe(":8080", mux)
}

package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5/pgxpool"
)

func getEnvOrExit(varName string) string {
	env := os.Getenv(varName)

	if env == "" {
		log.Fatalf("Missing required env var: %s", varName)
	}

	return env
}

func main() {
	// Init connection to DB.
	dsn := getEnvOrExit("DB_DSN")
	dbConPool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to init database connecton pool %v", err)
	}
	defer dbConPool.Close()

	queries := db.New(dbConPool)

	ctx := context.Background()

	_, err = queries.CreateUser(ctx, db.CreateUserParams{
		Username:     "Devin",
		Email:        "devinhadley4@gmail.com",
		PasswordHash: "a-poor-hash",
	})
	if err != nil {
		log.Fatalf("Failed to create user!")
	}

	mux := http.NewServeMux()
}

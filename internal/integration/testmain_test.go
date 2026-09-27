package integration

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, dsn, err := startIntegrationPostgres(ctx)
	if err != nil {
		slog.Error("failed to start postgres test container", "err", err)
		os.Exit(1)
	}

	defer func() {
		if terminateErr := container.Terminate(ctx); terminateErr != nil {
			slog.Error("failed to terminate postgres test container", "err", terminateErr)
		}
	}()

	integrationTestDSN = dsn

	if err := runGooseMigrations(ctx, dsn); err != nil {
		slog.Error("failed to run goose migrations", "err", err)
		os.Exit(1)
	}

	integrationTestPool, err = pgxpool.New(ctx, dsn)
	if err != nil {
		slog.Error("failed to create integration pgx pool", "err", err)
		os.Exit(1)
	}

	if err := integrationTestPool.Ping(ctx); err != nil {
		integrationTestPool.Close()
		slog.Error("failed to ping integration pgx pool", "err", err)
		os.Exit(1)
	}

	code := m.Run()

	integrationTestPool.Close()
	os.Exit(code)
}

func startIntegrationPostgres(ctx context.Context) (*postgres.PostgresContainer, string, error) {
	postgresContainer, err := postgres.Run(ctx, "postgres:17-alpine",
		postgres.WithDatabase("gobootstrapweb_test"),
		postgres.WithUsername("integration_user"),
		postgres.WithPassword("integration_password"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, "", err
	}

	dsn, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = postgresContainer.Terminate(ctx)
		return nil, "", err
	}

	return postgresContainer, dsn, nil
}

func runGooseMigrations(ctx context.Context, dsn string) error {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := waitForDB(ctx, db); err != nil {
		return err
	}

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	if err := goose.Up(db, "../../sqlc/migrations"); err != nil {
		return err
	}

	return nil
}

func waitForDB(ctx context.Context, db *sql.DB) error {
	var lastErr error

	for range 30 {
		lastErr = db.PingContext(ctx)
		if lastErr == nil {
			return nil
		}

		time.Sleep(200 * time.Millisecond)
	}

	return fmt.Errorf("final ping failed: %w", lastErr)
}

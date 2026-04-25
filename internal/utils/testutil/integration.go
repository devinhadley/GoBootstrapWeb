// Package testutil provides commonly used functions for integration testing.
package testutil

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

const IntegrationTestDSNEnvVar = "INTEGRATION_TEST_DB_DSN"

func GetIntegrationTestDSN(t testing.TB) string {
	t.Helper()

	dsn := os.Getenv(IntegrationTestDSNEnvVar)
	if dsn == "" {
		t.Skipf("%s is required for integration tests", IntegrationTestDSNEnvVar)
	}

	return dsn
}

// CleanupIntegrationTables truncates and resets the identity of all tables in the integration test db.
func CleanupIntegrationTables(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(context.Background(), "TRUNCATE TABLE sessions, users RESTART IDENTITY")
	if err != nil {
		t.Fatalf("failed to clean integration tables: %v", err)
	}
}

func PerformJSONRequest(handler http.Handler, method string, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		if cookie == nil {
			continue
		}

		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	return rec
}

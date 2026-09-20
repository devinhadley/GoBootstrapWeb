// Package testutil provides commonly used functions for integration testing.
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	integrationTestDSN  string
	integrationTestPool *pgxpool.Pool
)

func getIntegrationTestPool(t testing.TB) *pgxpool.Pool {
	t.Helper()

	if integrationTestPool != nil {
		return integrationTestPool
	}

	t.Fatalf("integration test pool is nil; expected TestMain to initialize shared pgx pool")
	return nil
}

// cleanupIntegrationTables truncates and resets the identity of all tables in the integration test db.
func cleanupIntegrationTables(t testing.TB, pool *pgxpool.Pool) {
	t.Helper()

	_, err := pool.Exec(context.Background(), "TRUNCATE TABLE sessions, users, password_reset_requests, email_reset_requests RESTART IDENTITY")
	if err != nil {
		t.Fatalf("failed to clean integration tables: %v", err)
	}
}

func performJsonRequest(handler http.Handler, method string, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
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

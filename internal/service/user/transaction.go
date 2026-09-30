package user

import (
	"context"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/session"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NOTE:
// Despite this not being a service level construct, it is a tightly coupled dependency
// that requires reuse across initialization in main & integration tests. To balance
// these requirements, despite not being service behavior, it is placed here.

// Creates a function which manages creating and tearing down a transaction given some function
// which performs work on DB with user queries.

type SessionDeleter interface {
	DeleteAllSessionsForUser(ctx context.Context, userID int64) error
}

type RunUserQueriesInTxFn func(ctx context.Context, fn func(q UserQueries, sessions SessionDeleter) error) error

func CreateUserServiceTxnGenerator(dbConPool *pgxpool.Pool, queries *db.Queries) RunUserQueriesInTxFn {
	return func(ctx context.Context, fn func(q UserQueries, sessions SessionDeleter) error) error {
		tx, err := dbConPool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)

		qtx := queries.WithTx(tx)

		err = fn(qtx, session.NewService(qtx))
		if err != nil {
			return err
		}

		return tx.Commit(ctx)
	}
}

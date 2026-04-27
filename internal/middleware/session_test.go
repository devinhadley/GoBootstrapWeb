package middleware

import (
	"context"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/user"
)

func TestCreateGetUserFuncCachesUser(t *testing.T) {
	const userID int64 = 42

	callCount := 0
	wantUser := db.User{ID: userID, Email: "test@example.com"}

	userService := user.NewService(&mockUserQueries{
		getUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			callCount++
			if id != userID {
				t.Fatalf("GetUserByID got id %v, want %v", id, userID)
			}

			return wantUser, nil
		},
	})

	getUser := createGetUserFunc(userID, userService, context.Background())

	gotUserOne, err := getUser()
	if err != nil {
		t.Fatalf("first getUser() returned error: %v", err)
	}

	gotUserTwo, err := getUser()
	if err != nil {
		t.Fatalf("second getUser() returned error: %v", err)
	}

	if gotUserOne.ID != wantUser.ID {
		t.Fatalf("first getUser() got id %v, want %v", gotUserOne.ID, wantUser.ID)
	}

	if gotUserTwo.ID != wantUser.ID {
		t.Fatalf("second getUser() got id %v, want %v", gotUserTwo.ID, wantUser.ID)
	}

	if callCount != 1 {
		t.Fatalf("GetUserByID called %v times, want 1", callCount)
	}
}

type mockUserQueries struct {
	getUserByIDFn func(ctx context.Context, id int64) (db.User, error)
}

func (q *mockUserQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	return db.User{}, nil
}

func (q *mockUserQueries) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	return db.User{}, nil
}

func (q *mockUserQueries) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	if q.getUserByIDFn != nil {
		return q.getUserByIDFn(ctx, id)
	}

	return db.User{}, nil
}

package service

import (
	"context"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/matthewhartstonge/argon2"
)

// Mocks...
type MockUserQueries struct {
	CreateUserFn     func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn func(ctx context.Context, email string) (db.User, error)
}

func (q *MockUserQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	return db.User{
		ID:           1,
		Email:        arg.Email,
		PasswordHash: arg.PasswordHash,
	}, nil
}

func (q *MockUserQueries) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	return db.User{
		ID:    1,
		Email: email,
	}, nil
}

// Handler tests are integrations tests...
func TestUserService(t *testing.T) {
	t.Run("user can sign up", testUserSignUp)
}

func testUserSignUp(t *testing.T) {
	userService := setupUserService(t)
	ctx := context.Background()

	input := SignUpInput{
		Email:    "test@example.com",
		Password: "example-password",
	}

	user, err := userService.SignUp(ctx, input)
	if err != nil {
		t.Fatalf("SignUp returned error: %v", err)
	}

	if user.Email != input.Email {
		t.Fatalf("got email %q, want %q", user.Email, input.Email)
	}

	ok, err := argon2.VerifyEncoded([]byte(input.Password), []byte(user.PasswordHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error: %v", err)
	}
	if !ok {
		t.Fatal("stored password hash does not match input password")
	}
}

func setupUserService(t *testing.T) *UserService {
	t.Helper()
	mockedQueries := MockUserQueries{}
	return NewUserService(&mockedQueries)
}

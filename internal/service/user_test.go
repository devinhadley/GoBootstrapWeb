package service

import (
	"context"
	"errors"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/matthewhartstonge/argon2"
)

func TestUserService(t *testing.T) {
	t.Run("user can sign up", testUserSignUp)
	t.Run("sign up rejects blank email or password", testUserSignUpRejectsBlankEmailOrPassword)
	t.Run("sign up rejects invalid email", testUserSignUpRejectsInvalidEmail)
}

func testUserSignUp(t *testing.T) {
	userService := setupUserService(t, MockUserQueries{})
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

func testUserSignUpRejectsBlankEmailOrPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, MockUserQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			t.Fatal("CreateUser should not be called for invalid sign-up input")
			return db.User{}, nil
		},
	})

	testCases := []struct {
		name     string
		email    string
		password string
	}{
		{name: "empty email", email: "", password: "example-password"},
		{name: "whitespace email", email: "   ", password: "example-password"},
		{name: "empty password", email: "test@example.com", password: ""},
		{name: "whitespace password", email: "test@example.com", password: "   "},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := userService.SignUp(ctx, SignUpInput{
				Email:    tc.email,
				Password: tc.password,
			})

			if !errors.Is(err, ErrInvalidSignUpInput) {
				t.Fatalf("got error %v, want %v", err, ErrInvalidSignUpInput)
			}
		})
	}
}

func testUserSignUpRejectsInvalidEmail(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, MockUserQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			t.Fatal("CreateUser should not be called for invalid email")
			return db.User{}, nil
		},
	})

	testCases := []string{
		"invalid",
		"test@localhost",
		"test@@example.com",
		"test@example",
	}

	for _, email := range testCases {
		t.Run(email, func(t *testing.T) {
			_, err := userService.SignUp(ctx, SignUpInput{
				Email:    email,
				Password: "example-password",
			})

			if !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("got error %v, want %v", err, ErrInvalidEmail)
			}
		})
	}
}

func setupUserService(t *testing.T, mockedQueries MockUserQueries) *UserService {
	t.Helper()
	return NewUserService(&mockedQueries)
}

// Mocks...
// Mocks...
type MockUserQueries struct {
	CreateUserFn     func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn func(ctx context.Context, email string) (db.User, error)
}

func (q *MockUserQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	if q.CreateUserFn != nil {
		return q.CreateUserFn(ctx, arg)
	}

	return db.User{
		ID:           1,
		Email:        arg.Email,
		PasswordHash: arg.PasswordHash,
	}, nil
}

func (q *MockUserQueries) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	if q.GetUserByEmailFn != nil {
		return q.GetUserByEmailFn(ctx, email)
	}

	return db.User{
		ID:    1,
		Email: email,
	}, nil
}

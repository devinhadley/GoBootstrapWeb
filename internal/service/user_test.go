package service

import (
	"context"
	"errors"
	"testing"

	"devinhadley/gobootstrapweb/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/matthewhartstonge/argon2"
)

func TestSignUp(t *testing.T) {
	t.Run("user can sign up", testUserSignUp)
	t.Run("sign up rejects blank email or password", testUserSignUpRejectsBlankEmailOrPassword)
	t.Run("sign up rejects invalid email", testUserSignUpRejectsInvalidEmail)
	t.Run("sign up normalizes and trims email", testUserSignUpNormalizesAndTrimsEmail)
	t.Run("sign up returns email taken when email already exists", testUserSignUpEmailTaken)
	t.Run("sign up propagates unexpected query error", testUserSignUpPropagatesUnexpectedError)
}

func TestLogIn(t *testing.T) {
	t.Run("user can log in", testUserLogIn)
	t.Run("log in rejects blank email or password", testUserLogInRejectsBlankEmailOrPassword)
	t.Run("log in rejects invalid email", testUserLogInRejectsInvalidEmail)
	t.Run("log in returns invalid credentials when user does not exist", testUserLogInUserNotFound)
	t.Run("log in returns invalid credentials for wrong password", testUserLogInWrongPassword)
	t.Run("log in propagates unexpected query error", testUserLogInPropagatesUnexpectedError)
}

func TestGetUserByID(t *testing.T) {
	t.Run("returns user by id", testGetUserByID)
	t.Run("propagates query error", testGetUserByIDPropagatesError)
}

func testUserSignUp(t *testing.T) {
	userService := setupUserService(t, MockUserQueries{})
	ctx := context.Background()

	input := AuthenticateBody{
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
			_, err := userService.SignUp(ctx, AuthenticateBody{
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
			_, err := userService.SignUp(ctx, AuthenticateBody{
				Email:    email,
				Password: "example-password",
			})

			if !errors.Is(err, ErrInvalidEmail) {
				t.Fatalf("got error %v, want %v", err, ErrInvalidEmail)
			}
		})
	}
}

func testUserSignUpNormalizesAndTrimsEmail(t *testing.T) {
	ctx := context.Background()
	inputEmail := "  User@Example.COM  "
	expectedEmail := "User@example.com"

	userService := setupUserService(t, MockUserQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			if arg.Email != expectedEmail {
				t.Fatalf("CreateUser got email %q, want %q", arg.Email, expectedEmail)
			}

			return db.User{
				ID:           1,
				Email:        arg.Email,
				PasswordHash: arg.PasswordHash,
			}, nil
		},
	})

	user, err := userService.SignUp(ctx, AuthenticateBody{
		Email:    inputEmail,
		Password: "example-password",
	})
	if err != nil {
		t.Fatalf("SignUp returned error: %v", err)
	}

	if user.Email != expectedEmail {
		t.Fatalf("got email %q, want %q", user.Email, expectedEmail)
	}
}

func testUserSignUpEmailTaken(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, MockUserQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			return db.User{}, &pgconn.PgError{
				Code:           "23505",
				ConstraintName: "users_email_key",
			}
		},
	})

	_, err := userService.SignUp(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})

	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("got error %v, want %v", err, ErrEmailTaken)
	}
}

func testUserSignUpPropagatesUnexpectedError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("database unavailable")

	userService := setupUserService(t, MockUserQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			return db.User{}, expectedErr
		},
	})

	_, err := userService.SignUp(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("got error %v, want %v", err, expectedErr)
	}
}

func testUserLogIn(t *testing.T) {
	ctx := context.Background()

	id := int64(1)
	email := "test@example.com"
	password := "password"

	argon := argon2.MemoryConstrainedDefaults()
	passwordHash, err := argon.HashEncoded([]byte(password))
	if err != nil {
		t.Fatalf("failed to hash initial password: %v", err)
	}

	userService := setupUserService(t, MockUserQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{ID: id, Email: email, PasswordHash: string(passwordHash)}, nil
		},
	})

	user, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("got error %v, expected nil", err)
	}

	if user.ID != id {
		t.Fatalf("got id %v, expected %v", user.ID, id)
	}

	if user.Email != email {
		t.Fatalf("got email %v, expected %v", user.Email, email)
	}

	if user.PasswordHash != string(passwordHash) {
		t.Fatalf("got password hash %v, expected %v", user.PasswordHash, passwordHash)
	}
}

func testUserLogInRejectsBlankEmailOrPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, MockUserQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for invalid log-in input")
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
			_, err := userService.LogIn(ctx, AuthenticateBody{
				Email:    tc.email,
				Password: tc.password,
			})

			if !errors.Is(err, ErrInvalidLogInInput) {
				t.Fatalf("got error %v, want %v", err, ErrInvalidLogInInput)
			}
		})
	}
}

func testUserLogInWrongPassword(t *testing.T) {
	ctx := context.Background()

	argon := argon2.MemoryConstrainedDefaults()
	passwordHash, err := argon.HashEncoded([]byte("correct-password"))
	if err != nil {
		t.Fatalf("failed to hash initial password: %v", err)
	}

	userService := setupUserService(t, MockUserQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{ID: 1, Email: email, PasswordHash: string(passwordHash)}, nil
		},
	})

	_, err = userService.LogIn(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "wrong-password",
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}
}

func testUserLogInRejectsInvalidEmail(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, MockUserQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for invalid email")
			return db.User{}, nil
		},
	})

	_, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    "invalid",
		Password: "example-password",
	})

	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidEmail)
	}
}

func testUserLogInUserNotFound(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, MockUserQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{}, pgx.ErrNoRows
		},
	})

	_, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}
}

func testUserLogInPropagatesUnexpectedError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("database unavailable")

	userService := setupUserService(t, MockUserQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{}, expectedErr
		},
	})

	_, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})

	if !errors.Is(err, expectedErr) {
		t.Fatalf("got error %v, want %v", err, expectedErr)
	}
}

func testGetUserByID(t *testing.T) {
	ctx := context.Background()
	wantID := int64(42)
	wantEmail := "test@example.com"

	userService := setupUserService(t, MockUserQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			if id != wantID {
				t.Fatalf("GetUserByID got id %v, want %v", id, wantID)
			}

			return db.User{ID: id, Email: wantEmail}, nil
		},
	})

	user, err := userService.GetUserByID(ctx, wantID)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}

	if user.ID != wantID {
		t.Fatalf("got id %v, want %v", user.ID, wantID)
	}

	if user.Email != wantEmail {
		t.Fatalf("got email %v, want %v", user.Email, wantEmail)
	}
}

func testGetUserByIDPropagatesError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("database unavailable")

	userService := setupUserService(t, MockUserQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			return db.User{}, wantErr
		},
	})

	_, err := userService.GetUserByID(ctx, 42)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func setupUserService(t *testing.T, mockedQueries MockUserQueries) *UserService {
	t.Helper()
	return NewUserService(&mockedQueries)
}

// Mocks...
type MockUserQueries struct {
	CreateUserFn     func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn func(ctx context.Context, email string) (db.User, error)
	GetUserByIDFn    func(ctx context.Context, id int64) (db.User, error)
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

func (q *MockUserQueries) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	if q.GetUserByIDFn != nil {
		return q.GetUserByIDFn(ctx, id)
	}

	return db.User{
		ID:    id,
		Email: "test@example.com",
	}, nil
}

package user

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
	"devinhadley/gobootstrapweb/internal/service/email"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matthewhartstonge/argon2"
)

func TestSignUp(t *testing.T) {
	t.Run("sign up propagates unexpected query error", testUserSignUpPropagatesUnexpectedError)
}

func TestLogIn(t *testing.T) {
	t.Run("log in rejects blank email or password", testUserLogInRejectsBlankEmailOrPassword)
	t.Run("log in propagates unexpected query error", testUserLogInPropagatesUnexpectedError)
	t.Run("logging in fails with inactive user", testLogInWhenUserInactive)
}

func TestGetUserByID(t *testing.T) {
	t.Run("propagates query error", testGetUserByIDPropagatesError)
}

func TestNormalizeAndValidateEmail(t *testing.T) {
	t.Run("accepts valid emails", testNormalizeAndValidateEmailValidInputs)
	t.Run("rejects invalid emails", testNormalizeAndValidateEmailInvalidInputs)
}

func TestPasswordReset(t *testing.T) {
	t.Run("cant create password reset with malformed email", testCantCreatePasswordResetWithMalformedEmail)
	t.Run("cant reset password with expired token", testCantResetPasswordWithExpiredToken)
}

func TestCreateEmailResetRequest(t *testing.T) {
	t.Run("email reset request fails with malformed new email", testCantRequestEmailResetWithMalformedNewEmail)
	t.Run("email reset request fails when new email matches current email", testCantRequestEmailResetWithSameEmail)
	t.Run("email reset request propagates unexpected error checking new email", testCreateEmailResetRequestPropagatesUnexpectedGetUserByEmailError)
}

func testUserSignUpPropagatesUnexpectedError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("database unavailable")

	userService := setupUserService(t, mockQueries{
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

func testUserLogInRejectsBlankEmailOrPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
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

func testUserLogInPropagatesUnexpectedError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("database unavailable")

	userService := setupUserService(t, mockQueries{
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

func testLogInWhenUserInactive(t *testing.T) {
	id := int64(1)
	password := "password"

	passwordHash := hashPassword(t, password)

	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{ID: id, Email: email, PasswordHash: passwordHash, IsActive: false}, nil
		},
	})

	usr, err := userService.LogIn(context.Background(), AuthenticateBody{
		Email:    "test@example.com",
		Password: password,
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wanted error %v but got %v", ErrInvalidCredentials, err)
	}

	if usr != (User{}) {
		t.Fatalf("wanted user %v but got %v", User{}, usr)
	}
}

func testGetUserByIDPropagatesError(t *testing.T) {
	ctx := context.Background()
	wantErr := errors.New("database unavailable")

	userService := setupUserService(t, mockQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			return db.User{}, wantErr
		},
	})

	_, err := userService.GetUserByID(ctx, 42)
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func testNormalizeAndValidateEmailValidInputs(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple address",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "trims surrounding whitespace",
			input:    "  user@example.com  ",
			expected: "user@example.com",
		},
		{
			name:     "normalizes uppercase domain",
			input:    "user@Example.COM",
			expected: "user@example.com",
		},
		{
			name:     "keeps local part casing",
			input:    "User.Name@Example.COM",
			expected: "User.Name@example.com",
		},
		{
			name:     "allows plus addressing",
			input:    "user+tag@example.com",
			expected: "user+tag@example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized, ok := normalizeAndValidateEmail(tc.input)
			if !ok {
				t.Fatalf("normalizeAndValidateEmail(%q) returned ok=false, want ok=true", tc.input)
			}

			if normalized != tc.expected {
				t.Fatalf("normalizeAndValidateEmail(%q) returned %q, want %q", tc.input, normalized, tc.expected)
			}
		})
	}
}

func testNormalizeAndValidateEmailInvalidInputs(t *testing.T) {
	testCases := []string{
		"",
		"   ",
		"null",
		"user",
		"user@localhost",
		"user@example",
		"user@.example.com",
		"user@example.com.",
		"user@@example.com",
		"user@",
		"@example.com",
		"User <user@example.com>",
		"user example.com",
		strings.Repeat("a", 255),
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			normalized, ok := normalizeAndValidateEmail(input)
			if ok {
				t.Fatalf("normalizeAndValidateEmail(%q) returned ok=true and %q, want ok=false", input, normalized)
			}

			if normalized != "" {
				t.Fatalf("normalizeAndValidateEmail(%q) returned %q, want empty string", input, normalized)
			}
		})
	}
}

func testCantCreatePasswordResetWithMalformedEmail(t *testing.T) {
	ctx := context.Background()

	userService := setupUserServiceWithEmail(t, mockQueries{
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for malformed email")
			return db.User{}, nil
		},
		CreatePasswordResetRequestFn: func(context.Context, db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
			t.Fatal("CreatePasswordResetRequest should not be called for malformed email")
			return db.PasswordResetRequest{}, nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for malformed email")
			return nil
		},
	}, "http://example.com/password-reset")

	err := userService.CreatePasswordResetRequest(ctx, CreatePasswordResetRequestBody{Email: "not-an-email"})
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidEmail)
	}
}

func testCantResetPasswordWithExpiredToken(t *testing.T) {
	ctx := context.Background()
	rawToken := []byte("token-expired-123")
	encodedToken := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)

	queried := false

	userService := setupUserService(t, mockQueries{
		ConsumePasswordResetRequestFn: func(_ context.Context, id []byte) (db.PasswordResetRequest, error) {
			if string(id) != string(tokenHash[:]) {
				t.Fatalf("ConsumePasswordResetRequest got id %v, want %v", id, tokenHash[:])
			}

			queried = true
			return db.PasswordResetRequest{
				ID:     tokenHash[:],
				UserID: 42,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Now().Add(-(passwordResetTokenDuration + time.Minute)),
					Valid: true,
				},
			}, nil
		},
		UpdatePasswordHashFn: func(context.Context, db.UpdatePasswordHashParams) error {
			t.Fatal("UpdatePasswordHash should not be called for expired token")
			return nil
		},
	})

	_, err := userService.ResetPasswordFromResetRequest(ctx, encodedToken, ResetPasswordFromResetRequestBody{
		NewPassword: "brand-new-password",
	})
	if !errors.Is(err, ErrInvalidResetToken) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidResetToken)
	}

	if !queried {
		t.Fatal("ConsumePasswordResetRequest was not called")
	}
}

func testCantRequestEmailResetWithMalformedNewEmail(t *testing.T) {
	ctx := context.Background()

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        "current@example.com",
		PasswordHash: hashPassword(t, "correct-current-password"),
	})

	userService := setupUserServiceWithEmail(t, mockQueries{
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for malformed new email")
			return db.User{}, nil
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called for malformed new email")
			return db.EmailResetRequest{}, nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for malformed new email")
			return nil
		},
	}, "")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: "correct-current-password",
		NewEmail: "not-an-email",
	})
	if !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidEmail)
	}
}

func testCantRequestEmailResetWithSameEmail(t *testing.T) {
	ctx := context.Background()
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, "correct-current-password"),
	})

	userService := setupUserServiceWithEmail(t, mockQueries{
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called when new email matches current email")
			return db.User{}, nil
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called when new email matches current email")
			return db.EmailResetRequest{}, nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called when new email matches current email")
			return nil
		},
	}, "")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: "correct-current-password",
		NewEmail: " " + currentEmail + " ",
	})
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("got error %v, want %v", err, ErrEmailTaken)
	}
}

func testCreateEmailResetRequestPropagatesUnexpectedGetUserByEmailError(t *testing.T) {
	ctx := context.Background()
	currentEmail := "current@example.com"
	newEmail := "new@example.com"
	wantErr := errors.New("database unavailable")

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, "correct-current-password"),
	})

	userService := setupUserServiceWithEmail(t, mockQueries{
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			return db.User{}, wantErr
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called when checking new email fails")
			return db.EmailResetRequest{}, nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called when checking new email fails")
			return nil
		},
	}, "")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: "correct-current-password",
		NewEmail: newEmail,
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("got error %v, want %v", err, wantErr)
	}
}

func hashPassword(t *testing.T, password string) string {
	t.Helper()
	argon := argon2.MemoryConstrainedDefaults()
	hash, err := argon.HashEncoded([]byte(password))
	if err != nil {
		t.Fatalf("HashEncoded returned error: %v", err)
	}
	return string(hash)
}

func setupUserService(t *testing.T, mockedQueries mockQueries) *Service {
	t.Helper()
	return setupUserServiceWithEmail(t, mockedQueries, email.MockEmailService{}, "")
}

func setupUserServiceWithEmail(t *testing.T, mockedQueries mockQueries, mockedEmailService email.MockEmailService, passwordResetURL string) *Service {
	t.Helper()
	runWithTx := func(ctx context.Context, fn func(q UserQueries) error) error {
		return fn(&mockedQueries)
	}
	return NewService(&mockedQueries, runWithTx, mockedEmailService, Config{PasswordResetURL: passwordResetURL})
}

func setupUserServiceWithEmailReset(t *testing.T, mockedQueries mockQueries, mockedEmailService email.MockEmailService, emailResetURL string) *Service {
	t.Helper()
	runWithTx := func(ctx context.Context, fn func(q UserQueries) error) error {
		return fn(&mockedQueries)
	}
	return NewService(&mockedQueries, runWithTx, mockedEmailService, Config{EmailResetURL: emailResetURL})
}

type mockQueries struct {
	CreateUserFn                  func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn              func(ctx context.Context, email string) (db.User, error)
	GetUserByIDFn                 func(ctx context.Context, id int64) (db.User, error)
	CreatePasswordResetRequestFn  func(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	ConsumePasswordResetRequestFn func(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	UpdatePasswordHashFn          func(ctx context.Context, arg db.UpdatePasswordHashParams) error
	CreateEmailResetRequestFn     func(ctx context.Context, arg db.CreateEmailResetRequestParams) (db.EmailResetRequest, error)
	ConsumeEmailResetRequestFn    func(ctx context.Context, id []byte) (db.EmailResetRequest, error)
	UpdateEmailFn                 func(ctx context.Context, arg db.UpdateEmailParams) error
}

func (q *mockQueries) CreateUser(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
	if q.CreateUserFn != nil {
		return q.CreateUserFn(ctx, arg)
	}

	return db.User{
		ID:           1,
		Email:        arg.Email,
		PasswordHash: arg.PasswordHash,
	}, nil
}

func (q *mockQueries) GetUserByEmail(ctx context.Context, email string) (db.User, error) {
	if q.GetUserByEmailFn != nil {
		return q.GetUserByEmailFn(ctx, email)
	}

	return db.User{
		ID:    1,
		Email: email,
	}, nil
}

func (q *mockQueries) GetUserByID(ctx context.Context, id int64) (db.User, error) {
	if q.GetUserByIDFn != nil {
		return q.GetUserByIDFn(ctx, id)
	}

	return db.User{
		ID:    id,
		Email: "test@example.com",
	}, nil
}

func (q *mockQueries) CreatePasswordResetRequest(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
	if q.CreatePasswordResetRequestFn != nil {
		return q.CreatePasswordResetRequestFn(ctx, arg)
	}

	return db.PasswordResetRequest{ID: arg.ID, UserID: arg.UserID}, nil
}

func (q *mockQueries) ConsumePasswordResetRequest(ctx context.Context, id []byte) (db.PasswordResetRequest, error) {
	if q.ConsumePasswordResetRequestFn != nil {
		return q.ConsumePasswordResetRequestFn(ctx, id)
	}

	return db.PasswordResetRequest{}, pgx.ErrNoRows
}

func (q *mockQueries) UpdatePasswordHash(ctx context.Context, arg db.UpdatePasswordHashParams) error {
	if q.UpdatePasswordHashFn != nil {
		return q.UpdatePasswordHashFn(ctx, arg)
	}

	return nil
}

func (q *mockQueries) CreateEmailResetRequest(ctx context.Context, arg db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
	if q.CreateEmailResetRequestFn != nil {
		return q.CreateEmailResetRequestFn(ctx, arg)
	}

	return db.EmailResetRequest{ID: arg.ID, UserID: arg.UserID, NewEmail: arg.NewEmail}, nil
}

func (q *mockQueries) ConsumeEmailResetRequest(ctx context.Context, id []byte) (db.EmailResetRequest, error) {
	if q.ConsumeEmailResetRequestFn != nil {
		return q.ConsumeEmailResetRequestFn(ctx, id)
	}

	return db.EmailResetRequest{}, pgx.ErrNoRows
}

func (q *mockQueries) UpdateEmail(ctx context.Context, arg db.UpdateEmailParams) error {
	if q.UpdateEmailFn != nil {
		return q.UpdateEmailFn(ctx, arg)
	}

	return nil
}

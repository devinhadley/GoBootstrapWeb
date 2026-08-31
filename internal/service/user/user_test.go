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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/matthewhartstonge/argon2"
)

func TestSignUp(t *testing.T) {
	t.Run("user can sign up", testUserSignUp)
	t.Run("sign up rejects blank email or password", testUserSignUpRejectsBlankEmailOrPassword)
	t.Run("sign up rejects short password", testUserSignUpRejectsShortPassword)
	t.Run("sign up rejects long password", testUserSignUpRejectsLongPassword)
	t.Run("sign up rejects common password", testUserSignUpRejectsCommonPassword)
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
	t.Run("log in is rate limited after 10 failed attempts within 10 minutes", testUserLogInRateLimited)
	t.Run("log in propagates unexpected query error", testUserLogInPropagatesUnexpectedError)
	t.Run("logging in fails with inactive user", testLogInWhenUserInactive)
}

func TestGetUserByID(t *testing.T) {
	t.Run("returns user by id", testGetUserByID)
	t.Run("propagates query error", testGetUserByIDPropagatesError)
}

func TestNormalizeAndValidateEmail(t *testing.T) {
	t.Run("accepts valid emails", testNormalizeAndValidateEmailValidInputs)
	t.Run("rejects invalid emails", testNormalizeAndValidateEmailInvalidInputs)
}

func TestPasswordReset(t *testing.T) {
	t.Run("can reset password when authenticated", testResetPasswordForAuthenticatedUser)
	t.Run("password reset fails with authenticated user if existing password incorrect", testResetPasswordForAuthenticatedUserWrongCurrentPassword)
	t.Run("authenticated password reset doesn't allow weak pass", testResetPasswordForAuthenticatedUserRejectsWeakPassword)
	t.Run("authenticated password reset is rate limited after repeated failed reauthentication", testResetPasswordForAuthenticatedUserReauthRateLimited)
	t.Run("authenticated password reset records a failed reauthentication attempt", testResetPasswordForAuthenticatedUserRecordsFailedReauthAttempt)
	t.Run("can request token password reset", testCanRequestPasswordReset)
	t.Run("cant create password reset with malformed email", testCantCreatePasswordResetWithMalformedEmail)
	t.Run("requesting token password reset response for unkown email", testRequestingTokenPasswordResetForUnknownEmail)
	t.Run("cant request more than 3 password resets for a particular email in 120 minutes", testCantRequestMoreThanThreePasswordResetsIn120Minutes)
	t.Run("cant request more than 2 password resets for a particular email in 15 minutes", testCantRequestMoreThanTwoPasswordResetsIn15Minutes)
	t.Run("can reset password with token", testCanResetPasswordWithToken)
	t.Run("cant reset password with incorrect token", testCantResetPasswordWithIncorrectToken)
	t.Run("cant reset password with expired token", testCantResetPasswordWithExpiredToken)
}

func TestCreateEmailResetRequest(t *testing.T) {
	t.Run("can request email reset when authenticated", testCanRequestEmailReset)
	t.Run("email reset request fails with incorrect current password", testCreateEmailResetRequestFailsWithIncorrectPassword)
	t.Run("email reset request fails with malformed new email", testCantRequestEmailResetWithMalformedNewEmail)
	t.Run("email reset request fails when new email matches current email", testCantRequestEmailResetWithSameEmail)
	t.Run("email reset request fails when new email already in use", testCantRequestEmailResetWithEmailAlreadyInUse)
	t.Run("email reset request propagates unexpected error checking new email", testCreateEmailResetRequestPropagatesUnexpectedGetUserByEmailError)
	t.Run("cant request more than 3 email resets for a particular email in 120 minutes", testCantRequestMoreThanThreeEmailResetsIn120Minutes)
	t.Run("cant request more than 2 email resets for a particular email in 15 minutes", testCantRequestMoreThanTwoEmailResetsIn15Minutes)
	t.Run("email reset request is rate limited after repeated failed reauthentication", testCreateEmailResetRequestReauthRateLimited)
	t.Run("email reset request and password reset share the reauthentication rate limit budget", testReauthenticationRateLimitSharedAcrossFlows)
}

func testUserSignUp(t *testing.T) {
	userService := setupUserService(t, mockQueries{})
	ctx := context.Background()

	input := AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	}

	user, err := userService.SignUp(ctx, input)
	if err != nil {
		t.Fatalf("SignUp returned error: %v", err)
	}

	if user.DBUser().Email != input.Email {
		t.Fatalf("got email %q, want %q", user.DBUser().Email, input.Email)
	}

	ok, err := argon2.VerifyEncoded([]byte(input.Password), []byte(user.DBUser().PasswordHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error: %v", err)
	}
	if !ok {
		t.Fatal("stored password hash does not match input password")
	}
}

func testUserSignUpRejectsBlankEmailOrPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			t.Fatal("CreateUser should not be called for invalid sign-up input")
			return db.User{}, nil
		},
	})

	testCases := []struct {
		name          string
		email         string
		password      string
		expectedError error
	}{
		{name: "empty email", email: "", password: "example-password", expectedError: ErrEmailBlank},
		{name: "whitespace email", email: "   ", password: "example-password", expectedError: ErrEmailBlank},
		{name: "empty password", email: "test@example.com", password: "", expectedError: ErrPasswordEmpty},
		{name: "whitespace password", email: "test@example.com", password: "   ", expectedError: ErrPasswordEmpty},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := userService.SignUp(ctx, AuthenticateBody{
				Email:    tc.email,
				Password: tc.password,
			})

			if !errors.Is(err, tc.expectedError) {
				t.Fatalf("got error %v, want %v", err, tc.expectedError)
			}
		})
	}
}

func testUserSignUpRejectsShortPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			t.Fatal("CreateUser should not be called for short password")
			return db.User{}, nil
		},
	})

	_, err := userService.SignUp(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "12345678901",
	})

	if !errors.Is(err, ErrPasswordShort) {
		t.Fatalf("got error %v, want %v", err, ErrPasswordShort)
	}
}

func testUserSignUpRejectsLongPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			t.Fatal("CreateUser should not be called for long password")
			return db.User{}, nil
		},
	})

	_, err := userService.SignUp(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: strings.Repeat("a", 257),
	})

	if !errors.Is(err, ErrPasswordLong) {
		t.Fatalf("got error %v, want %v", err, ErrPasswordLong)
	}
}

func testUserSignUpRejectsCommonPassword(t *testing.T) {
	ctx := context.Background()
	commonPassword := "thisiscommonpassword"
	userService := setupUserService(t, mockQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			t.Fatal("CreateUser should not be called for common password")
			return db.User{}, nil
		},
	})
	userService.commonPasswords = commonPasswords{commonPassword: struct{}{}}

	_, err := userService.SignUp(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: commonPassword,
	})

	if !errors.Is(err, ErrPasswordCommon) {
		t.Fatalf("got error %v, want %v", err, ErrPasswordCommon)
	}
}

func testUserSignUpRejectsInvalidEmail(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
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

	userService := setupUserService(t, mockQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			if arg.Email != expectedEmail {
				t.Fatalf("CreateUser got email %q, want %q", arg.Email, expectedEmail)
			}

			return db.User{
				ID:           1,
				Email:        arg.Email,
				PasswordHash: arg.PasswordHash,
				IsActive:     true,
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

	if user.DBUser().Email != expectedEmail {
		t.Fatalf("got email %q, want %q", user.DBUser().Email, expectedEmail)
	}
}

func testUserSignUpEmailTaken(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		CreateUserFn: func(ctx context.Context, arg db.CreateUserParams) (db.User, error) {
			return db.User{}, &pgconn.PgError{
				Code: "23505",
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

func testUserLogIn(t *testing.T) {
	ctx := context.Background()

	id := int64(1)
	email := "test@example.com"
	password := "password"
	authAttemptCreated := false

	passwordHash := hashPassword(t, password)

	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{ID: id, Email: email, PasswordHash: passwordHash, IsActive: true}, nil
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			authAttemptCreated = true
			if arg.Action != db.AuthActionLogin {
				t.Fatalf("CreateLoginAuthAttempt got action %q, want %q", arg.Action, db.AuthActionLogin)
			}
			if arg.Email != email {
				t.Fatalf("CreateLoginAuthAttempt got email %q, want %q", arg.Email, email)
			}
			if arg.Outcome != db.AuthOutcomeSucceeded {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeSucceeded)
			}
			return nil
		},
	})

	user, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    email,
		Password: password,
	})
	if err != nil {
		t.Fatalf("got error %v, expected nil", err)
	}

	if user.DBUser().ID != id {
		t.Fatalf("got id %v, expected %v", user.DBUser().ID, id)
	}

	if user.DBUser().Email != email {
		t.Fatalf("got email %v, expected %v", user.DBUser().Email, email)
	}

	if user.DBUser().PasswordHash != passwordHash {
		t.Fatalf("got password hash %v, expected %v", user.DBUser().PasswordHash, passwordHash)
	}

	if !authAttemptCreated {
		t.Fatal("expected CreateLoginAuthAttempt to be called")
	}
}

func testUserLogInRejectsBlankEmailOrPassword(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for invalid log-in input")
			return db.User{}, nil
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			t.Fatalf("i should not be called")
			return nil
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

func testUserLogInWrongPassword(t *testing.T) {
	ctx := context.Background()
	authAttemptCreated := false

	passwordHash := hashPassword(t, "correct-password")

	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{ID: 1, Email: email, PasswordHash: passwordHash, IsActive: true}, nil
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			authAttemptCreated = true
			if arg.Outcome != db.AuthOutcomeFailed {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeFailed)
			}
			return nil
		},
	})

	_, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "wrong-password",
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}

	if !authAttemptCreated {
		t.Fatal("expected CreateLoginAuthAttempt to be called")
	}
}

func testUserLogInRejectsInvalidEmail(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for invalid email")
			return db.User{}, nil
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			t.Fatal("i should not be called")
			return nil
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
	authAttemptCreated := false
	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{}, pgx.ErrNoRows
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			authAttemptCreated = true
			if arg.Outcome != db.AuthOutcomeFailed {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeFailed)
			}
			return nil
		},
	})

	_, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}

	if !authAttemptCreated {
		t.Fatal("expected CreateLoginAuthAttempt to be called")
	}
}

func testUserLogInPropagatesUnexpectedError(t *testing.T) {
	ctx := context.Background()
	expectedErr := errors.New("database unavailable")

	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{}, expectedErr
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			t.Fatalf("i should not be called")
			return nil
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
	authAttemptCreated := false

	passwordHash := hashPassword(t, password)

	userService := setupUserService(t, mockQueries{
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			return db.User{ID: id, Email: email, PasswordHash: passwordHash, IsActive: false}, nil
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			authAttemptCreated = true
			if arg.Outcome != db.AuthOutcomeFailed {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeFailed)
			}
			return nil
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

	if !authAttemptCreated {
		t.Fatal("expected CreateLoginAuthAttempt to be called")
	}
}

func testUserLogInRateLimited(t *testing.T) {
	ctx := context.Background()
	userService := setupUserService(t, mockQueries{
		CountFailedAuthAttemptsSinceFn: func(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
			return rateLimitLoginAttemptsAllowed, nil
		},
		GetUserByEmailFn: func(ctx context.Context, email string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for rate limited login")
			return db.User{}, nil
		},
		CreateLoginAuthAttemptFn: func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited login")
			return nil
		},
	})

	_, err := userService.LogIn(ctx, AuthenticateBody{
		Email:    "test@example.com",
		Password: "example-password",
	})

	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}
}

func testGetUserByID(t *testing.T) {
	ctx := context.Background()
	wantID := int64(42)
	wantEmail := "test@example.com"

	userService := setupUserService(t, mockQueries{
		GetUserByIDFn: func(ctx context.Context, id int64) (db.User, error) {
			if id != wantID {
				t.Fatalf("GetUserByID got id %v, want %v", id, wantID)
			}

			return db.User{ID: id, Email: wantEmail, IsActive: true}, nil
		},
	})

	user, err := userService.GetUserByID(ctx, wantID)
	if err != nil {
		t.Fatalf("GetUserByID returned error: %v", err)
	}

	if user.DBUser().ID != wantID {
		t.Fatalf("got id %v, want %v", user.DBUser().ID, wantID)
	}

	if user.DBUser().Email != wantEmail {
		t.Fatalf("got email %v, want %v", user.DBUser().Email, wantEmail)
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

func testResetPasswordForAuthenticatedUser(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"
	newPassword := "brand-new-password"

	usr := UserFromDB(db.User{
		ID:           42,
		PasswordHash: hashPassword(t, currentPassword),
	})

	updated := false
	var updatedHash string

	userService := setupUserService(t, mockQueries{
		UpdatePasswordHashFn: func(_ context.Context, arg db.UpdatePasswordHashParams) error {

			if arg.ID != usr.DBUser().ID {
				t.Fatalf("UpdatePasswordHash got id %v, want %v", arg.ID, usr.DBUser().ID)
			}

			updated = true
			updatedHash = arg.PasswordHash
			return nil
		},
	})

	err := userService.ResetPasswordForAuthenticatedUser(ctx, usr, AuthenticatedPasswordResetBody{
		Password:    currentPassword,
		NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("ResetPasswordForAuthenticatedUser returned error: %v", err)
	}

	if !updated {
		t.Fatal("UpdatePasswordHash was not called")
	}

	newPasswordMatches, err := argon2.VerifyEncoded([]byte(newPassword), []byte(updatedHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error for new password: %v", err)
	}
	if !newPasswordMatches {
		t.Fatal("updated hash does not match new password")
	}

	oldPasswordMatches, err := argon2.VerifyEncoded([]byte(currentPassword), []byte(updatedHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error for current password: %v", err)
	}
	if oldPasswordMatches {
		t.Fatal("updated hash matched current password, expected new password hash")
	}
}

func testResetPasswordForAuthenticatedUserWrongCurrentPassword(t *testing.T) {
	ctx := context.Background()
	actualCurrentPassword := "correct-current-password"
	providedCurrentPassword := "wrong-current-password"
	newPassword := "brand-new-password"

	usr := UserFromDB(db.User{
		ID:           84,
		PasswordHash: hashPassword(t, actualCurrentPassword),
	})

	userService := setupUserService(t, mockQueries{
		UpdatePasswordHashFn: func(context.Context, db.UpdatePasswordHashParams) error {
			t.Fatal("UpdatePasswordHash should not be called when current password is incorrect")
			return nil
		},
	})

	err := userService.ResetPasswordForAuthenticatedUser(ctx, usr, AuthenticatedPasswordResetBody{
		Password:    providedCurrentPassword,
		NewPassword: newPassword,
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}
}

func testResetPasswordForAuthenticatedUserReauthRateLimited(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        "current@example.com",
		PasswordHash: hashPassword(t, currentPassword),
	})

	rateLimitChecked := false

	userService := setupUserService(t, mockQueries{
		CountFailedAuthAttemptsSinceFn: func(_ context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
			if arg.Action != db.AuthActionReauthentication {
				t.Fatalf("CountFailedAuthAttemptsSince got action %q, want %q", arg.Action, db.AuthActionReauthentication)
			}
			if arg.Email != usr.DBUser().Email {
				t.Fatalf("CountFailedAuthAttemptsSince got email %q, want %q", arg.Email, usr.DBUser().Email)
			}
			rateLimitChecked = true
			return rateLimitLoginAttemptsAllowed, nil
		},
		UpdatePasswordHashFn: func(context.Context, db.UpdatePasswordHashParams) error {
			t.Fatal("UpdatePasswordHash should not be called for rate limited reauthentication")
			return nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited reauthentication")
			return nil
		},
	})

	err := userService.ResetPasswordForAuthenticatedUser(ctx, usr, AuthenticatedPasswordResetBody{
		Password:    currentPassword,
		NewPassword: "brand-new-password",
	})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}

	if !rateLimitChecked {
		t.Fatal("CountFailedAuthAttemptsSince was not called")
	}
}

func testResetPasswordForAuthenticatedUserRecordsFailedReauthAttempt(t *testing.T) {
	ctx := context.Background()
	actualCurrentPassword := "correct-current-password"
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, actualCurrentPassword),
	})

	authAttemptCreated := false

	userService := setupUserService(t, mockQueries{
		UpdatePasswordHashFn: func(context.Context, db.UpdatePasswordHashParams) error {
			t.Fatal("UpdatePasswordHash should not be called when current password is incorrect")
			return nil
		},
		CreateLoginAuthAttemptFn: func(_ context.Context, arg db.CreateLoginAuthAttemptParams) error {
			if arg.Action != db.AuthActionReauthentication {
				t.Fatalf("CreateLoginAuthAttempt got action %q, want %q", arg.Action, db.AuthActionReauthentication)
			}
			if arg.Email != currentEmail {
				t.Fatalf("CreateLoginAuthAttempt got email %q, want %q", arg.Email, currentEmail)
			}
			if arg.Outcome != db.AuthOutcomeFailed {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeFailed)
			}
			authAttemptCreated = true
			return nil
		},
	})

	err := userService.ResetPasswordForAuthenticatedUser(ctx, usr, AuthenticatedPasswordResetBody{
		Password:    "wrong-current-password",
		NewPassword: "brand-new-password",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}

	if !authAttemptCreated {
		t.Fatal("CreateLoginAuthAttempt was not called")
	}
}

func testResetPasswordForAuthenticatedUserRejectsWeakPassword(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"

	usr := UserFromDB(db.User{
		ID:           128,
		PasswordHash: hashPassword(t, currentPassword),
	})

	testCases := []struct {
		name          string
		newPassword   string
		expectedError error
	}{
		{name: "empty password", newPassword: "", expectedError: ErrPasswordEmpty},
		{name: "whitespace password", newPassword: "   ", expectedError: ErrPasswordEmpty},
		{name: "short password", newPassword: "12345678901", expectedError: ErrPasswordShort},
		{name: "long password", newPassword: strings.Repeat("a", 257), expectedError: ErrPasswordLong},
		{name: "common password", newPassword: "thisiscommonpassword", expectedError: ErrPasswordCommon},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userService := setupUserService(t, mockQueries{
				UpdatePasswordHashFn: func(context.Context, db.UpdatePasswordHashParams) error {
					t.Fatal("UpdatePasswordHash should not be called for weak password")
					return nil
				},
			})

			if errors.Is(tc.expectedError, ErrPasswordCommon) {
				userService.commonPasswords = commonPasswords{tc.newPassword: struct{}{}}
			}

			err := userService.ResetPasswordForAuthenticatedUser(ctx, usr, AuthenticatedPasswordResetBody{
				Password:    currentPassword,
				NewPassword: tc.newPassword,
			})
			if !errors.Is(err, tc.expectedError) {
				t.Fatalf("got error %v, want %v", err, tc.expectedError)
			}
		})
	}
}

func testCanRequestPasswordReset(t *testing.T) {
	ctx := context.Background()
	inputEmail := " User@Example.COM "
	normalizedEmail := "User@example.com"
	userID := int64(42)

	countChecked := false
	gotUser := false
	resetRequested := false
	emailSent := false
	authAttemptCreated := false

	passwordResetURL := "http://example.com/password-reset"
	userService := setupUserServiceWithEmail(t, mockQueries{
		CountTieredAuthAttemptsFn: func(_ context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			if arg.Email != normalizedEmail {
				t.Fatalf("CountTieredAuthAttempts got email %q, want %q", arg.Email, normalizedEmail)
			}
			countChecked = true
			return db.CountTieredAuthAttemptsRow{}, nil
		},
		GetUserByEmailFn: func(_ context.Context, email string) (db.User, error) {
			if email != normalizedEmail {
				t.Fatalf("GetUserByEmail got email %q, want %q", email, normalizedEmail)
			}
			gotUser = true
			return db.User{ID: userID, Email: normalizedEmail, IsActive: true}, nil
		},
		CreatePasswordResetRequestFn: func(_ context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
			if arg.UserID != userID {
				t.Fatalf("CreatePasswordResetRequest got userID %v, want %v", arg.UserID, userID)
			}
			if len(arg.ID) != 32 {
				t.Fatalf("CreatePasswordResetRequest got token hash length %v, want 32", len(arg.ID))
			}
			resetRequested = true
			return db.PasswordResetRequest{ID: arg.ID, UserID: arg.UserID}, nil
		},
		CreateLoginAuthAttemptFn: func(_ context.Context, arg db.CreateLoginAuthAttemptParams) error {
			if arg.Action != db.AuthActionPasswordReset {
				t.Fatalf("CreateLoginAuthAttempt got action %q, want %q", arg.Action, db.AuthActionPasswordReset)
			}
			if arg.Email != normalizedEmail {
				t.Fatalf("CreateLoginAuthAttempt got email %q, want %q", arg.Email, normalizedEmail)
			}
			if arg.Outcome != db.AuthOutcomeSucceeded {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeSucceeded)
			}
			authAttemptCreated = true
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(toEmail string, subject string, body string) error {
			prefix := "http://example.com/password-reset/?token="

			if toEmail != normalizedEmail {
				t.Fatalf("SendMail got toEmail %q, want %q", toEmail, normalizedEmail)
			}
			if subject != "Password Reset" {
				t.Fatalf("SendMail got subject %q, want %q", subject, "Password Reset")
			}
			if !strings.HasPrefix(body, prefix) {
				t.Fatalf("SendMail got body %q, want prefix %q", body, prefix)
			}
			if len(body) <= len(prefix) {
				t.Fatalf("SendMail got body %q, want token appended", body)
			}
			emailSent = true
			return nil
		},
	}, passwordResetURL)

	err := userService.CreatePasswordResetRequest(ctx, CreatePasswordResetRequestBody{Email: inputEmail})
	if err != nil {
		t.Fatalf("CreatePasswordResetRequest returned error: %v", err)
	}

	if !countChecked {
		t.Fatal("CountTieredAuthAttempts was not called")
	}
	if !gotUser {
		t.Fatal("GetUserByEmail was not called")
	}
	if !resetRequested {
		t.Fatal("CreatePasswordResetRequest was not called")
	}
	if !emailSent {
		t.Fatal("SendMail was not called")
	}
	if !authAttemptCreated {
		t.Fatal("CreateLoginAuthAttempt was not called")
	}
}

func testCantCreatePasswordResetWithMalformedEmail(t *testing.T) {
	ctx := context.Background()

	userService := setupUserServiceWithEmail(t, mockQueries{
		CountTieredAuthAttemptsFn: func(context.Context, db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			t.Fatal("CountTieredAuthAttempts should not be called for malformed email")
			return db.CountTieredAuthAttemptsRow{}, nil
		},
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for malformed email")
			return db.User{}, nil
		},
		CreatePasswordResetRequestFn: func(context.Context, db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
			t.Fatal("CreatePasswordResetRequest should not be called for malformed email")
			return db.PasswordResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for malformed email")
			return nil
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

func testCantRequestMoreThanThreePasswordResetsIn120Minutes(t *testing.T) {
	ctx := context.Background()
	inputEmail := "user@example.com"
	rateLimitChecked := false

	userService := setupUserServiceWithEmail(t, mockQueries{
		CountTieredAuthAttemptsFn: func(_ context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			if arg.Email != inputEmail {
				t.Fatalf("CountTieredAuthAttempts got email %q, want %q", arg.Email, inputEmail)
			}
			rateLimitChecked = true
			return db.CountTieredAuthAttemptsRow{OldCount: 3, RecentCount: 0}, nil
		},
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for rate limited password reset request")
			return db.User{}, nil
		},
		CreatePasswordResetRequestFn: func(context.Context, db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
			t.Fatal("CreatePasswordResetRequest should not be called for rate limited password reset request")
			return db.PasswordResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited password reset request")
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for rate limited password reset request")
			return nil
		},
	}, "http://example.com/password-reset")

	err := userService.CreatePasswordResetRequest(ctx, CreatePasswordResetRequestBody{Email: inputEmail})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}

	if !rateLimitChecked {
		t.Fatal("CountTieredAuthAttempts was not called")
	}
}

func testRequestingTokenPasswordResetForUnknownEmail(t *testing.T) {
	ctx := context.Background()
	inputEmail := "unknown@example.com"
	rateLimitChecked := false

	userService := setupUserServiceWithEmail(t, mockQueries{
		CountTieredAuthAttemptsFn: func(_ context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			if arg.Email != inputEmail {
				t.Fatalf("CountTieredAuthAttempts got email %q, want %q", arg.Email, inputEmail)
			}
			rateLimitChecked = true
			return db.CountTieredAuthAttemptsRow{}, nil
		},
		GetUserByEmailFn: func(_ context.Context, email string) (db.User, error) {
			if email != inputEmail {
				t.Fatalf("GetUserByEmail got email %q, want %q", email, inputEmail)
			}
			return db.User{}, pgx.ErrNoRows
		},
		CreatePasswordResetRequestFn: func(context.Context, db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
			t.Fatal("CreatePasswordResetRequest should not be called for unknown email")
			return db.PasswordResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(_ context.Context, arg db.CreateLoginAuthAttemptParams) error {

			if arg.Action != db.AuthActionPasswordReset {
				t.Fatalf("got action %v, want %v", arg.Action, db.AuthActionPasswordReset)
			}

			if arg.Email != inputEmail {
				t.Fatalf("got email %v, want %v", arg.Email, inputEmail)
			}

			if arg.Outcome != db.AuthOutcomeFailed {
				t.Fatalf("got outcome %v, want %v", arg.Outcome, db.AuthOutcomeFailed)
			}

			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for unknown email")
			return nil
		},
	}, "http://example.com/password-reset")

	err := userService.CreatePasswordResetRequest(ctx, CreatePasswordResetRequestBody{Email: inputEmail})
	if !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("got error %v, want %v", err, ErrUserNotFound)
	}

	if !rateLimitChecked {
		t.Fatal("CountTieredAuthAttempts was not called")
	}
}

func testCantRequestMoreThanTwoPasswordResetsIn15Minutes(t *testing.T) {
	ctx := context.Background()
	inputEmail := "user@example.com"
	rateLimitChecked := false

	userService := setupUserServiceWithEmail(t, mockQueries{
		CountTieredAuthAttemptsFn: func(_ context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			if arg.Email != inputEmail {
				t.Fatalf("CountTieredAuthAttempts got email %q, want %q", arg.Email, inputEmail)
			}
			rateLimitChecked = true
			return db.CountTieredAuthAttemptsRow{OldCount: 0, RecentCount: 2}, nil
		},
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for rate limited password reset request")
			return db.User{}, nil
		},
		CreatePasswordResetRequestFn: func(context.Context, db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error) {
			t.Fatal("CreatePasswordResetRequest should not be called for rate limited password reset request")
			return db.PasswordResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited password reset request")
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for rate limited password reset request")
			return nil
		},
	}, "http://example.com/password-reset")

	err := userService.CreatePasswordResetRequest(ctx, CreatePasswordResetRequestBody{Email: inputEmail})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}

	if !rateLimitChecked {
		t.Fatal("CountTieredAuthAttempts was not called")
	}
}

func testCanResetPasswordWithToken(t *testing.T) {
	ctx := context.Background()
	rawToken := []byte("0123456789abcdef")
	encodedToken := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)
	userID := int64(99)
	newPassword := "brand-new-password"

	updated := false
	consumed := false
	var updatedHash string

	userService := setupUserService(t, mockQueries{
		ConsumePasswordResetRequestFn: func(_ context.Context, id []byte) (db.PasswordResetRequest, error) {
			if string(id) != string(tokenHash[:]) {
				t.Fatalf("ConsumePasswordResetRequest got id %v, want %v", id, tokenHash[:])
			}

			consumed = true

			return db.PasswordResetRequest{
				ID:     tokenHash[:],
				UserID: userID,
				CreatedAt: pgtype.Timestamptz{
					Time:  time.Now(),
					Valid: true,
				},
			}, nil
		},
		UpdatePasswordHashFn: func(_ context.Context, arg db.UpdatePasswordHashParams) error {
			if arg.ID != userID {
				t.Fatalf("UpdatePasswordHash got id %v, want %v", arg.ID, userID)
			}

			updated = true
			updatedHash = arg.PasswordHash
			return nil
		},
	})

	_, err := userService.ResetPasswordFromResetRequest(ctx, encodedToken, ResetPasswordFromResetRequestBody{
		NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("ResetPasswordFromResetRequest returned error: %v", err)
	}

	if !updated {
		t.Fatal("UpdatePasswordHash was not called")
	}
	if !consumed {
		t.Fatal("ConsumePasswordResetRequest was not called")
	}
	newPasswordMatches, err := argon2.VerifyEncoded([]byte(newPassword), []byte(updatedHash))
	if err != nil {
		t.Fatalf("VerifyEncoded returned error for new password: %v", err)
	}
	if !newPasswordMatches {
		t.Fatal("updated hash does not match new password")
	}
}

func testCantResetPasswordWithIncorrectToken(t *testing.T) {
	ctx := context.Background()
	rawToken := []byte("fedcba9876543210")
	encodedToken := base64.RawURLEncoding.EncodeToString(rawToken)
	tokenHash := sha256.Sum256(rawToken)

	queried := false

	userService := setupUserService(t, mockQueries{
		ConsumePasswordResetRequestFn: func(_ context.Context, id []byte) (db.PasswordResetRequest, error) {
			if string(id) != string(tokenHash[:]) {
				t.Fatalf("ConsumePasswordResetRequest got id %v, want %v", id, tokenHash[:])
			}

			queried = true
			return db.PasswordResetRequest{}, pgx.ErrNoRows
		},
		UpdatePasswordHashFn: func(context.Context, db.UpdatePasswordHashParams) error {
			t.Fatal("UpdatePasswordHash should not be called for incorrect token")
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
					Time:  time.Now().Add(-((passwordResetTokenDurationMinutes + 1) * time.Minute)),
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

func testCanRequestEmailReset(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"
	currentEmail := "current@example.com"
	inputNewEmail := " New@Example.COM "
	normalizedNewEmail := "New@example.com"
	userID := int64(42)

	usr := UserFromDB(db.User{
		ID:           userID,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, currentPassword),
	})

	gotExistingUserCheck := false
	resetRequested := false
	newEmailMailed := false
	oldEmailNotified := false
	reauthAttemptCreated := false
	emailResetAttemptCreated := false

	emailResetURL := "http://example.com/email-reset"
	userService := setupUserServiceWithEmailReset(t, mockQueries{
		GetUserByEmailFn: func(_ context.Context, email string) (db.User, error) {
			if email != normalizedNewEmail {
				t.Fatalf("GetUserByEmail got email %q, want %q", email, normalizedNewEmail)
			}
			gotExistingUserCheck = true
			return db.User{}, pgx.ErrNoRows
		},
		CreateEmailResetRequestFn: func(_ context.Context, arg db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			if arg.UserID != userID {
				t.Fatalf("CreateEmailResetRequest got userID %v, want %v", arg.UserID, userID)
			}
			if arg.NewEmail != normalizedNewEmail {
				t.Fatalf("CreateEmailResetRequest got newEmail %q, want %q", arg.NewEmail, normalizedNewEmail)
			}
			if len(arg.ID) == 0 {
				t.Fatal("CreateEmailResetRequest got empty token id")
			}
			resetRequested = true
			return db.EmailResetRequest{ID: arg.ID, UserID: arg.UserID, NewEmail: arg.NewEmail}, nil
		},
		CreateLoginAuthAttemptFn: func(_ context.Context, arg db.CreateLoginAuthAttemptParams) error {
			if arg.Email != currentEmail {
				t.Fatalf("CreateLoginAuthAttempt got email %q, want %q", arg.Email, currentEmail)
			}
			if arg.Outcome != db.AuthOutcomeSucceeded {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeSucceeded)
			}
			switch arg.Action {
			case db.AuthActionReauthentication:
				reauthAttemptCreated = true
			case db.AuthActionEmailReset:
				emailResetAttemptCreated = true
			default:
				t.Fatalf("CreateLoginAuthAttempt got unexpected action %q", arg.Action)
			}
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(toEmail string, subject string, body string) error {
			switch toEmail {
			case normalizedNewEmail:
				prefix := "http://example.com/email-reset/?token="
				if subject != "Email Reset" {
					t.Fatalf("SendMail to new email got subject %q, want %q", subject, "Email Reset")
				}
				if !strings.HasPrefix(body, prefix) {
					t.Fatalf("SendMail to new email got body %q, want prefix %q", body, prefix)
				}
				if len(body) <= len(prefix) {
					t.Fatalf("SendMail to new email got body %q, want token appended", body)
				}
				newEmailMailed = true
			case currentEmail:
				if subject != "Email Change Requested" {
					t.Fatalf("SendMail to old email got subject %q, want %q", subject, "Email Change Requested")
				}
				oldEmailNotified = true
			default:
				t.Fatalf("SendMail called with unexpected recipient %q", toEmail)
			}
			return nil
		},
	}, emailResetURL)

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: currentPassword,
		NewEmail: inputNewEmail,
	})
	if err != nil {
		t.Fatalf("CreateEmailResetRequest returned error: %v", err)
	}

	if !gotExistingUserCheck {
		t.Fatal("GetUserByEmail was not called")
	}
	if !resetRequested {
		t.Fatal("CreateEmailResetRequest was not called")
	}
	if !newEmailMailed {
		t.Fatal("SendMail to new email was not called")
	}
	if !oldEmailNotified {
		t.Fatal("SendMail to old email was not called")
	}
	if !reauthAttemptCreated {
		t.Fatal("CreateLoginAuthAttempt was not called for reauthentication")
	}
	if !emailResetAttemptCreated {
		t.Fatal("CreateLoginAuthAttempt was not called for email_reset")
	}
}

func testCantRequestMoreThanThreeEmailResetsIn120Minutes(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, currentPassword),
	})

	rateLimitChecked := false

	userService := setupUserServiceWithEmailReset(t, mockQueries{
		CountTieredAuthAttemptsFn: func(_ context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			if arg.Email != currentEmail {
				t.Fatalf("CountTieredAuthAttempts got email %q, want %q", arg.Email, currentEmail)
			}
			rateLimitChecked = true
			return db.CountTieredAuthAttemptsRow{OldCount: 3, RecentCount: 0}, nil
		},
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for rate limited email reset request")
			return db.User{}, nil
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called for rate limited email reset request")
			return db.EmailResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited email reset request")
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for rate limited email reset request")
			return nil
		},
	}, "http://example.com/email-reset")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: currentPassword,
		NewEmail: "new@example.com",
	})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}

	if !rateLimitChecked {
		t.Fatal("CountTieredAuthAttempts was not called")
	}
}

func testCantRequestMoreThanTwoEmailResetsIn15Minutes(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, currentPassword),
	})

	rateLimitChecked := false

	userService := setupUserServiceWithEmailReset(t, mockQueries{
		CountTieredAuthAttemptsFn: func(_ context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
			if arg.Email != currentEmail {
				t.Fatalf("CountTieredAuthAttempts got email %q, want %q", arg.Email, currentEmail)
			}
			rateLimitChecked = true
			return db.CountTieredAuthAttemptsRow{OldCount: 0, RecentCount: 2}, nil
		},
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for rate limited email reset request")
			return db.User{}, nil
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called for rate limited email reset request")
			return db.EmailResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited email reset request")
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for rate limited email reset request")
			return nil
		},
	}, "http://example.com/email-reset")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: currentPassword,
		NewEmail: "new@example.com",
	})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}

	if !rateLimitChecked {
		t.Fatal("CountTieredAuthAttempts was not called")
	}
}

func testCreateEmailResetRequestFailsWithIncorrectPassword(t *testing.T) {
	ctx := context.Background()

	// Arrange
	actualPassword := "correct-current-password"
	providedPassword := "wrong-current-password"
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, actualPassword),
	})

	authAttemptCreated := false

	userService := setupUserServiceWithEmail(t, mockQueries{
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called when password is incorrect")
			return db.EmailResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(_ context.Context, arg db.CreateLoginAuthAttemptParams) error {
			if arg.Action != db.AuthActionReauthentication {
				t.Fatalf("CreateLoginAuthAttempt got action %q, want %q", arg.Action, db.AuthActionReauthentication)
			}
			if arg.Email != currentEmail {
				t.Fatalf("CreateLoginAuthAttempt got email %q, want %q", arg.Email, currentEmail)
			}
			if arg.Outcome != db.AuthOutcomeFailed {
				t.Fatalf("CreateLoginAuthAttempt got outcome %q, want %q", arg.Outcome, db.AuthOutcomeFailed)
			}
			authAttemptCreated = true
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(toEmail string, subject string, body string) error {
			t.Fatal("SendMail should not be called when password is incorrect")
			return nil
		},
	}, "")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: providedPassword,
		NewEmail: "new@example.com",
	})

	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("got error %v, want %v", err, ErrInvalidCredentials)
	}
	if !authAttemptCreated {
		t.Fatal("CreateLoginAuthAttempt was not called")
	}
}

func testCreateEmailResetRequestReauthRateLimited(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, currentPassword),
	})

	rateLimitChecked := false

	userService := setupUserServiceWithEmailReset(t, mockQueries{
		CountFailedAuthAttemptsSinceFn: func(_ context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
			if arg.Action != db.AuthActionReauthentication {
				t.Fatalf("CountFailedAuthAttemptsSince got action %q, want %q", arg.Action, db.AuthActionReauthentication)
			}
			if arg.Email != currentEmail {
				t.Fatalf("CountFailedAuthAttemptsSince got email %q, want %q", arg.Email, currentEmail)
			}
			rateLimitChecked = true
			return rateLimitLoginAttemptsAllowed, nil
		},
		GetUserByEmailFn: func(context.Context, string) (db.User, error) {
			t.Fatal("GetUserByEmail should not be called for rate limited reauthentication")
			return db.User{}, nil
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called for rate limited reauthentication")
			return db.EmailResetRequest{}, nil
		},
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for rate limited reauthentication")
			return nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called for rate limited reauthentication")
			return nil
		},
	}, "http://example.com/email-reset")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: currentPassword,
		NewEmail: "new@example.com",
	})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("got error %v, want %v", err, ErrRateLimit)
	}

	if !rateLimitChecked {
		t.Fatal("CountFailedAuthAttemptsSince was not called")
	}
}

// testReauthenticationRateLimitSharedAcrossFlows asserts that password-change and
// email-reset-request reauthentication both check and record against the same
// db.AuthActionReauthentication + email budget, so an attacker cannot get a bigger
// guessing budget by switching endpoints.
func testReauthenticationRateLimitSharedAcrossFlows(t *testing.T) {
	ctx := context.Background()
	currentPassword := "correct-current-password"
	currentEmail := "current@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, currentPassword),
	})

	var checkedActions, checkedEmails []string

	newQueries := func() mockQueries {
		return mockQueries{
			CountFailedAuthAttemptsSinceFn: func(_ context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
				checkedActions = append(checkedActions, string(arg.Action))
				checkedEmails = append(checkedEmails, arg.Email)
				return rateLimitLoginAttemptsAllowed, nil
			},
		}
	}

	passwordResetQueries := newQueries()
	passwordResetService := setupUserService(t, passwordResetQueries)
	err := passwordResetService.ResetPasswordForAuthenticatedUser(ctx, usr, AuthenticatedPasswordResetBody{
		Password:    currentPassword,
		NewPassword: "brand-new-password",
	})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("ResetPasswordForAuthenticatedUser got error %v, want %v", err, ErrRateLimit)
	}

	emailResetQueries := newQueries()
	emailResetService := setupUserServiceWithEmailReset(t, emailResetQueries, email.MockEmailService{}, "http://example.com/email-reset")
	err = emailResetService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: currentPassword,
		NewEmail: "new@example.com",
	})
	if !errors.Is(err, ErrRateLimit) {
		t.Fatalf("CreateEmailResetRequest got error %v, want %v", err, ErrRateLimit)
	}

	for i, action := range checkedActions {
		if action != string(db.AuthActionReauthentication) {
			t.Fatalf("check %d: got action %q, want %q", i, action, db.AuthActionReauthentication)
		}
		if checkedEmails[i] != currentEmail {
			t.Fatalf("check %d: got email %q, want %q", i, checkedEmails[i], currentEmail)
		}
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
		CreateLoginAuthAttemptFn: func(context.Context, db.CreateLoginAuthAttemptParams) error {
			t.Fatal("CreateLoginAuthAttempt should not be called for malformed new email")
			return nil
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

func testCantRequestEmailResetWithEmailAlreadyInUse(t *testing.T) {
	ctx := context.Background()
	currentEmail := "current@example.com"
	newEmail := "new@example.com"

	usr := UserFromDB(db.User{
		ID:           42,
		Email:        currentEmail,
		PasswordHash: hashPassword(t, "correct-current-password"),
	})

	gotExistingUserCheck := false

	userService := setupUserServiceWithEmail(t, mockQueries{
		GetUserByEmailFn: func(_ context.Context, email string) (db.User, error) {
			if email != newEmail {
				t.Fatalf("GetUserByEmail got email %q, want %q", email, newEmail)
			}
			gotExistingUserCheck = true
			return db.User{ID: 99, Email: newEmail}, nil
		},
		CreateEmailResetRequestFn: func(context.Context, db.CreateEmailResetRequestParams) (db.EmailResetRequest, error) {
			t.Fatal("CreateEmailResetRequest should not be called when new email is already in use")
			return db.EmailResetRequest{}, nil
		},
	}, email.MockEmailService{
		SendMailFn: func(string, string, string) error {
			t.Fatal("SendMail should not be called when new email is already in use")
			return nil
		},
	}, "")

	err := userService.CreateEmailResetRequest(ctx, usr, CreateEmailResetRequestBody{
		Password: "correct-current-password",
		NewEmail: newEmail,
	})
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("got error %v, want %v", err, ErrEmailTaken)
	}
	if !gotExistingUserCheck {
		t.Fatal("GetUserByEmail was not called")
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
	CreateUserFn                   func(ctx context.Context, arg db.CreateUserParams) (db.User, error)
	GetUserByEmailFn               func(ctx context.Context, email string) (db.User, error)
	GetUserByIDFn                  func(ctx context.Context, id int64) (db.User, error)
	CountFailedAuthAttemptsSinceFn func(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error)
	CountTieredAuthAttemptsFn      func(ctx context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error)
	CreateLoginAuthAttemptFn       func(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error
	CreatePasswordResetRequestFn   func(ctx context.Context, arg db.CreatePasswordResetRequestParams) (db.PasswordResetRequest, error)
	ConsumePasswordResetRequestFn  func(ctx context.Context, id []byte) (db.PasswordResetRequest, error)
	UpdatePasswordHashFn           func(ctx context.Context, arg db.UpdatePasswordHashParams) error
	CreateEmailResetRequestFn      func(ctx context.Context, arg db.CreateEmailResetRequestParams) (db.EmailResetRequest, error)
	ConsumeEmailResetRequestFn     func(ctx context.Context, id []byte) (db.EmailResetRequest, error)
	UpdateEmailFn                  func(ctx context.Context, arg db.UpdateEmailParams) error
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

func (q *mockQueries) CountFailedAuthAttemptsSince(ctx context.Context, arg db.CountFailedAuthAttemptsSinceParams) (int64, error) {
	if q.CountFailedAuthAttemptsSinceFn != nil {
		return q.CountFailedAuthAttemptsSinceFn(ctx, arg)
	}
	return 0, nil
}

func (q *mockQueries) CountTieredAuthAttempts(ctx context.Context, arg db.CountTieredAuthAttemptsParams) (db.CountTieredAuthAttemptsRow, error) {
	if q.CountTieredAuthAttemptsFn != nil {
		return q.CountTieredAuthAttemptsFn(ctx, arg)
	}

	return db.CountTieredAuthAttemptsRow{}, nil
}

func (q *mockQueries) CreateLoginAuthAttempt(ctx context.Context, arg db.CreateLoginAuthAttemptParams) error {
	if q.CreateLoginAuthAttemptFn != nil {
		return q.CreateLoginAuthAttemptFn(ctx, arg)
	}

	return nil
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

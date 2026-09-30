package user

import "context"

type MockService struct {
	SignUpFn                            func(ctx context.Context, input AuthenticateBody) (User, error)
	LogInFn                             func(ctx context.Context, input AuthenticateBody) (User, error)
	ResetPasswordForAuthenticatedUserFn func(ctx context.Context, usr User, input AuthenticatedPasswordResetBody) error
	CreatePasswordResetRequestFn        func(ctx context.Context, reqBody CreatePasswordResetRequestBody) error
	ResetPasswordFromResetRequestFn     func(ctx context.Context, token string, input ResetPasswordFromResetRequestBody) error
	GetUserByIDFn                       func(ctx context.Context, id int64) (User, error)
}

func (s MockService) SignUp(ctx context.Context, input AuthenticateBody) (User, error) {
	if s.SignUpFn != nil {
		return s.SignUpFn(ctx, input)
	}

	return User{}, nil
}

func (s MockService) LogIn(ctx context.Context, input AuthenticateBody) (User, error) {
	if s.LogInFn != nil {
		return s.LogInFn(ctx, input)
	}

	return User{}, nil
}

func (s MockService) ResetPasswordForAuthenticatedUser(ctx context.Context, usr User, input AuthenticatedPasswordResetBody) error {
	if s.ResetPasswordForAuthenticatedUserFn != nil {
		return s.ResetPasswordForAuthenticatedUserFn(ctx, usr, input)
	}

	return nil
}

func (s MockService) CreatePasswordResetRequest(ctx context.Context, reqBody CreatePasswordResetRequestBody) error {
	if s.CreatePasswordResetRequestFn != nil {
		return s.CreatePasswordResetRequestFn(ctx, reqBody)
	}

	return nil
}

func (s MockService) ResetPasswordFromResetRequest(ctx context.Context, token string, input ResetPasswordFromResetRequestBody) error {
	if s.ResetPasswordFromResetRequestFn != nil {
		return s.ResetPasswordFromResetRequestFn(ctx, token, input)
	}

	return nil
}

func (s MockService) GetUserByID(ctx context.Context, id int64) (User, error) {
	if s.GetUserByIDFn != nil {
		return s.GetUserByIDFn(ctx, id)
	}

	return User{}, nil
}

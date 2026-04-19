package handlers // handlers are http endpoints.

import (
	"encoding/json"
	"errors"
	"net/http"

	"devinhadley/gobootstrapweb/internal/service"
	"devinhadley/gobootstrapweb/internal/utils"
)

type loginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type signUpBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func CreateLoginHandler(userService *service.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody loginBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		_, err = userService.LogIn(r.Context(), reqBody.Email, reqBody.Password)
		if err != nil {

			if errors.Is(err, service.ErrInvalidCredentials) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "authentication failed"})
				return
			}

			if errors.Is(err, service.ErrInvalidLogInInput) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
				return
			}

			if errors.Is(err, service.ErrInvalidEmail) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email is not valid"})
				return
			}

			utils.WriteAndReportInternalError(w)
			return

		}

		// Set session...
		w.WriteHeader(http.StatusOK)
	}
}

func CreateSignUpHandler(userService *service.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody signUpBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		_, err = userService.SignUp(r.Context(), service.SignUpInput{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if errors.Is(err, service.ErrInvalidSignUpInput) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
				return
			}

			if errors.Is(err, service.ErrInvalidEmail) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email is not valid"})
				return
			}

			if errors.Is(err, service.ErrEmailTaken) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email already in use"})
				return
			}

			utils.WriteJSONResponse(w, http.StatusInternalServerError, map[string]any{"error": "internal server error"})
			return
		}

		w.WriteHeader(http.StatusOK)
	}
}

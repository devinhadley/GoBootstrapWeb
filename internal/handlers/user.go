package handlers // handlers are http endpoints.

import (
	"encoding/json"
	"net/http"

	"devinhadley/gobootstrapweb/internal/service"
)

type loginBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type signUpBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: message})
}

func CreateLoginHandler(userService *service.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody loginBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		_, err = userService.LogIn(r.Context(), reqBody.Email, reqBody.Password)
		if err != nil {

			if err == service.ErrInvalidCredentials {
				writeJSONError(w, http.StatusBadRequest, "authentication failed")
				return
			}

			if err == service.ErrInvalidLogInInput {
				writeJSONError(w, http.StatusBadRequest, "email and password may not be blank")
				return
			}

		}

		// Set session...
	}
}

func CreateSignUpHandler(userService *service.UserService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody signUpBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		_, err = userService.SignUp(r.Context(), service.SignUpInput{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if err == service.ErrInvalidSignUpInput {
				writeJSONError(w, http.StatusBadRequest, "email and password may not be blank")
				return
			}

			if err == service.ErrInvalidEmail {
				writeJSONError(w, http.StatusBadRequest, "email is not valid")
				return
			}

			if err == service.ErrEmailTaken {
				writeJSONError(w, http.StatusBadRequest, "email already in use")
				return
			}
		}

		w.WriteHeader(http.StatusOK)
	}
}

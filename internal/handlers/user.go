package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"encoding/json"
	"errors"
	"net/http"

	"devinhadley/gobootstrapweb/internal/service"
	"devinhadley/gobootstrapweb/internal/utils"
)

func CreateSignUpHandler(userService *service.UserService, sessionService *service.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody service.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		user, err := userService.SignUp(r.Context(), service.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if errors.Is(err, service.ErrInvalidSignUpInput) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
				return
			}

			if errors.Is(err, service.ErrInvalidEmail) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
				return
			}

			if errors.Is(err, service.ErrEmailTaken) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
				return
			}

			utils.WriteAndReportInternalError(w)
			return
		}

		session, err := sessionService.CreateSession(r.Context(), user)
		if err != nil {
			utils.WriteAndReportInternalError(w)
			return
		}

		rawSession := session.DBSession()
		utils.AddSessionToCookie(w, rawSession.ID, session.GetAbsoluteExpiration())

		w.WriteHeader(http.StatusOK)
	}
}

func CreateLoginHandler(userService *service.UserService, sessionService *service.SessionService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody service.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		_, err = userService.LogIn(r.Context(), service.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
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
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
				return
			}

			utils.WriteAndReportInternalError(w)
			return

		}

		// Setup session...
		w.WriteHeader(http.StatusOK)
		// TODO: Setup session cookie.
	}
}

package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"encoding/json"
	"errors"
	"net/http"

	"devinhadley/gobootstrapweb/internal/service/session"
	"devinhadley/gobootstrapweb/internal/service/user"
	"devinhadley/gobootstrapweb/internal/utils"
)

func CreateSignUpHandler(userService *user.Service, sessionService *session.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		createdUser, err := userService.SignUp(r.Context(), user.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {
			if errors.Is(err, user.ErrInvalidSignUpInput) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
				return
			}

			if errors.Is(err, user.ErrEmailTaken) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
				return
			}

			if errors.Is(err, user.ErrInvalidEmail) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
				return
			}

			if errors.Is(err, user.ErrEmailTaken) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email already in use"})
				return
			}

			if errors.Is(err, user.ErrPasswordEmpty) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password can't be empty"})
				return
			}

			if errors.Is(err, user.ErrPasswordShort) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 12 or more characters"})
				return
			}

			if errors.Is(err, user.ErrPasswordLong) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password must be 256 charactrs or less"})
				return
			}

			if errors.Is(err, user.ErrPasswordCommon) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"password": "password too common"})
				return
			}

			utils.WriteAndReportInternalError(w)
			return
		}

		createdSession, err := sessionService.CreateSession(r.Context(), createdUser)
		if err != nil {
			utils.WriteAndReportInternalError(w)
			return
		}

		rawSession := createdSession.DBSession()
		utils.AddSessionToCookie(w, rawSession.ID, createdSession.GetAbsoluteExpiration())

		w.WriteHeader(http.StatusOK)
	}
}

func CreateLoginHandler(userService *user.Service, sessionService *session.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var reqBody user.AuthenticateBody
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&reqBody)
		if err != nil {
			utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}

		_, err = userService.LogIn(r.Context(), user.AuthenticateBody{
			Email:    reqBody.Email,
			Password: reqBody.Password,
		})
		if err != nil {

			if errors.Is(err, user.ErrInvalidCredentials) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "authentication failed"})
				return
			}

			if errors.Is(err, user.ErrInvalidLogInInput) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"error": "email and password may not be blank"})
				return
			}

			if errors.Is(err, user.ErrInvalidEmail) {
				utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]any{"email": "email is not valid"})
				return
			}

			// TODO: Handle remaining errors.

			utils.WriteAndReportInternalError(w)
			return

		}

		// Setup session...
		w.WriteHeader(http.StatusOK)
		// TODO: Setup session cookie.
	}
}

package middleware

import (
	"net/http"

	"devinhadley/gobootstrapweb/internal/web"
)

type Requirement func(w http.ResponseWriter, r *http.Request) bool

func Authenticated(w http.ResponseWriter, r *http.Request) bool {
	if !isUserInRequest(r) {
		web.WriteJSONResponse(w, http.StatusUnauthorized, map[string]any{})
		return false
	}

	return true
}

func Requires(next http.Handler, checks ...Requirement) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, check := range checks {
			if ok := check(w, r); !ok {
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

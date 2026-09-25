package handlers // handlers are responsible for http endpoints and http related actions.

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"devinhadley/gobootstrapweb/internal/service/ratelimit"
	"devinhadley/gobootstrapweb/internal/service/user"
)

type rateLimiter interface {
	Allow(key string, p ratelimit.Policy) (bool, error)
}

var (
	logInLimit                = ratelimit.Policy{Count: 10, Per: 15 * time.Minute}
	passwordResetRequestLimit = ratelimit.Policy{Count: 3, Per: 1 * time.Hour}
	emailResetRequestLimit    = ratelimit.Policy{Count: 3, Per: 1 * time.Hour}
	authedPasswordResetLimit  = ratelimit.Policy{Count: 5, Per: 1 * time.Hour}
)

// Conveinence wrappers for per handler rate limiting...

func limitByUser(w http.ResponseWriter, r *http.Request, limiter rateLimiter, usr user.User, p ratelimit.Policy) bool {
	key := fmt.Sprintf("%v:user:%v", r.Pattern, usr.DBUser().ID)
	return limited(w, limiter, key, p)
}

// Rate limit by pattern & some arbitrary field, i.e. email.
func limitByField(w http.ResponseWriter, r *http.Request, limiter rateLimiter, field, value string, p ratelimit.Policy) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	key := fmt.Sprintf("%v:field:%v:%v", r.Pattern, field, normalized)
	return limited(w, limiter, key, p)
}

func limited(w http.ResponseWriter, limiter rateLimiter, key string, p ratelimit.Policy) bool {
	allowed, err := limiter.Allow(key, p)
	if err != nil {
		log.Printf("checking rate limit for key %q: %v", key, err)
	}

	if !allowed {
		w.WriteHeader(http.StatusTooManyRequests)
		return true
	}

	return false
}

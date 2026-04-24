package utils

import (
	"encoding/base64"
	"net/http"
	"time"

	"devinhadley/gobootstrapweb/internal/db"
)

const (
	sessionIDCookieName         = "id"
	absoluteSessionExpiryMonths = 3
)

func AddSessionToCookie(w http.ResponseWriter, session *db.Session) {
	base64SessionID := base64.StdEncoding.EncodeToString(session.ID)
	absoluteExpiration := time.Now().AddDate(0, absoluteSessionExpiryMonths, 0)

	cookie := http.Cookie{
		Name:     sessionIDCookieName,
		Value:    base64SessionID,
		Expires:  absoluteExpiration,
		HttpOnly: true,
		Path:     "/",
		Secure:   isSessionCookieSecure(),
	}

	http.SetCookie(w, &cookie)
}

func ClearSessionCookie(w http.ResponseWriter) {
	cookie := http.Cookie{
		Name:     sessionIDCookieName,
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Path:     "/",
		Secure:   isSessionCookieSecure(),
	}

	http.SetCookie(w, &cookie)
}

func isSessionCookieSecure() bool {
	ok, isSecure := GetEnv("USE_HTTPS")
	if !ok {
		return true
	}

	return isSecure == "true"
}

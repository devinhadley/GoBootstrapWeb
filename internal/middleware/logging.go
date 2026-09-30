package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

type logAttrs struct {
	attrs []slog.Attr
}

var logAttrsKey = &contextKey{"logAttrs"}

func AddLogAttrs(ctx context.Context, attrs ...slog.Attr) {
	bag, ok := ctx.Value(logAttrsKey).(*logAttrs)
	if !ok {
		return
	}
	bag.attrs = append(bag.attrs, attrs...)
}

type statusRecorder struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

func (s *statusRecorder) WriteHeader(statusCode int) {
	if s.status == 0 {
		s.status = statusCode
	}
	s.ResponseWriter.WriteHeader(statusCode)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytesWritten += n
	return n, err
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}

func CreateRequestLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}
		bag := &logAttrs{} // populated by further middleware & handlers as they see fit...

		next.ServeHTTP(recorder, r.WithContext(context.WithValue(r.Context(), logAttrsKey, bag)))

		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int("bytes", recorder.bytesWritten),
			slog.Float64("duration_ms", float64(time.Since(start).Microseconds())/1000),
			slog.String("remote_addr", r.RemoteAddr),
		}
		attrs = append(attrs, bag.attrs...)

		slog.LogAttrs(r.Context(), slog.LevelInfo, "request", attrs...)
	})
}

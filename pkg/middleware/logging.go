package middleware

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/tantosec/badAuthenticator/internal/types"
	"github.com/tantosec/badAuthenticator/pkg/contextkeys"
	"github.com/tantosec/badAuthenticator/pkg/logging"
)

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func newResponseWriter(w http.ResponseWriter) *responseWriter {
	// net/http uses 200 when a handler writes without calling WriteHeader.
	return &responseWriter{w, http.StatusOK}
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID := fmt.Sprintf("%x", rand.Int63())
		logger := logging.GetLogger()

		logDetails := &types.LogDetails{}
		ctx := r.Context()
		ctx = context.WithValue(ctx, contextkeys.LogDetailsKey{}, logDetails)
		r = r.WithContext(ctx)

		wrappedWriter := newResponseWriter(w)
		next.ServeHTTP(wrappedWriter, r)

		fields := []any{
			"id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status", wrappedWriter.statusCode,
			"duration", time.Since(start),
		}

		if logDetails.CredentialID != "" {
			fields = append(fields, "credential_id", logDetails.CredentialID)
		}

		logger.Info("HTTP Request", fields...)
	})
}

// Diagnostic HTTP capture — enabled ONLY if CALGW_HTTPDEBUG points to a file.
// Dumps requests AND responses (headers + bodies, capped) to analyze
// client-side failures (dataaccessd "Error 2" while everything is 2xx on the
// server side). Bodies contain personal data: the file is created 0600, to be
// enabled briefly then removed.
package server

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

const debugBodyCap = 64 << 10

// debugCapture wraps the handler and logs each complete exchange.
func debugCapture(path string, next http.Handler) http.Handler {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		// Diagnostic impossible → serve without capture rather than fail.
		return next
	}
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ := io.ReadAll(io.LimitReader(r.Body, debugBodyCap))
		rest, _ := io.ReadAll(r.Body) // beyond the cap: forwarded, not logged
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(reqBody), bytes.NewReader(rest)))

		rec := &debugRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)

		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(f, "\n===== %s %s %s ua=%q depth=%q if-match=%q ct=%q\n",
			time.Now().UTC().Format(time.RFC3339), r.Method, r.URL.RequestURI(),
			r.Header.Get("User-Agent"), r.Header.Get("Depth"), r.Header.Get("If-Match"), r.Header.Get("Content-Type"))
		if len(reqBody) > 0 {
			fmt.Fprintf(f, "--- request body (%d bytes%s):\n%s\n", len(reqBody), truncNote(len(rest)), reqBody)
		}
		fmt.Fprintf(f, "--- response %d, headers: %v\n", rec.status, rec.Header())
		if rec.body.Len() > 0 {
			fmt.Fprintf(f, "--- response body (%d bytes):\n%s\n", rec.body.Len(), rec.body.Bytes())
		}
	})
}

func truncNote(rest int) string {
	if rest > 0 {
		return fmt.Sprintf(", +%d truncated", rest)
	}
	return ""
}

// debugRecorder duplicates the response into a capped buffer.
type debugRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (d *debugRecorder) WriteHeader(code int) {
	d.status = code
	d.ResponseWriter.WriteHeader(code)
}

func (d *debugRecorder) Write(p []byte) (int, error) {
	if d.body.Len() < debugBodyCap {
		d.body.Write(p[:min(len(p), debugBodyCap-d.body.Len())])
	}
	return d.ResponseWriter.Write(p)
}

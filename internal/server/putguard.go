// PUT gatekeeping: the Proton server validates NOTHING (properties are just
// text inside encrypted/signed cards), so refusals must come from US — as an
// honest 403 + DAV:error body, never a 2xx no-op (a proven cause of
// dataaccessd's "Error 2" loop, 2026-07-16).
//
// interceptPutPrecondition inspects the iCalendar body of PUTs and applies the
// "refuse" policies from docs/FEATURE-MATRIX.md §3 that do NOT depend on
// calendar state:
//
//   - VTODO / VJOURNAL / VFREEBUSY: no model on the Proton side → 403.
//
// Refusing outgoing invitations (ATTENDEE + ORGANIZER = account address) was
// MOVED into the CalDAV backend (M5a): the middleware cannot tell whether the
// PUT is a create or an update — only the backend, which resolves the UID on
// the Proton side, can route create+invitation → write + iMIP email, update of
// an event with invitees → 403 "ATTENDEE-UPDATE" (M5b), and an INCOMING
// booking (third-party ORGANIZER, the BookingService case) → strip (as M3).
//
// The analysis is deliberately LIGHT and TOLERANT (scan of unfolded iCal
// lines, not a full parse): in case of doubt — unreadable body, too large — we
// LET IT THROUGH to the handler. The middleware must never block because of a
// weakness in its own analyzer. Multi-VEVENT and RECURRENCE-ID are already
// refused deeper (M3).
package server

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// putguardMaxInspect bounds the body we agree to analyze: a real .ics is a few
// KiB, 8 MiB is already very generous. Beyond that we give up the analysis
// (doubt → pass) but the body is forwarded IN FULL.
const putguardMaxInspect = 8 << 20

// cgNamespace is the gateway's in-house namespace for DAV:error bodies.
const cgNamespace = "https://cal-gateway.example/ns"

// interceptPutPrecondition applies the refusal policies on iCalendar PUTs; any
// other verb or Content-Type falls through to the next handler.
func interceptPutPrecondition(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || !isCalendarContentType(r.Header.Get("Content-Type")) {
			next.ServeHTTP(w, r)
			return
		}

		// We consume the body to inspect it, then hand it back INTACT to the
		// next handler: the read bytes are re-prefixed to the unread rest
		// (io.MultiReader), whatever the analysis verdict.
		buf, err := io.ReadAll(io.LimitReader(r.Body, putguardMaxInspect+1))
		rest := r.Body
		r.Body = readCloser{io.MultiReader(bytes.NewReader(buf), rest), rest}

		if err != nil || len(buf) > putguardMaxInspect {
			// Partial read or abnormally large body: doubt → pass.
			next.ServeHTTP(w, r)
			return
		}

		if name, refused := evaluatePutPolicies(buf); refused {
			writePutRefusal(w, name)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// readCloser reassembles an io.ReadCloser from a prefixed Reader and the
// original body's Closer (Close must always reach the latter).
type readCloser struct {
	io.Reader
	io.Closer
}

// isCalendarContentType recognizes iCalendar bodies ("text/calendar", charset
// parameters tolerated). Missing or exotic header → no inspection.
func isCalendarContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		// Malformed header: lax recognition rather than a policy hole.
		return strings.Contains(strings.ToLower(ct), "text/calendar")
	}
	return mediaType == "text/calendar"
}

// evaluatePutPolicies scans the unfolded iCal and returns the name of the
// refused component (for the DAV:error body) if a policy applies.
func evaluatePutPolicies(body []byte) (name string, refused bool) {
	for _, line := range unfoldICalLines(body) {
		switch strings.ToUpper(line) {
		case "BEGIN:VTODO":
			return "VTODO", true
		case "BEGIN:VJOURNAL":
			return "VJOURNAL", true
		case "BEGIN:VFREEBUSY":
			return "VFREEBUSY", true
		}
	}
	return "", false
}

// unfoldICalLines splits the body into RFC 5545 logical lines: a physical line
// starting with a space or tab continues the previous one. Tolerant of \r\n
// and \n line endings.
func unfoldICalLines(body []byte) []string {
	physical := strings.Split(string(body), "\n")
	lines := make([]string, 0, len(physical))
	for _, p := range physical {
		p = strings.TrimSuffix(p, "\r")
		if len(p) > 0 && (p[0] == ' ' || p[0] == '\t') && len(lines) > 0 {
			lines[len(lines)-1] += p[1:]
			continue
		}
		lines = append(lines, p)
	}
	return lines
}

// writePutRefusal emits the 403 + DAV:error body of the refusal:
// <D:error xmlns:D="DAV:"><CG:unsupported-property xmlns:CG="…" name="…"/></D:error>
func writePutRefusal(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)

	var escaped bytes.Buffer
	xml.EscapeText(&escaped, []byte(name)) // fixed names today, belt-and-braces anyway
	fmt.Fprintf(w,
		`%s<D:error xmlns:D="DAV:"><CG:unsupported-property xmlns:CG=%q name="%s"/></D:error>`,
		xml.Header, cgNamespace, escaped.String())
}

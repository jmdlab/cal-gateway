package server

// Tests of the CalDAV Scheduling announcement (RFC 6638): principal
// properties, the OPTIONS calendar-auto-schedule token, the inbox/outbox
// collections and the outbox free-busy POST. The go-webdav backend is never
// reached for inbox/outbox (full interception) — a nil backend is enough, as
// in server_test.go.

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emersion/go-ical"
	webcaldav "github.com/emersion/go-webdav/caldav"
)

// stubBackend: the minimum webcaldav.Backend so go-webdav's OPTIONS respond
// (they only touch the backend for objects) and ListCalendars serves
// schedule-default-calendar-URL.
type stubBackend struct{}

var errStub = errors.New("stub")

func (stubBackend) CalendarHomeSetPath(context.Context) (string, error) {
	return "/alice/calendars/", nil
}
func (stubBackend) CurrentUserPrincipal(context.Context) (string, error) { return "/alice/", nil }
func (stubBackend) CreateCalendar(context.Context, *webcaldav.Calendar) error {
	return errStub
}
func (stubBackend) ListCalendars(context.Context) ([]webcaldav.Calendar, error) {
	return []webcaldav.Calendar{{Path: "/alice/calendars/cal1/", Name: "Personal"}}, nil
}
func (stubBackend) GetCalendar(context.Context, string) (*webcaldav.Calendar, error) {
	return nil, errStub
}
func (stubBackend) GetCalendarObject(context.Context, string, *webcaldav.CalendarCompRequest) (*webcaldav.CalendarObject, error) {
	return nil, errStub
}
func (stubBackend) ListCalendarObjects(context.Context, string, *webcaldav.CalendarCompRequest) ([]webcaldav.CalendarObject, error) {
	return nil, errStub
}
func (stubBackend) QueryCalendarObjects(context.Context, string, *webcaldav.CalendarQuery) ([]webcaldav.CalendarObject, error) {
	return nil, errStub
}
func (stubBackend) PutCalendarObject(context.Context, string, *ical.Calendar, *webcaldav.PutCalendarObjectOptions) (*webcaldav.CalendarObject, error) {
	return nil, errStub
}
func (stubBackend) DeleteCalendarObject(context.Context, string) error { return errStub }

// schedHandler: the full chain without the readiness gate, with the account
// owner's addresses as in prod.
func schedHandler() http.Handler {
	return newHandler(Config{
		ListenAddr:            "127.0.0.1:0",
		AuthUser:              "alice",
		AuthPassword:          "pw",
		CalendarUserAddresses: []string{"alice@example.com", "alice@proton.me"},
	}, stubBackend{})
}

// schedReq runs an authenticated request against the full chain.
func schedReq(t *testing.T, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	req.SetBasicAuth("alice", "pw")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	schedHandler().ServeHTTP(rec, req)
	return rec
}

// TestPrincipalAnnouncesScheduling: the principal's PROPFIND contains
// schedule-inbox-URL, schedule-outbox-URL and calendar-user-type, on top of
// the existing set (calendar-user-address-set, home set…) — no regression.
func TestPrincipalAnnouncesScheduling(t *testing.T) {
	rec := schedReq(t, "PROPFIND", "/alice/", "", map[string]string{"Depth": "0"})
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("code = %d, want 207", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"schedule-inbox-URL", "/alice/inbox/",
		"schedule-outbox-URL", "/alice/outbox/",
		"calendar-user-type", "INDIVIDUAL",
		"http://calendarserver.org/ns/",
		// The existing set must not regress.
		"calendar-user-address-set", "mailto:alice@example.com", "mailto:alice@proton.me",
		"calendar-home-set", "/alice/calendars/",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("principal PROPFIND: %q missing\n%s", want, body)
		}
	}
	// The multistatus must remain well-formed XML.
	assertWellFormedXML(t, rec.Body.Bytes())
}

// TestOptionsCalendarAutoSchedule: the OPTIONS DAV header (served by go-webdav
// then completed by appendAutoScheduleDAV) contains the calendar-auto-schedule
// token WITHOUT losing the existing one — on the principal, the home set and a
// calendar collection.
func TestOptionsCalendarAutoSchedule(t *testing.T) {
	for _, path := range []string{"/alice/", "/alice/calendars/", "/alice/calendars/cal1/"} {
		rec := schedReq(t, http.MethodOptions, path, "", nil)
		dav := rec.Header().Get("DAV")
		if !strings.Contains(dav, "calendar-auto-schedule") {
			t.Errorf("OPTIONS %s: DAV = %q, calendar-auto-schedule token missing", path, dav)
		}
		if !strings.Contains(dav, "calendar-access") || !strings.Contains(dav, "1") {
			t.Errorf("OPTIONS %s: DAV = %q, go-webdav capabilities lost", path, dav)
		}
		if rec.Header().Get("Allow") == "" {
			t.Errorf("OPTIONS %s: Allow header lost", path)
		}
	}
}

// TestOptionsInboxOutbox: OPTIONS of the scheduling collections (full
// interception, never go-webdav) — complete DAV + coherent Allow.
func TestOptionsInboxOutbox(t *testing.T) {
	for path, wantAllow := range map[string]string{
		"/alice/inbox/":  "PROPFIND",
		"/alice/outbox/": "POST",
	} {
		rec := schedReq(t, http.MethodOptions, path, "", nil)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("OPTIONS %s: code = %d, want 204", path, rec.Code)
		}
		if dav := rec.Header().Get("DAV"); !strings.Contains(dav, "calendar-auto-schedule") {
			t.Errorf("OPTIONS %s: DAV = %q", path, dav)
		}
		if allow := rec.Header().Get("Allow"); !strings.Contains(allow, wantAllow) {
			t.Errorf("OPTIONS %s: Allow = %q, want %q inside", path, allow, wantAllow)
		}
	}
}

// TestInboxPropfind: resourcetype = collection + schedule-inbox, never 404
// (macOS probes this path at account setup).
func TestInboxPropfind(t *testing.T) {
	rec := schedReq(t, "PROPFIND", "/alice/inbox/", "", map[string]string{"Depth": "0"})
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("code = %d, want 207", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"schedule-inbox", "collection", "/alice/inbox/", "getctag",
		// schedule-default-calendar-URL must point at a REAL backend calendar
		// (the first from ListCalendars).
		"schedule-default-calendar-URL", "/alice/calendars/cal1/",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("inbox PROPFIND: %q missing\n%s", want, body)
		}
	}
	assertWellFormedXML(t, rec.Body.Bytes())
}

// assertWellFormedXML: the body must be well-formed XML end to end.
func assertWellFormedXML(t *testing.T, body []byte) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		if _, err := dec.Token(); err != nil {
			if err == io.EOF {
				return
			}
			t.Fatalf("malformed XML: %v\n%s", err, body)
		}
	}
}

// TestOutboxPropfind: resourcetype = collection + schedule-outbox.
func TestOutboxPropfind(t *testing.T) {
	rec := schedReq(t, "PROPFIND", "/alice/outbox/", "", map[string]string{"Depth": "0"})
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("code = %d, want 207", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "schedule-outbox") {
		t.Errorf("outbox PROPFIND: schedule-outbox missing\n%s", body)
	}
}

// TestInboxEmpty: GET → 200 (never 404), REPORT → empty 207 multistatus.
func TestInboxEmpty(t *testing.T) {
	if rec := schedReq(t, http.MethodGet, "/alice/inbox/", "", nil); rec.Code != http.StatusOK {
		t.Errorf("GET inbox: code = %d, want 200", rec.Code)
	}
	report := `<?xml version="1.0"?><C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"/>`
	rec := schedReq(t, "REPORT", "/alice/inbox/", report, nil)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("REPORT inbox: code = %d, want 207", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "<response") {
		t.Errorf("REPORT inbox: the collection is meant to be empty\n%s", body)
	}
}

// scheduleResponse maps the <C:schedule-response> XML for verification.
type scheduleResponse struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:caldav schedule-response"`
	Responses []struct {
		Recipient struct {
			Href string `xml:"DAV: href"`
		} `xml:"recipient"`
		RequestStatus string `xml:"request-status"`
		CalendarData  string `xml:"calendar-data"`
	} `xml:"response"`
}

// TestOutboxPostFreeBusy: macOS's VFREEBUSY iTIP POST receives a valid
// schedule-response — one <response> per attendee, request-status 2.0, and a
// VFREEBUSY REPLY with no busy range.
func TestOutboxPostFreeBusy(t *testing.T) {
	itip := strings.Join([]string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:-//Apple Inc.//Mac OS X//EN",
		"METHOD:REQUEST",
		"BEGIN:VFREEBUSY",
		"UID:freebusy-probe-1",
		"DTSTAMP:20260716T120000Z",
		"DTSTART:20260716T000000Z",
		"DTEND:20260717T000000Z",
		"ORGANIZER:mailto:alice@example.com",
		"ATTENDEE:mailto:bob@example.com",
		"ATTENDEE:mailto:carol@example.com",
		"END:VFREEBUSY",
		"END:VCALENDAR",
		"",
	}, "\r\n")

	rec := schedReq(t, http.MethodPost, "/alice/outbox/", itip,
		map[string]string{"Content-Type": "text/calendar; charset=utf-8"})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	var sr scheduleResponse
	if err := xml.Unmarshal(rec.Body.Bytes(), &sr); err != nil {
		t.Fatalf("schedule-response does not parse: %v\n%s", err, rec.Body.String())
	}
	if len(sr.Responses) != 2 {
		t.Fatalf("responses = %d, want 2 (one per attendee)", len(sr.Responses))
	}
	wantRecipients := map[string]bool{"mailto:bob@example.com": false, "mailto:carol@example.com": false}
	for _, resp := range sr.Responses {
		if !strings.HasPrefix(resp.RequestStatus, "2.0") {
			t.Errorf("request-status = %q, want prefix 2.0", resp.RequestStatus)
		}
		if _, known := wantRecipients[resp.Recipient.Href]; !known {
			t.Errorf("unexpected recipient: %q", resp.Recipient.Href)
		}
		wantRecipients[resp.Recipient.Href] = true

		cd := resp.CalendarData
		for _, want := range []string{"METHOD:REPLY", "BEGIN:VFREEBUSY", "UID:freebusy-probe-1", "ORGANIZER:mailto:alice@example.com"} {
			if !strings.Contains(cd, want) {
				t.Errorf("calendar-data: %q missing\n%s", want, cd)
			}
		}
		if strings.Contains(cd, "\nFREEBUSY") {
			t.Errorf("calendar-data: no FREEBUSY range expected (all free)\n%s", cd)
		}
		if !strings.Contains(cd, "ATTENDEE:"+resp.Recipient.Href) {
			t.Errorf("calendar-data: attendee %q must appear in its own VFREEBUSY\n%s", resp.Recipient.Href, cd)
		}
	}
	for rcpt, seen := range wantRecipients {
		if !seen {
			t.Errorf("recipient %q absent from the schedule-response", rcpt)
		}
	}
}

// TestOutboxPostInvalid: missing or non-iTIP body → clean 400 (never a 5xx,
// which would make adding the invitee fail on macOS).
func TestOutboxPostInvalid(t *testing.T) {
	if rec := schedReq(t, http.MethodPost, "/alice/outbox/", "", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("POST without body: code = %d, want 400", rec.Code)
	}
	if rec := schedReq(t, http.MethodPost, "/alice/outbox/", "not iCalendar at all", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("POST invalid body: code = %d, want 400", rec.Code)
	}
	// Valid VCALENDAR but without VFREEBUSY (a VEVENT posted to the outbox =
	// explicit scheduling, which we do not announce) → 400 too.
	vevent := strings.Join([]string{
		"BEGIN:VCALENDAR",
		"VERSION:2.0",
		"PRODID:-//test//EN",
		"METHOD:REQUEST",
		"BEGIN:VEVENT",
		"UID:x1",
		"DTSTAMP:20260716T120000Z",
		"DTSTART:20260716T130000Z",
		"DTEND:20260716T140000Z",
		"SUMMARY:test",
		"END:VEVENT",
		"END:VCALENDAR",
		"",
	}, "\r\n")
	if rec := schedReq(t, http.MethodPost, "/alice/outbox/", vevent, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("POST VEVENT: code = %d, want 400", rec.Code)
	}
}

// TestSchedulingAuthRequired: inbox/outbox stay behind Basic auth — the
// interception must not create an authentication hole.
func TestSchedulingAuthRequired(t *testing.T) {
	for _, path := range []string{"/alice/inbox/", "/alice/outbox/"} {
		req := httptest.NewRequest("PROPFIND", path, nil)
		rec := httptest.NewRecorder()
		schedHandler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without auth: code = %d, want 401", path, rec.Code)
		}
	}
}

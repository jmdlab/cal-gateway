package server

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nextRecorder is the fake downstream handler: it records whether it was
// called and the EXACT body it received (byte-for-byte verification).
type nextRecorder struct {
	called bool
	body   []byte
}

func (n *nextRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.called = true
	b, err := io.ReadAll(r.Body)
	if err != nil {
		panic("nextRecorder: reading the forwarded body: " + err.Error())
	}
	n.body = b
	w.WriteHeader(http.StatusCreated)
}

// doPut runs a PUT through the middleware and returns the response + the
// downstream handler for inspection.
func doPut(t *testing.T, contentType, body string) (*httptest.ResponseRecorder, *nextRecorder) {
	t.Helper()
	next := &nextRecorder{}
	h := interceptPutPrecondition(next)

	req := httptest.NewRequest(http.MethodPut, "/alice/calendars/cal1/evt.ics", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec, next
}

const icsVEventNormal = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:evt-1\r\nDTSTART:20260801T100000Z\r\nDTEND:20260801T110000Z\r\nSUMMARY:Dentist\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

const icsVTodo = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTODO\r\nUID:todo-1\r\nSUMMARY:Buy bread\r\nEND:VTODO\r\nEND:VCALENDAR\r\n"

// BookingService case: a RECEIVED booking — third-party ORGANIZER + ATTENDEE (us).
const icsBooking = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:booking-1\r\nDTSTART:20260801T100000Z\r\nORGANIZER;CN=BookingService:mailto:noreply@bookingservice.example\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@proton.me\r\nSUMMARY:Haircut\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

// OUTGOING invitation: ORGANIZER = account address + third-party ATTENDEE.
// The ORGANIZER's CN is FOLDED (RFC 5545) to exercise unfolding.
const icsOutgoing = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:invite-1\r\nDTSTART:20260801T100000Z\r\nORGANIZER;CN=Alice\r\n Doe:mailto:ALICE@proton.me\r\nATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:friend@example.com\r\nSUMMARY:Lunch\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

// assertRefusal checks the expected 403 + DAV:error body, and that the
// downstream handler was NOT called.
func assertRefusal(t *testing.T, rec *httptest.ResponseRecorder, next *nextRecorder, wantName string) {
	t.Helper()
	if next.called {
		t.Fatalf("the downstream handler was called although the PUT should have been refused")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`<D:error xmlns:D="DAV:">`,
		`<CG:unsupported-property xmlns:CG="https://cal-gateway.example/ns" name="` + wantName + `"/>`,
		`</D:error>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("DAV:error body missing %q:\n%s", want, body)
		}
	}
}

// assertPassthrough checks the PUT reached the downstream handler with the
// body intact byte-for-byte.
func assertPassthrough(t *testing.T, rec *httptest.ResponseRecorder, next *nextRecorder, wantBody string) {
	t.Helper()
	if !next.called {
		t.Fatalf("the downstream handler was not called (middleware status = %d, body %q)", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(next.body, []byte(wantBody)) {
		t.Errorf("forwarded body altered:\ngot  %q\nwant %q", next.body, wantBody)
	}
	if rec.Code != http.StatusCreated {
		t.Errorf("status = %d, want 201 (the downstream handler's)", rec.Code)
	}
}

func TestPutGuardVEventNormalPasses(t *testing.T) {
	rec, next := doPut(t, "text/calendar; charset=utf-8", icsVEventNormal)
	assertPassthrough(t, rec, next, icsVEventNormal)
}

func TestPutGuardVTodoRefused(t *testing.T) {
	rec, next := doPut(t, "text/calendar", icsVTodo)
	assertRefusal(t, rec, next, "VTODO")
}

func TestPutGuardVJournalAndVFreebusyRefused(t *testing.T) {
	for _, comp := range []string{"VJOURNAL", "VFREEBUSY"} {
		body := "BEGIN:VCALENDAR\r\nBEGIN:" + comp + "\r\nUID:x\r\nEND:" + comp + "\r\nEND:VCALENDAR\r\n"
		rec, next := doPut(t, "text/calendar", body)
		assertRefusal(t, rec, next, comp)
	}
}

func TestPutGuardBookingThirdPartyOrganizerPasses(t *testing.T) {
	rec, next := doPut(t, "text/calendar", icsBooking)
	assertPassthrough(t, rec, next, icsBooking)
}

func TestPutGuardOutgoingInvitationPassesToBackend(t *testing.T) {
	// M5a: the middleware no longer refuses outgoing invitations — the decision
	// (create+invitation → write+email; update of an event with invitees → 403
	// ATTENDEE-UPDATE; incoming → strip) lives in the backend, which alone
	// knows whether the UID exists and whether the ORGANIZER is the account.
	rec, next := doPut(t, "text/calendar", icsOutgoing)
	assertPassthrough(t, rec, next, icsOutgoing)
}

func TestPutGuardUnreadableBodyPasses(t *testing.T) {
	// Non-iCal body (arbitrary binary): never blocked by a weakness in our
	// analyzer — passes to the handler, intact byte-for-byte.
	garbage := "\x00\xff\x1bnot iCal at all\r\n\xc3\x28 ORGANIZER broken\xe9"
	rec, next := doPut(t, "text/calendar", garbage)
	assertPassthrough(t, rec, next, garbage)
}

func TestPutGuardNonCalendarContentTypeIgnored(t *testing.T) {
	// A non-calendar PUT (even one containing VTODO text) is not inspected.
	rec, next := doPut(t, "text/plain", icsVTodo)
	assertPassthrough(t, rec, next, icsVTodo)
}

func TestPutGuardOtherVerbsIgnored(t *testing.T) {
	next := &nextRecorder{}
	h := interceptPutPrecondition(next)
	req := httptest.NewRequest(http.MethodGet, "/alice/calendars/cal1/evt.ics", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !next.called {
		t.Fatalf("GET should have passed to the downstream handler")
	}
}

func TestPutGuardGiantBodyPassesIntact(t *testing.T) {
	// Body > putguardMaxInspect: we give up the analysis (doubt → pass) but the
	// full body — including the uninspected part — must reach the downstream
	// handler intact.
	big := icsVTodo + strings.Repeat("X-PADDING:abcdefghijklmnopqrstuvwxyz\r\n", (putguardMaxInspect/38)+2)
	rec, next := doPut(t, "text/calendar", big)
	assertPassthrough(t, rec, next, big)
}

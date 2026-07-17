package caldav

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/invite"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

// liveTestCalendarPrefix is the required ID prefix of the dedicated (empty)
// test calendar used by the live opt-in tests — they must never touch a real
// calendar. Overridable via CALGW_TEST_CALID_PREFIX; defaults to "TEST".
var liveTestCalendarPrefix = func() string {
	if p := os.Getenv("CALGW_TEST_CALID_PREFIX"); p != "" {
		return p
	}
	return "TEST"
}()

// dryRunSender writes each invitation as a .eml on disk instead of sending it —
// the default path for the live test (NO real email without
// CALGW_LIVE_SEND=1, a coordinator decision).
type dryRunSender struct {
	t     *testing.T
	dir   string
	count int
	paths []string
	msgs  []invite.Message
}

func (d *dryRunSender) Send(ctx context.Context, m invite.Message) error {
	d.count++
	d.msgs = append(d.msgs, m)
	p := filepath.Join(d.dir, fmt.Sprintf("invite-%02d-%s.eml", d.count, m.To))
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := invite.WriteEML(m, f); err != nil {
		return err
	}
	d.paths = append(d.paths, p)
	d.t.Logf("dry-run: .eml generated (not sent) → %s", p)
	return nil
}

// TestLiveInviteFullPath is the OPT-IN test (CALGW_LIVE=1) of the M5a FULL PATH:
// CalDAV PUT (real backend + real Proton account) of a creation with ONE
// invitee bob@example.com → the event is written with its attendees card →
// the iMIP email is generated DRY-RUN (.eml on disk, NOT sent) unless
// CALGW_LIVE_SEND=1 is ALSO set (real send via the bridge, credentials
// CALGW_SMTP_USERNAME/CALGW_SMTP_PASSWORD) → re-read by the backend:
// ATTENDEE/ORGANIZER served (Apple sees its write confirmed) → DELETE,
// clean disappearance, zero debris (cleanup in defer even on failure).
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//	  go test ./internal/caldav/ -run TestLiveInviteFullPath -v
func TestLiveInviteFullPath(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live full-path invite round-trip")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	if dataDir == "" {
		t.Fatal("need CALGW_DATADIR")
	}

	ctx := context.Background()
	acct, err := proton.RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	// Guardrail: test calendar selected by its ID prefix.
	cals, err := acct.ListCalendars(ctx)
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	calID := ""
	for _, c := range cals {
		if strings.HasPrefix(c.ID, liveTestCalendarPrefix) {
			calID = c.ID
			break
		}
	}
	if calID == "" {
		t.Fatalf("no calendar with ID prefix %q (test calendar missing?)", liveTestCalendarPrefix)
	}

	addrs := acct.Addresses()
	if len(addrs) == 0 {
		t.Fatal("no account address")
	}
	organizer := addrs[0]
	const invitee = "bob@example.com"

	// Sender: dry-run (.eml) by default; REAL send only if
	// CALGW_LIVE_SEND=1 (a coordinator decision, never the test's).
	var sender InviteSender
	dry := &dryRunSender{t: t, dir: t.TempDir()}
	if os.Getenv("CALGW_LIVE_SEND") == "1" {
		user, pass := os.Getenv("CALGW_SMTP_USERNAME"), os.Getenv("CALGW_SMTP_PASSWORD")
		if user == "" || pass == "" {
			t.Fatal("CALGW_LIVE_SEND=1 needs CALGW_SMTP_USERNAME and CALGW_SMTP_PASSWORD (bridge credentials)")
		}
		sender = invite.NewSender(invite.Config{
			Enabled: true, Host: "127.0.0.1", Port: 1025,
			Username: user, Password: pass, FromName: "Alice",
		})
		t.Log("CALGW_LIVE_SEND=1: REAL send via the SMTP bridge")
	} else {
		sender = dry
	}

	backend := NewBackend(acct, "alice")
	backend.ConfigureInvites(append([]string{organizer}, acct.Addresses()...), "Alice", sender)

	// 1) PUT of a creation with an invitee (the backend's full path).
	uid := "calgw-m5a-live-" + time.Now().UTC().Format("20060102T150405Z")
	start := time.Now().UTC().Add(96 * time.Hour).Truncate(time.Hour)
	cal := buildICS(t, uid, "TEST cal-gateway M5a — ignore", start, start.Add(time.Hour), false)
	org := ical.NewProp(ical.PropOrganizer)
	org.Params.Set(ical.ParamCommonName, "Alice")
	org.Value = "mailto:" + organizer
	cal.Children[0].Props.Set(org)
	att := ical.NewProp(ical.PropAttendee)
	att.Params.Set(ical.ParamCommonName, "Bob")
	att.Params.Set(ical.ParamRSVP, "TRUE")
	att.Value = "mailto:" + invitee
	cal.Children[0].Props.Add(att)

	putPath := "/alice/calendars/" + calID + "/" + uid + ".ics"
	obj, err := backend.PutCalendarObject(ctx, putPath, cal, nil)
	if err != nil {
		t.Fatalf("PutCalendarObject (create+invite): %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = backend.DeleteCalendarObject(ctx, obj.Path) // no debris
		}
	}()
	t.Logf("PUT 201 → %s (etag %s)", obj.Path, obj.ETag)

	// 2) The email: generated dry-run (or actually sent if CALGW_LIVE_SEND=1).
	if os.Getenv("CALGW_LIVE_SEND") != "1" {
		if dry.count != 1 {
			t.Fatalf("invitations generated = %d, want 1", dry.count)
		}
		raw, rerr := os.ReadFile(dry.paths[0])
		if rerr != nil {
			t.Fatalf("reading .eml: %v", rerr)
		}
		for _, want := range []string{"multipart/mixed", "multipart/alternative",
			"text/calendar", "method=REQUEST", `filename="invite.ics"`, "UID:" + uid} {
			if !strings.Contains(string(raw), want) {
				t.Errorf(".eml missing %q", want)
			}
		}
	}

	// 3) Re-read by the backend: ATTENDEE + ORGANIZER served.
	got, err := backend.GetCalendarObject(ctx, obj.Path, nil)
	if err != nil {
		t.Fatalf("GetCalendarObject: %v", err)
	}
	var served strings.Builder
	if err := ical.NewEncoder(&served).Encode(got.Data); err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(served.String(), "\r\n ", "")
	for _, want := range []string{
		"ORGANIZER:mailto:" + organizer,
		"mailto:" + invitee,
		"PARTSTAT=NEEDS-ACTION",
		"ROLE=REQ-PARTICIPANT",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("re-read missing %q:\n%s", want, served.String())
		}
	}
	if strings.Contains(s, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN served to the client:\n%s", served.String())
	}

	// 4) DELETE + clean disappearance (zero debris).
	if err := backend.DeleteCalendarObject(ctx, obj.Path); err != nil {
		t.Fatalf("DeleteCalendarObject: %v", err)
	}
	deleted = true
	if _, err := backend.GetCalendarObject(ctx, obj.Path, nil); err == nil {
		t.Fatal("resource still served after delete")
	} else if !isLiveNotFound(err) {
		t.Fatalf("post-delete GET = %v, want 404/not-found", err)
	}
}

// isLiveNotFound recognizes a clean disappearance (CalDAV 404 or wrapped
// ErrEventNotFound).
func isLiveNotFound(err error) bool {
	return errors.Is(err, proton.ErrEventNotFound) || isHTTPStatus(err, http.StatusNotFound)
}

// TestLiveInviteLifecycle is the OPT-IN test (CALGW_LIVE=1) of the M5b
// lifecycle on the real account (the dedicated empty test calendar, never the
// live calendar): create invitee → SIGNIFICANT update (SEQUENCE+1, REQUEST
// "updated invitation", list/token/organizer INTACT) → ADD an invitee (REQUEST
// to the new one only, retained invitee's token unchanged) → REMOVAL (CANCEL to
// the removed one only) → COSMETIC update (no email, SEQUENCE stable) → DELETE
// (CANCEL to the remaining one). Emails: dry-run .eml by default; REAL send only
// if CALGW_LIVE_SEND=1 (a coordinator decision). Zero debris (defer).
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//	  go test ./internal/caldav/ -run TestLiveInviteLifecycle -v
func TestLiveInviteLifecycle(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live invite lifecycle round-trip")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	if dataDir == "" {
		t.Fatal("need CALGW_DATADIR")
	}
	if os.Getenv("CALGW_LIVE_SEND") == "1" {
		t.Fatal("lifecycle test is dry-run only — run the M5a full-path test for real sends")
	}

	ctx := context.Background()
	acct, err := proton.RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	cals, err := acct.ListCalendars(ctx)
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	calID := ""
	for _, c := range cals {
		if strings.HasPrefix(c.ID, liveTestCalendarPrefix) {
			calID = c.ID
			break
		}
	}
	if calID == "" {
		t.Fatalf("no calendar with ID prefix %q (test calendar missing?)", liveTestCalendarPrefix)
	}
	addrs := acct.Addresses()
	if len(addrs) == 0 {
		t.Fatal("no account address")
	}
	organizer := addrs[0]
	const invitee1 = "bob@example.com"
	const invitee2 = "calgw-m5b-test@example.com" // never actually emailed (dry-run)

	dry := &dryRunSender{t: t, dir: t.TempDir()}
	backend := NewBackend(acct, "alice")
	backend.ConfigureInvites(append([]string{organizer}, acct.Addresses()...), "Alice", dry)

	buildPut := func(uid, title string, start time.Time, attendees ...string) *ical.Calendar {
		cal := buildICS(t, uid, title, start, start.Add(time.Hour), false)
		org := ical.NewProp(ical.PropOrganizer)
		org.Params.Set(ical.ParamCommonName, "Alice")
		org.Value = "mailto:" + organizer
		cal.Children[0].Props.Set(org)
		for _, email := range attendees {
			att := ical.NewProp(ical.PropAttendee)
			att.Params.Set(ical.ParamCommonName, email)
			att.Params.Set(ical.ParamRSVP, "TRUE")
			att.Value = "mailto:" + email
			cal.Children[0].Props.Add(att)
		}
		return cal
	}
	// snapshot re-reads the decrypted state and checks SEQUENCE + invitee set.
	snapshot := func(step string, eventID string, wantSeq int, wantEmails ...string) *proton.Event {
		t.Helper()
		ev, gerr := acct.GetEvent(ctx, calID, eventID)
		if gerr != nil {
			t.Fatalf("%s: GetEvent: %v", step, gerr)
		}
		if ev.DecryptFailed {
			t.Fatalf("%s: event does not decrypt cleanly", step)
		}
		if ev.Sequence != wantSeq {
			t.Errorf("%s: Sequence = %d, want %d", step, ev.Sequence, wantSeq)
		}
		if ev.Organizer != organizer {
			t.Errorf("%s: Organizer = %q, want %q", step, ev.Organizer, organizer)
		}
		got := make(map[string]bool, len(ev.Attendees))
		for _, at := range ev.Attendees {
			got[strings.ToLower(at.Email)] = true
			if at.Token == "" {
				t.Errorf("%s: invitee %s without X-PM-TOKEN", step, at.Email)
			}
		}
		if len(got) != len(wantEmails) {
			t.Errorf("%s: attendees = %+v, want %v", step, ev.Attendees, wantEmails)
		}
		for _, w := range wantEmails {
			if !got[strings.ToLower(w)] {
				t.Errorf("%s: invitee %s missing (%+v)", step, w, ev.Attendees)
			}
		}
		return ev
	}
	lastEML := func(step, wantMethod string, wantSeq int, wantTo string) {
		t.Helper()
		if len(dry.msgs) == 0 {
			t.Fatalf("%s: no email generated", step)
		}
		m := dry.msgs[len(dry.msgs)-1]
		if m.To != wantTo || m.Method != wantMethod {
			t.Errorf("%s: email To %q Method %q, want %q/%q", step, m.To, m.Method, wantTo, wantMethod)
		}
		ics := string(m.ICS)
		wantSeqLine := fmt.Sprintf("SEQUENCE:%d", wantSeq)
		if !strings.Contains(ics, "METHOD:"+wantMethod) || !strings.Contains(ics, wantSeqLine) {
			t.Errorf("%s: ICS sans METHOD:%s / %s:\n%s", step, wantMethod, wantSeqLine, ics)
		}
		if strings.Contains(ics, "X-PM-TOKEN") {
			t.Errorf("%s: X-PM-TOKEN leaked into the email", step)
		}
	}

	// 1) CREATE invitee (M5a, the cycle's base).
	uid := "calgw-m5b-live-" + time.Now().UTC().Format("20060102T150405Z")
	start := time.Now().UTC().Add(96 * time.Hour).Truncate(time.Hour)
	putPath := "/alice/calendars/" + calID + "/" + uid + ".ics"
	obj, err := backend.PutCalendarObject(ctx, putPath, buildPut(uid, "TEST cal-gateway M5b — ignore", start, invitee1), nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = backend.DeleteCalendarObject(ctx, obj.Path) // no debris
		}
	}()
	eventID := strings.TrimSuffix(path.Base(obj.Path), ".ics")
	ev0 := snapshot("create", eventID, 0, invitee1)
	tok1 := ev0.Attendees[0].Token
	if dry.count != 1 {
		t.Fatalf("create: emails = %d, want 1", dry.count)
	}
	lastEML("create", "REQUEST", 0, invitee1)

	// 2) SIGNIFICANT UPDATE (start+1h): SEQUENCE+1, REQUEST to the retained one,
	//    attendees card INTACT (same token, organizer in place).
	if _, err := backend.PutCalendarObject(ctx, obj.Path, buildPut(uid, "TEST cal-gateway M5b — ignore", start.Add(time.Hour), invitee1), nil); err != nil {
		t.Fatalf("significant update: %v", err)
	}
	ev1 := snapshot("significant-update", eventID, 1, invitee1)
	if ev1.Attendees[0].Token != tok1 {
		t.Errorf("significant update: token rewritten (%s → %s) — the card should have survived verbatim", tok1, ev1.Attendees[0].Token)
	}
	if !ev1.Start.Equal(start.Add(time.Hour)) {
		t.Errorf("significant update: Start = %v, want %v", ev1.Start, start.Add(time.Hour))
	}
	if dry.count != 2 {
		t.Fatalf("significant update: emails = %d, want 2", dry.count)
	}
	lastEML("significant-update", "REQUEST", 1, invitee1)

	// 3) ADD an invitee: REQUEST to the new one only, retained invitee's token intact.
	if _, err := backend.PutCalendarObject(ctx, obj.Path, buildPut(uid, "TEST cal-gateway M5b — ignore", start.Add(time.Hour), invitee1, invitee2), nil); err != nil {
		t.Fatalf("add invitee: %v", err)
	}
	ev2 := snapshot("add", eventID, 2, invitee1, invitee2)
	for _, at := range ev2.Attendees {
		if strings.EqualFold(at.Email, invitee1) && at.Token != tok1 {
			t.Errorf("add: retained invitee's token rewritten (%s → %s)", tok1, at.Token)
		}
	}
	if dry.count != 3 {
		t.Fatalf("add: emails = %d, want 3 (REQUEST to the new one only)", dry.count)
	}
	lastEML("add", "REQUEST", 2, invitee2)

	// 4) REMOVAL of the 2nd invitee: CANCEL to the removed one only, reduced list.
	if _, err := backend.PutCalendarObject(ctx, obj.Path, buildPut(uid, "TEST cal-gateway M5b — ignore", start.Add(time.Hour), invitee1), nil); err != nil {
		t.Fatalf("remove invitee: %v", err)
	}
	snapshot("removal", eventID, 3, invitee1)
	if dry.count != 4 {
		t.Fatalf("removal: emails = %d, want 4 (CANCEL to the removed one only)", dry.count)
	}
	lastEML("removal", "CANCEL", 3, invitee2)

	// 5) COSMETIC UPDATE (title): no email, SEQUENCE stable.
	if _, err := backend.PutCalendarObject(ctx, obj.Path, buildPut(uid, "TEST cal-gateway M5b (renamed) — ignore", start.Add(time.Hour), invitee1), nil); err != nil {
		t.Fatalf("cosmetic update: %v", err)
	}
	ev4 := snapshot("cosmetic", eventID, 3, invitee1)
	if ev4.Title != "TEST cal-gateway M5b (renamed) — ignore" {
		t.Errorf("cosmetic: Title = %q", ev4.Title)
	}
	if dry.count != 4 {
		t.Fatalf("cosmetic: emails = %d, want 4 (no new send)", dry.count)
	}

	// 6) DELETE: CANCEL to the remaining one, clean disappearance.
	if err := backend.DeleteCalendarObject(ctx, obj.Path); err != nil {
		t.Fatalf("delete: %v", err)
	}
	deleted = true
	if dry.count != 5 {
		t.Fatalf("delete: emails = %d, want 5 (CANCEL to the remaining one)", dry.count)
	}
	lastEML("delete", "CANCEL", 4, invitee1)
	if _, err := backend.GetCalendarObject(ctx, obj.Path, nil); err == nil || !isLiveNotFound(err) {
		t.Fatalf("post-delete GET = %v, want 404/not-found", err)
	}
	t.Logf("full cycle OK — 5 dry-run .eml in %s", dry.dir)
}

// TestLivePartstatProbe (C-0) is a READ-ONLY probe: it scans ALL of the
// account's calendars (backend window) and logs each event with invitees along
// with its cleartext Status values (0=NEEDS-ACTION 1=TENTATIVE 2=DECLINED
// 3=ACCEPTED). A Status != 0 observed on an event organized by the account
// proves that the Proton server updates the cleartext column when an invitee
// responds (REPLY handled server-side) — so the "accepted" badge is FREE: our
// read path already derives PARTSTAT from this Status, and the poller refreshes
// the row. Creates nothing, modifies nothing, sends nothing.
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//	  go test ./internal/caldav/ -run TestLivePartstatProbe -v
func TestLivePartstatProbe(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the read-only PARTSTAT probe")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	if dataDir == "" {
		t.Fatal("need CALGW_DATADIR")
	}
	ctx := context.Background()
	acct, err := proton.RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	cals, err := acct.ListCalendars(ctx)
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	now := time.Now()
	invited, responded := 0, 0
	for _, c := range cals {
		events, lerr := acct.ListEvents(ctx, c.ID, now.Add(-DefaultWindowPast), now.Add(DefaultWindowFuture))
		if lerr != nil {
			t.Logf("calendar %s (%s): %v", c.Name, c.ID[:4], lerr)
			continue
		}
		for _, ev := range events {
			if len(ev.Attendees) == 0 {
				continue
			}
			invited++
			statuses := make([]int, 0, len(ev.Attendees))
			hasResponse := false
			for _, at := range ev.Attendees {
				statuses = append(statuses, at.Status)
				if at.Status != 0 {
					hasResponse = true
				}
			}
			if hasResponse {
				responded++
			}
			t.Logf("cal %s | uid %.12s… | organizer=%s | %d invitee(s) statuses=%v lastEdit=%s",
				c.Name, ev.UID, ev.Organizer, len(ev.Attendees), statuses, ev.LastEdit.Format(time.RFC3339))
		}
	}
	t.Logf("PROBE: %d event(s) with invitees in the window, %d with at least one response (Status != 0)", invited, responded)
}

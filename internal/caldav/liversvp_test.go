package caldav

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/proton"
)

// TestLiveRSVPOutgoing is the OPT-IN test (CALGW_LIVE=1) of the OUTGOING RSVP
// (M6b) on the real account (the dedicated empty test calendar, NEVER the live
// calendar):
//
//  1. we SEED a "received" event via acct.CreateEvent directly (ORGANIZER
//     = a third party planner@example.com, the account owner — the account
//     address — as an invitee at NEEDS-ACTION), in order to obtain an
//     attendeeID assigned by the server;
//
//  2. we PUT via the backend the event's full state, flipping only the account
//     owner's PARTSTAT to ACCEPTED → an iMIP REPLY is generated DRY-RUN (.eml,
//     never sent — this test is dry-run only) + the account owner's Proton
//     Status changes to 3;
//
//  3. cleanup: DELETE, zero debris (defer even on failure).
//
//     CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//     go test ./internal/caldav/ -run TestLiveRSVPOutgoing -v
func TestLiveRSVPOutgoing(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live outgoing-RSVP round-trip")
	}
	if os.Getenv("CALGW_LIVE_SEND") == "1" {
		t.Fatal("the RSVP test is dry-run only (no real email) — do not set CALGW_LIVE_SEND")
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
	self := addrs[0] // the account owner: the account address, the invitee who responds
	const organizer = "planner@example.com"

	// 1) SEED: a "received" event (third-party organizer, self as invitee),
	//    written directly (the backend would refuse a create with a third-party
	//    organizer).
	uid := "calgw-m6b-live-" + time.Now().UTC().Format("20060102T150405Z")
	start := time.Now().UTC().Add(120 * time.Hour).Truncate(time.Hour)
	seedID, err := acct.CreateEvent(ctx, calID, proton.EventInput{
		UID:         uid,
		Title:       "TEST cal-gateway M6b — ignore",
		Start:       start,
		End:         start.Add(time.Hour),
		Organizer:   organizer,
		OrganizerCN: "Planner",
		Attendees:   []proton.AttendeeInput{{Email: self, CN: "Alice"}},
	})
	if err != nil {
		t.Fatalf("seed CreateEvent (received event): %v", err)
	}
	objPath := "/alice/calendars/" + calID + "/" + seedID + ".ics"
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, seedID) // no debris
		}
	}()

	// The account owner's attendeeID assigned by the server (re-read authoritative).
	rows, err := acct.AuthoritativeEventsByUID(ctx, calID, uid)
	if err != nil || len(rows) == 0 {
		t.Fatalf("re-read of the seeded event: %v", err)
	}
	seeded := rows[0]
	if seeded.Organizer != organizer {
		t.Fatalf("seeded Organizer = %q, want %q", seeded.Organizer, organizer)
	}
	if len(seeded.Attendees) != 1 || seeded.Attendees[0].ID == "" {
		t.Fatalf("account owner's attendee without assigned ID: %+v", seeded.Attendees)
	}
	if seeded.Attendees[0].Status != 0 {
		t.Fatalf("Status initial = %d, want 0 (NEEDS-ACTION)", seeded.Attendees[0].Status)
	}

	// Backend with invitations enabled + DRY-RUN sender (.eml, never sent).
	dry := &dryRunSender{t: t, dir: t.TempDir()}
	backend := NewBackend(acct, "alice")
	backend.ConfigureInvites(acct.Addresses(), "Alice", dry)

	// 2) PUT: identical full state + account owner's PARTSTAT = ACCEPTED.
	cal := buildICS(t, uid, "TEST cal-gateway M6b — ignore", start, start.Add(time.Hour), false)
	v := cal.Children[0]
	org := ical.NewProp(ical.PropOrganizer)
	org.Params.Set(ical.ParamCommonName, "Planner")
	org.Value = "mailto:" + organizer
	v.Props.Set(org)
	att := ical.NewProp(ical.PropAttendee)
	att.Params.Set(ical.ParamCommonName, "Alice")
	att.Params.Set(ical.ParamParticipationStatus, "ACCEPTED")
	att.Value = "mailto:" + self
	v.Props.Add(att)

	if _, err := backend.PutCalendarObject(ctx, objPath, cal, nil); err != nil {
		t.Fatalf("PUT RSVP (attendu 201, pas 403): %v", err)
	}

	// A REPLY .eml generated dry-run, From=account owner, To=organizer, METHOD:REPLY.
	if dry.count != 1 {
		t.Fatalf("REPLY .eml generated = %d, want 1", dry.count)
	}
	raw, rerr := os.ReadFile(dry.paths[0])
	if rerr != nil {
		t.Fatalf("reading .eml: %v", rerr)
	}
	eml := string(raw)
	for _, want := range []string{"method=REPLY", "METHOD:REPLY", "PARTSTAT=ACCEPTED", "UID:" + uid, "mailto:" + organizer} {
		if !strings.Contains(eml, want) {
			t.Errorf(".eml REPLY missing %q", want)
		}
	}
	if strings.Contains(eml, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN leaked into the REPLY .eml")
	}
	if m := dry.msgs[0]; m.From != self || m.To != organizer {
		t.Errorf("REPLY From/To = %q/%q, want %q/%q", m.From, m.To, self, organizer)
	}

	// 3) The account owner's Proton Status has changed to ACCEPTED (3), the
	//    organizer and the rest of the event unchanged.
	after, err := acct.AuthoritativeEventsByUID(ctx, calID, uid)
	if err != nil || len(after) == 0 {
		t.Fatalf("post-RSVP re-read: %v", err)
	}
	ev := after[0]
	if ev.Organizer != organizer {
		t.Errorf("post-RSVP Organizer = %q, want %q (never rewritten)", ev.Organizer, organizer)
	}
	if len(ev.Attendees) != 1 || ev.Attendees[0].Status != 3 {
		t.Fatalf("post-RSVP Status = %+v, want 3 (ACCEPTED)", ev.Attendees)
	}
	t.Logf("RSVP OK — Status 0→3, dry-run REPLY .eml in %s", dry.dir)

	// 4) Cleanup.
	if err := acct.DeleteEvent(ctx, calID, seedID); err != nil {
		t.Fatalf("cleanup DeleteEvent: %v", err)
	}
	deleted = true
}

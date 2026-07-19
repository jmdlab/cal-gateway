package proton

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
)

// TestLiveAttendeesCardRoundTrip is the OPT-IN test (CALGW_LIVE=1) of the
// PROTON half of M5a on the real account: CreateEvent with ONE invitee
// (bob@example.com) → RAW re-read of the row: the AttendeesEventContent card
// exists (Type 3), decrypts with the SharedKeyPacket (shared session key),
// carries the ATTENDEE line with X-PM-TOKEN = SHA1(UID+canonical); the
// SharedSigned card carries ORGANIZER before SEQUENCE; the PLAINTEXT Attendees
// array carries the same token (Status 0) → DECRYPTED re-read:
// Event.Organizer + Event.Attendees round-trip → DELETE, disappearance (2501),
// zero debris (cleanup in defer even on failure). NO email sent here — this
// test exercises only the API write path.
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//	  go test ./internal/proton/ -run TestLiveAttendeesCardRoundTrip -v
func TestLiveAttendeesCardRoundTrip(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live attendees-card round-trip")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	if dataDir == "" {
		t.Fatal("need CALGW_DATADIR")
	}

	ctx := context.Background()
	acct, err := RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	calID := resolveLiveTestCalendar(t, ctx, acct)

	addrs := acct.Addresses()
	if len(addrs) == 0 {
		t.Fatal("no account address to organize with")
	}
	organizer := addrs[0]
	const invitee = "bob@example.com"

	// 0) Canonicalization only (the /core/v4/addresses/canonical endpoint).
	canon, err := acct.canonicalEmails(ctx, []string{invitee})
	if err != nil {
		t.Fatalf("canonicalEmails: %v", err)
	}
	t.Logf("canonical(%s) = %s", invitee, canon[invitee])

	// 1) Create with one invitee.
	start := time.Now().UTC().Add(96 * time.Hour).Truncate(time.Hour)
	in := EventInput{
		Title: "TEST cal-gateway M5a — ignorer",
		Start: start, End: start.Add(time.Hour),
		TZID:        "Europe/Paris",
		Organizer:   organizer,
		OrganizerCN: "Alice",
		Attendees:   []AttendeeInput{{Email: invitee, CN: "Bob"}},
	}
	eventID, err := acct.CreateEvent(ctx, calID, in)
	if err != nil {
		t.Fatalf("CreateEvent with invitee: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, eventID) // no debris, even on failure
		}
	}()
	t.Logf("created invited event %s", eventID)

	// 2) Raw row: attendees card + plaintext array + ORGANIZER.
	row, err := acct.getEventRow(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("getEventRow: %v", err)
	}
	uid := row.UID
	wantToken := attendeeToken(uid, canon[invitee])

	if len(row.AttendeesEvents) != 1 {
		t.Fatalf("AttendeesEvents = %d cartes, want 1", len(row.AttendeesEvents))
	}
	attPart := row.AttendeesEvents[0]
	if attPart.Type&papi.CalendarEventTypeEncrypted == 0 {
		t.Errorf("attendees card not encrypted (Type %d)", attPart.Type)
	}
	calKR, err := acct.calendarKeyRing(ctx, calID)
	if err != nil {
		t.Fatalf("calendarKeyRing: %v", err)
	}
	// THE shared-session-key proof: the card opens with SharedKeyPacket.
	plain, err := (&Account{}).cardPlaintext(attPart, row.SharedKeyPacket, calKR)
	if err != nil {
		t.Fatalf("attendees card unreadable with SharedKeyPacket: %v", err)
	}
	attLine := strings.ReplaceAll(strings.ReplaceAll(plain, "\r\n ", ""), "\r\n\t", "")
	if !strings.Contains(attLine, "X-PM-TOKEN="+wantToken+":mailto:"+invitee) {
		t.Errorf("attendees card without the expected token %s:\n%s", wantToken, plain)
	}
	if strings.Contains(plain, "DTSTAMP") {
		t.Errorf("DTSTAMP forbidden in the attendees card:\n%s", plain)
	}

	var signedCard string
	for i := range row.SharedEvents {
		if row.SharedEvents[i].Type&papi.CalendarEventTypeEncrypted == 0 {
			signedCard = row.SharedEvents[i].Data
			break
		}
	}
	unfoldedSigned := strings.ReplaceAll(signedCard, "\r\n ", "")
	iOrg := strings.Index(unfoldedSigned, "ORGANIZER;CN=Alice:mailto:"+organizer)
	iSeq := strings.Index(unfoldedSigned, "SEQUENCE:")
	if iOrg < 0 || iSeq < iOrg {
		t.Errorf("ORGANIZER missing or after SEQUENCE in the signed card:\n%s", signedCard)
	}
	if len(row.Attendees) != 1 || row.Attendees[0].Token != wantToken || int(row.Attendees[0].Status) != 0 {
		t.Errorf("plaintext Attendees array = %+v, want [{token %s, status 0}]", row.Attendees, wantToken)
	}

	// 3) Decrypted re-read (the M5a read path).
	ev, err := acct.GetEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if ev.DecryptFailed {
		t.Fatal("invited event does not decrypt cleanly")
	}
	if ev.Organizer != organizer {
		t.Errorf("Organizer = %q, want %q", ev.Organizer, organizer)
	}
	if len(ev.Attendees) != 1 || ev.Attendees[0].Email != invitee ||
		ev.Attendees[0].Token != wantToken || ev.Attendees[0].Status != 0 {
		t.Errorf("Attendees = %+v, want [{%s Bob 0 %s}]", ev.Attendees, invitee, wantToken)
	}

	// 4) Delete + clean disappearance (2501).
	if err := acct.DeleteEvent(ctx, calID, eventID); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	deleted = true
	if _, err := acct.GetEvent(ctx, calID, eventID); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("event still readable after delete (err = %v), want ErrEventNotFound", err)
	}
}

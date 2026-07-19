package proton

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
)

// TestAttendeeToken pins the X-PM-TOKEN computation against a hand-computed
// vector: lowercase hex of SHA1(UID + CanonicalEmail), raw concatenation.
// $ printf 'calgw-m5a-test-uid-1bob@example.com' | sha1sum
func TestAttendeeToken(t *testing.T) {
	got := attendeeToken("calgw-m5a-test-uid-1", "bob@example.com")
	want := "0f140f48d340be5225613c813741c44584068d08"
	if got != want {
		t.Errorf("attendeeToken = %q, want %q", got, want)
	}
	if got != strings.ToLower(got) {
		t.Errorf("token must be lowercase hex: %q", got)
	}
}

// TestAttendeesFragmentByteExact pins the AttendeesEventContent card byte for
// byte: VCALENDAR/VEVENT wrapper, UID then the ATTENDEE line (parameter order
// CN, ROLE, RSVP, PARTSTAT, X-PM-TOKEN), folded per RFC 5545 at 75 octets,
// CRLF, no trailing CRLF, NO DTSTAMP.
func TestAttendeesFragmentByteExact(t *testing.T) {
	uid := "calgw-m5a-test-uid-1"
	atts := []AttendeeInput{{Email: "bob@example.com"}}
	tokens := []string{attendeeToken(uid, "bob@example.com")}

	want := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:calgw-m5a-test-uid-1\r\n" +
		"ATTENDEE;CN=bob@example.com;ROLE=REQ-PARTICIPANT;RSVP=TRUE;PARTSTAT=NEEDS-A\r\n" +
		" CTION;X-PM-TOKEN=0f140f48d340be5225613c813741c44584068d08:mailto:bob@examp\r\n" +
		" le.com\r\nEND:VEVENT\r\nEND:VCALENDAR"
	if got := attendeesFragment(uid, atts, tokens); got != want {
		t.Errorf("attendees card bytes:\ngot  %q\nwant %q", got, want)
	}
}

// TestAttendeeLineCN: explicit CN, default (email), quoting of special
// parameter characters, and truncation at 190.
func TestAttendeeLineCN(t *testing.T) {
	if got := attendeeLine(AttendeeInput{Email: "a@b.c", CN: "Test-User"}, "tok"); !strings.HasPrefix(got, "ATTENDEE;CN=Test-User;ROLE=") {
		t.Errorf("explicit CN: %q", got)
	}
	if got := attendeeLine(AttendeeInput{Email: "a@b.c", CN: "Doe, Bob"}, "tok"); !strings.Contains(got, `CN="Doe, Bob";ROLE=`) {
		t.Errorf("CN with comma must be quoted: %q", got)
	}
	long := strings.Repeat("x", 200)
	if got := attendeeLine(AttendeeInput{Email: "a@b.c", CN: long}, "tok"); strings.Contains(got, strings.Repeat("x", 191)) {
		t.Errorf("CN not truncated at 190: %q", got)
	}
}

// TestBuildFragmentsOrganizerPosition: ORGANIZER on the SharedSigned card,
// AFTER EXDATE and BEFORE SEQUENCE, never an X-PM-TOKEN on it.
func TestBuildFragmentsOrganizerPosition(t *testing.T) {
	start := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	in := EventInput{
		Start: start, End: start.Add(time.Hour),
		RRule:       "FREQ=DAILY;COUNT=3",
		ExDates:     []time.Time{start.Add(24 * time.Hour)},
		Organizer:   "alice@example.com",
		OrganizerCN: "Alice",
		Attendees:   []AttendeeInput{{Email: "bob@example.com"}},
	}
	frags := buildFragments("uid-org", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), in)

	card := frags.sharedSigned
	iEx := strings.Index(card, "EXDATE")
	iOrg := strings.Index(card, "ORGANIZER;CN=Alice:mailto:alice@example.com")
	iSeq := strings.Index(card, "SEQUENCE:")
	if iOrg < 0 {
		t.Fatalf("ORGANIZER missing from the SharedSigned card:\n%s", card)
	}
	if !(iEx < iOrg && iOrg < iSeq) {
		t.Errorf("order EXDATE(%d) < ORGANIZER(%d) < SEQUENCE(%d) not respected:\n%s", iEx, iOrg, iSeq, card)
	}
	if strings.Contains(card, "X-PM-TOKEN") {
		t.Errorf("X-PM-TOKEN forbidden on the SharedSigned card:\n%s", card)
	}
	// Without an invitation: no ORGANIZER.
	in2 := EventInput{Start: start, End: start.Add(time.Hour)}
	if f2 := buildFragments("uid-no", time.Now().UTC(), in2); strings.Contains(f2.sharedSigned, "ORGANIZER") {
		t.Errorf("ORGANIZER emitted without an invitation:\n%s", f2.sharedSigned)
	}
}

// TestSealCardsAttendeesSharedSessionKey: the attendees card is Type=3 and
// decrypts with the body's SharedKeyPacket — THE SAME session key as the
// SharedEncrypted card, no dedicated key packet.
func TestSealCardsAttendeesSharedSessionKey(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	uid := "uid-seal-att"
	frags := buildFragments(uid, time.Now().UTC(), EventInput{
		Start: time.Now().UTC(), End: time.Now().UTC().Add(time.Hour),
		Title: "Lunch",
	})
	frags.attendees = attendeesFragment(uid,
		[]AttendeeInput{{Email: "bob@example.com"}},
		[]string{attendeeToken(uid, "bob@example.com")})

	body, err := sealCards(frags, calKR, signerKR)
	if err != nil {
		t.Fatalf("sealCards: %v", err)
	}
	if len(body.AttendeesEventContent) != 1 {
		t.Fatalf("AttendeesEventContent = %d cartes, want 1", len(body.AttendeesEventContent))
	}
	att := body.AttendeesEventContent[0]
	if att.Type != cardEncryptedAndSigned {
		t.Errorf("attendees card Type = %d, want %d (ENCRYPTED_AND_SIGNED)", att.Type, cardEncryptedAndSigned)
	}
	if att.Signature == "" {
		t.Error("attendees card not signed")
	}
	// Decryption with the SHARED key packet (SharedKeyPacket).
	part := papi.CalendarEventPart{
		Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned,
		Data: att.Data,
	}
	plain, err := (&Account{}).cardPlaintext(part, body.SharedKeyPacket, calKR)
	if err != nil {
		t.Fatalf("attendees card does not open with SharedKeyPacket: %v", err)
	}
	if plain != frags.attendees {
		t.Errorf("attendees plaintext altered:\ngot  %q\nwant %q", plain, frags.attendees)
	}
	// And the SharedEncrypted card opens with the SAME key packet.
	shEnc := body.SharedEventContent[1]
	if _, err := (&Account{}).cardPlaintext(papi.CalendarEventPart{
		Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned,
		Data: shEnc.Data,
	}, body.SharedKeyPacket, calKR); err != nil {
		t.Fatalf("SharedEncrypted card and attendees card do not share the session key: %v", err)
	}
	// Without attendees: empty array, no card.
	frags.attendees = ""
	body2, err := sealCards(frags, calKR, signerKR)
	if err != nil {
		t.Fatalf("sealCards without attendees: %v", err)
	}
	if len(body2.AttendeesEventContent) != 0 || string(body2.Attendees) != "[]" {
		t.Errorf("creation without attendees: AttendeesEventContent=%v Attendees=%s", body2.AttendeesEventContent, body2.Attendees)
	}
}

// TestEventBodyIsOrganizerOmitted: IsOrganizer is absent from the JSON when it
// is 0 (every path other than invitation creation) and present at 1 otherwise.
func TestEventBodyIsOrganizerOmitted(t *testing.T) {
	raw, err := json.Marshal(&eventBody{Permissions: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "IsOrganizer") {
		t.Errorf("IsOrganizer emitted at 0: %s", raw)
	}
	raw, err = json.Marshal(&eventBody{Permissions: 1, IsOrganizer: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"IsOrganizer":1`) {
		t.Errorf("IsOrganizer:1 absent: %s", raw)
	}
}

// TestDecryptEventAttendees: the read path decrypts the AttendeesEvents card
// (shared session key), parses ORGANIZER (SharedSigned card) and joins the
// CLEARTEXT Status from the row's Attendees array by Token.
func TestDecryptEventAttendees(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	uid := "uid-read-att"
	tokJM := attendeeToken(uid, "bob@example.com")
	tokSeb := attendeeToken(uid, "seb@example.com")

	signedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:" + uid + "\r\n" +
		"DTSTART:20260901T090000Z\r\n" +
		"DTEND:20260901T100000Z\r\n" +
		"ORGANIZER;CN=Alice:mailto:alice@example.com\r\n" +
		"SEQUENCE:0\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"
	attCard := attendeesFragment(uid,
		[]AttendeeInput{{Email: "bob@example.com", CN: "Bob"}, {Email: "seb@example.com"}},
		[]string{tokJM, tokSeb})

	kp, data, _, err := encryptAndSign(attCard, calKR, signerKR)
	if err != nil {
		t.Fatalf("encryptAndSign: %v", err)
	}

	raw := papi.CalendarEvent{
		ID: "row-att", UID: uid,
		StartTime:       time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC).Unix(),
		EndTime:         time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC).Unix(),
		SharedKeyPacket: kp, // shared by the shared AND attendees cards
		SharedEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeSigned, Data: signedCard},
		},
		AttendeesEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned, Data: data},
		},
		Attendees: []papi.CalendarAttendee{
			{Token: tokJM, Status: papi.CalendarAttendeeStatusYes}, // 3 = ACCEPTED
			{Token: tokSeb, Status: papi.CalendarAttendeeStatusNo}, // 2 = DECLINED
		},
	}
	ev := (&Account{}).decryptEvent(raw, "", calKR)
	if ev.DecryptFailed {
		t.Fatal("decryptEvent failed on the fixture")
	}
	if ev.Organizer != "alice@example.com" {
		t.Errorf("Organizer = %q, want alice@example.com", ev.Organizer)
	}
	if len(ev.Attendees) != 2 {
		t.Fatalf("Attendees = %+v, want 2 attendees", ev.Attendees)
	}
	if a := ev.Attendees[0]; a.Email != "bob@example.com" || a.CN != "Bob" || a.Token != tokJM || a.Status != 3 {
		t.Errorf("attendee 1 = %+v, want {bob@example.com Bob 3 %s}", a, tokJM)
	}
	if a := ev.Attendees[1]; a.Email != "seb@example.com" || a.Status != 2 {
		t.Errorf("attendee 2 = %+v, want status 2 (DECLINED)", a)
	}
}

// TestRebuildAttendeesFragment (M5b): the lines of KEPT attendees survive
// VERBATIM (PARTSTAT/params included), the removed one disappears, the added
// one gets a fresh line; "" when no attendee remains; fresh card when the event
// had none.
func TestRebuildAttendeesFragment(t *testing.T) {
	tokKeep := attendeeToken("uid-r", "bob@example.com")
	tokDrop := attendeeToken("uid-r", "seb@example.com")
	// "Kept" line deliberately NON-standard (PARTSTAT=ACCEPTED written by a
	// Proton client): it must survive to the byte.
	keptLine := "ATTENDEE;CN=Bob;ROLE=REQ-PARTICIPANT;RSVP=TRUE;PARTSTAT=ACCEPTED;X-PM-TOKEN=" +
		tokKeep + ":mailto:bob@example.com"
	old := icalWrap([]string{
		"UID:uid-r",
		keptLine,
		attendeeLine(AttendeeInput{Email: "seb@example.com"}, tokDrop),
	})

	added := []AttendeeInput{{Email: "carol@example.com", CN: "Carol"}}
	addedTok := []string{attendeeToken("uid-r", "carol@example.com")}
	got := rebuildAttendeesFragment(old, "uid-r", map[string]bool{tokKeep: true}, added, addedTok)

	unfolded := strings.ReplaceAll(strings.ReplaceAll(got, "\r\n ", ""), "\r\n\t", "")
	if !strings.Contains(unfolded, keptLine) {
		t.Errorf("kept line not verbatim:\n%s", got)
	}
	if strings.Contains(unfolded, "seb@example.com") {
		t.Errorf("removed attendee still present:\n%s", got)
	}
	if !strings.Contains(unfolded, "X-PM-TOKEN="+addedTok[0]+":mailto:carol@example.com") {
		t.Errorf("added attendee missing:\n%s", got)
	}
	if !strings.HasPrefix(got, "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:uid-r") ||
		!strings.HasSuffix(got, "END:VEVENT\r\nEND:VCALENDAR") {
		t.Errorf("invalid card wrapper:\n%s", got)
	}

	// No attendee remains → card removed.
	if got := rebuildAttendeesFragment(old, "uid-r", nil, nil, nil); got != "" {
		t.Errorf("empty card expected, got:\n%s", got)
	}
	// No original card → same form as a creation.
	fresh := rebuildAttendeesFragment("", "uid-r", nil, added, addedTok)
	if fresh != attendeesFragment("uid-r", added, addedTok) {
		t.Errorf("fresh card != creation form:\n%s", fresh)
	}
}

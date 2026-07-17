package proton

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// Tests of the UPDATE path (M3): in-place patch of the cards, reuse of the
// original session keys, anti-loss guarantee (properties outside the model kept
// verbatim).

func TestPatchCardPreservesUnknownProps(t *testing.T) {
	// Card with properties OUTSIDE the model (ORGANIZER, ATTENDEE, X-*) and a
	// nested VALARM carrying a SUMMARY — which must NOT be touched.
	card := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:u1\r\n" +
		"SUMMARY:Old title\r\n" +
		"ORGANIZER;CN=Alice:mailto:alice@example.com\r\n" +
		"ATTENDEE;CN=Bob:mailto:bob@example.com\r\n" +
		"X-PM-CONFERENCE-URL:https://meet.example/xyz\r\n" +
		"BEGIN:VALARM\r\n" +
		"ACTION:EMAIL\r\n" +
		"SUMMARY:Reminder\r\n" +
		"TRIGGER:-PT15M\r\n" +
		"END:VALARM\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"

	patch := cardPatch{
		set: map[string]string{"SUMMARY": ":New title"},
		del: map[string]bool{},
	}
	got := patchCard(card, patch)

	for _, want := range []string{
		"SUMMARY:New title",
		"ORGANIZER;CN=Alice:mailto:alice@example.com",
		"ATTENDEE;CN=Bob:mailto:bob@example.com",
		"X-PM-CONFERENCE-URL:https://meet.example/xyz",
		"BEGIN:VALARM\r\nACTION:EMAIL\r\nSUMMARY:Reminder", // VALARM intact
	} {
		if !strings.Contains(got, want) {
			t.Errorf("patched card missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Old title") {
		t.Errorf("old SUMMARY survived:\n%s", got)
	}
	// The VALARM's SUMMARY must not have been replaced.
	if strings.Count(got, "SUMMARY:New title") != 1 {
		t.Errorf("VALARM SUMMARY was patched too:\n%s", got)
	}
}

func TestPatchCardDeleteAppendInsert(t *testing.T) {
	card := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:u1\r\n" +
		"DTSTART:20220307T090000Z\r\n" +
		"RRULE:FREQ=WEEKLY;BYDAY=MO,TH\r\n" +
		"EXDATE:20260601T090000Z\r\n" +
		"SEQUENCE:0\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"

	patch := cardPatch{
		set: map[string]string{
			"SEQUENCE": ":1",
			"LOCATION": ":Room B", // absent: must be inserted before END:VEVENT
		},
		del: map[string]bool{"EXDATE": true},
		add: []string{"EXDATE:20260713T090000Z", "EXDATE:20260716T090000Z"},
	}
	got := patchCard(card, patch)

	if strings.Contains(got, "EXDATE:20260601T090000Z") {
		t.Errorf("deleted EXDATE survived:\n%s", got)
	}
	for _, want := range []string{
		"EXDATE:20260713T090000Z",
		"EXDATE:20260716T090000Z",
		"SEQUENCE:1",
		"LOCATION:Room B",
		"RRULE:FREQ=WEEKLY;BYDAY=MO,TH",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("patched card missing %q:\n%s", want, got)
		}
	}
	if !strings.HasSuffix(got, "END:VEVENT\r\nEND:VCALENDAR") || strings.HasSuffix(got, "\r\n") {
		t.Errorf("wrapper form broken:\n%q", got)
	}

	// Empty patch: the card must pass byte for byte.
	if patchCard(card, cardPatch{}) != card {
		t.Error("empty patch must return the card verbatim")
	}
}

func TestDiffPatchesMinimal(t *testing.T) {
	// Real master: it LIVES in TZID Europe/Paris inside Proton (columns
	// StartTimezone/EndTimezone), set in WINTER — 09:00 CET = 08:00Z.
	start := time.Date(2022, 3, 7, 8, 0, 0, 0, time.UTC)
	cur := &Event{
		Title: "Weekly Sync", Start: start, End: start.Add(time.Hour),
		TZ: "Europe/Paris", EndTZ: "Europe/Paris",
		RRule: "FREQ=WEEKLY;BYDAY=MO,TH", Sequence: 0,
	}

	// Identical input, sent back in Z form by the client (TZID empty): no patch
	// — instant unchanged, the original TZID form stays intact.
	same := EventInput{
		Title: "Weekly Sync", Start: start, End: start.Add(time.Hour),
		RRule: "FREQ=WEEKLY;BYDAY=MO,TH",
	}
	signed, enc := diffPatches(cur, same)
	if !signed.empty() || !enc.empty() {
		t.Fatalf("unchanged input produced patches: signed=%+v enc=%+v", signed, enc)
	}

	// SUMMER EXDATE added by a client in Z form (TZID empty): the ORIGINAL zone
	// is reused — DST-correct wall-clock time (09:00 CEST), NEVER a bare Z
	// reintroduced into the card (the 2026-07-16 self-corruption). SEQUENCE
	// bumped, bounds untouched.
	ex := time.Date(2026, 7, 16, 7, 0, 0, 0, time.UTC) // 09:00 CEST
	withEx := same
	withEx.ExDates = []time.Time{ex}
	signed, enc = diffPatches(cur, withEx)
	if !enc.empty() {
		t.Errorf("text patch on structural-only change: %+v", enc)
	}
	if !signed.del["EXDATE"] || len(signed.add) != 1 || signed.add[0] != "EXDATE;TZID=Europe/Paris:20260716T090000" {
		t.Errorf("EXDATE patch = %+v", signed)
	}
	if signed.set["SEQUENCE"] != ":1" {
		t.Errorf("SEQUENCE = %q, want :1", signed.set["SEQUENCE"])
	}
	if _, has := signed.set["DTSTART"]; has {
		t.Error("DTSTART rewritten although unchanged")
	}

	// Instant CHANGED with TZID empty: bounds rewritten in the ORIGINAL zone.
	moved := same
	moved.Start = start.Add(30 * time.Minute) // 09:30 CET
	moved.End = moved.Start.Add(time.Hour)
	signed, _ = diffPatches(cur, moved)
	if signed.set["DTSTART"] != ";TZID=Europe/Paris:20220307T093000" {
		t.Errorf("DTSTART = %q, want original TZID form", signed.set["DTSTART"])
	}
	if signed.set["DTEND"] != ";TZID=Europe/Paris:20220307T103000" {
		t.Errorf("DTEND = %q, want original TZID form", signed.set["DTEND"])
	}

	// Explicit client TZID: always master.
	repinned := moved
	repinned.TZID = "America/New_York"
	signed, _ = diffPatches(cur, repinned)
	if signed.set["DTSTART"] != ";TZID=America/New_York:20220307T033000" { // 08:30Z = 03:30 EST
		t.Errorf("DTSTART = %q, want client zone", signed.set["DTSTART"])
	}

	// Event that lived in bare Z (empty TZ): it stays there — the guard never
	// fabricates a zone.
	curZ := &Event{Title: "Z", Start: start, End: start.Add(time.Hour), RRule: "FREQ=DAILY"}
	withExZ := EventInput{Title: "Z", Start: start, End: start.Add(time.Hour), RRule: "FREQ=DAILY", ExDates: []time.Time{ex}}
	signed, _ = diffPatches(curZ, withExZ)
	if len(signed.add) != 1 || signed.add[0] != "EXDATE:20260716T070000Z" {
		t.Errorf("EXDATE Z = %+v, want Z form preserved", signed.add)
	}

	// Title cleared: deletion of the TEXT property.
	cleared := same
	cleared.Title = ""
	_, enc = diffPatches(cur, cleared)
	if !enc.del["SUMMARY"] {
		t.Errorf("cleared title must delete SUMMARY: %+v", enc)
	}
}

// TestUpdateResealRoundTrip is the critical M3 test: re-seal a patched event and
// prove that (1) the cards re-decrypt with the ORIGINAL key packets (session
// keys reused), (2) the properties outside the model survive verbatim, (3) the
// detached signatures cover the sent bytes, (4) the body carries no key packet.
func TestUpdateResealRoundTrip(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	// Original cards, with properties outside the model to preserve.
	signedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-m3\r\n" +
		"DTSTART:20220307T090000Z\r\n" +
		"DTEND:20220307T100000Z\r\n" +
		"RRULE:FREQ=WEEKLY;BYDAY=MO,TH\r\n" +
		"X-SIGNED-KEEP:yes\r\n" +
		"SEQUENCE:0\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"
	encCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-m3\r\n" +
		"SUMMARY:Weekly Sync\r\n" +
		"ORGANIZER;CN=Alice:mailto:alice@example.com\r\n" +
		"X-ENC-KEEP:yes\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"

	// "Creation" sealing (fresh session key -> key packet).
	kp, data, _, err := encryptAndSign(encCard, calKR, signerKR)
	if err != nil {
		t.Fatalf("encryptAndSign: %v", err)
	}

	row := &eventRow{CalendarEvent: papi.CalendarEvent{
		ID: "row-m3", UID: "uid-m3",
		StartTime:       time.Date(2022, 3, 7, 9, 0, 0, 0, time.UTC).Unix(),
		EndTime:         time.Date(2022, 3, 7, 10, 0, 0, 0, time.UTC).Unix(),
		SharedKeyPacket: kp,
		SharedEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeSigned, Data: signedCard},
			{Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned, Data: data},
		},
	}}
	cur := decryptEvent(row.CalendarEvent, calKR)
	if cur.DecryptFailed {
		t.Fatal("fixture must decrypt cleanly")
	}

	// Update: title modified + EXDATE added (the Apple scenario).
	ex := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	in := EventInput{
		Title: "Weekly Sync (modified)",
		Start: cur.Start, End: cur.End,
		RRule:   cur.RRule,
		ExDates: []time.Time{ex},
	}
	body, err := buildUpdateBody(row, &cur, in, calKR, signerKR, nil)
	if err != nil {
		t.Fatalf("buildUpdateBody: %v", err)
	}

	// (4) No key packet in an update body.
	if body.SharedKeyPacket != "" || body.CalendarKeyPacket != "" {
		t.Fatal("update body must not carry key packets")
	}

	// (2)+(3) Signed card: EXDATE + SEQUENCE:1 + X- kept, signature OK.
	newSigned := body.SharedEventContent[0]
	for _, want := range []string{"EXDATE:20260716T090000Z", "SEQUENCE:1", "X-SIGNED-KEEP:yes", "RRULE:FREQ=WEEKLY;BYDAY=MO,TH"} {
		if !strings.Contains(newSigned.Data, want) {
			t.Errorf("signed card missing %q:\n%s", want, newSigned.Data)
		}
	}
	sig, err := crypto.NewPGPSignatureFromArmored(newSigned.Signature)
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	if err := signerKR.VerifyDetached(crypto.NewPlainMessage([]byte(newSigned.Data)), sig, crypto.GetUnixTime()); err != nil {
		t.Errorf("signed card signature does not cover Data bytes: %v", err)
	}

	// (1) Encrypted card: re-decrypts with the ORIGINAL key packet.
	newEnc := body.SharedEventContent[1]
	part := papi.CalendarEventPart{Type: papi.CalendarEventType(newEnc.Type), Data: newEnc.Data}
	plain, err := cardPlaintext(part, kp, calKR)
	if err != nil {
		t.Fatalf("re-encrypted card does not open with the ORIGINAL key packet: %v", err)
	}
	for _, want := range []string{"SUMMARY:Weekly Sync (modified)", "ORGANIZER;CN=Alice:mailto:alice@example.com", "X-ENC-KEEP:yes"} {
		if !strings.Contains(plain, want) {
			t.Errorf("encrypted card missing %q:\n%s", want, plain)
		}
	}
	if strings.Contains(plain, "SUMMARY:Weekly Sync\r\n") {
		t.Errorf("old SUMMARY survived:\n%s", plain)
	}
}

// TestDiffCalendarPatch: STATUS/TRANSP compared with defaults applied — a card
// without STATUS equals CONFIRMED, an empty input too; only an EFFECTIVE
// different value produces a touch-up.
func TestDiffCalendarPatch(t *testing.T) {
	cur := &Event{} // card without STATUS/TRANSP = defaults
	if p := diffCalendarPatch(cur, EventInput{}); !p.empty() {
		t.Errorf("defaults vs defaults produced a patch: %+v", p)
	}
	if p := diffCalendarPatch(cur, EventInput{Status: "CONFIRMED", Transp: "OPAQUE"}); !p.empty() {
		t.Errorf("explicit defaults produced a patch: %+v", p)
	}
	p := diffCalendarPatch(cur, EventInput{Status: "CANCELLED"})
	if p.set["STATUS"] != ":CANCELLED" {
		t.Errorf("STATUS patch = %+v", p)
	}
	if _, has := p.set["TRANSP"]; has {
		t.Errorf("TRANSP patched although unchanged: %+v", p)
	}
	// Back to default from CANCELLED: rewritten to CONFIRMED.
	p = diffCalendarPatch(&Event{Status: "CANCELLED", Transp: "TRANSPARENT"}, EventInput{})
	if p.set["STATUS"] != ":CONFIRMED" || p.set["TRANSP"] != ":OPAQUE" {
		t.Errorf("back-to-default patch = %+v", p)
	}
}

// TestUpdateBodyStatusAndNotifications: the update patches the signed calendar
// card (STATUS/TRANSP) and computes the Notifications column without degrading
// the tri-state — while never touching the shared cards.
func TestUpdateBodyStatusAndNotifications(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	sharedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-m4\r\n" +
		"DTSTART:20220307T090000Z\r\n" +
		"DTEND:20220307T100000Z\r\n" +
		"SEQUENCE:0\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"
	calCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-m4\r\n" +
		"STATUS:CONFIRMED\r\n" +
		"TRANSP:OPAQUE\r\n" +
		"X-CAL-KEEP:yes\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"

	row := &eventRow{
		CalendarEvent: papi.CalendarEvent{
			ID: "row-m4", UID: "uid-m4",
			StartTime: time.Date(2022, 3, 7, 9, 0, 0, 0, time.UTC).Unix(),
			EndTime:   time.Date(2022, 3, 7, 10, 0, 0, 0, time.UTC).Unix(),
			SharedEvents: []papi.CalendarEventPart{
				{Type: papi.CalendarEventTypeSigned, Data: sharedCard},
			},
			CalendarEvents: []papi.CalendarEventPart{
				{Type: papi.CalendarEventTypeSigned, Data: calCard},
			},
		},
		Notifications: json.RawMessage("null"),
	}
	cur := decryptEvent(row.CalendarEvent, calKR)
	if cur.Status != "CONFIRMED" || cur.Transp != "OPAQUE" {
		t.Fatalf("fixture status/transp = %q/%q", cur.Status, cur.Transp)
	}

	in := EventInput{
		Start: cur.Start, End: cur.End,
		Status: "CANCELLED", Transp: "TRANSPARENT",
		Notifications: []Notification{{Type: NotificationDevice, Trigger: "-PT15M"}},
	}
	body, err := buildUpdateBody(row, &cur, in, calKR, signerKR, nil)
	if err != nil {
		t.Fatalf("buildUpdateBody: %v", err)
	}

	// Calendar card patched: STATUS/TRANSP rewritten, X- kept.
	calData := body.CalendarEventContent[0].Data
	for _, want := range []string{"STATUS:CANCELLED", "TRANSP:TRANSPARENT", "X-CAL-KEEP:yes"} {
		if !strings.Contains(calData, want) {
			t.Errorf("calendar card missing %q:\n%s", want, calData)
		}
	}
	if strings.Contains(calData, "STATUS:CONFIRMED") {
		t.Errorf("old STATUS survived:\n%s", calData)
	}
	// The shared card did NOT receive the calendar patch.
	if strings.Contains(body.SharedEventContent[0].Data, "STATUS:") {
		t.Errorf("shared card polluted by STATUS:\n%s", body.SharedEventContent[0].Data)
	}
	// Notifications: null -> explicit array (alarm added).
	var notifs []Notification
	if err := json.Unmarshal(body.Notifications, &notifs); err != nil || len(notifs) != 1 || notifs[0].Trigger != "-PT15M" {
		t.Errorf("Notifications = %s", body.Notifications)
	}

	// Without an alarm or status change: original column and card verbatim.
	same := EventInput{Start: cur.Start, End: cur.End, Status: "CONFIRMED", Transp: "OPAQUE"}
	body2, err := buildUpdateBody(row, &cur, same, calKR, signerKR, nil)
	if err != nil {
		t.Fatalf("buildUpdateBody(same): %v", err)
	}
	if string(body2.Notifications) != "null" {
		t.Errorf("unchanged notifications = %s, want null preserved", body2.Notifications)
	}
	if body2.CalendarEventContent[0].Data != calCard {
		t.Errorf("unchanged calendar card was rewritten:\n%s", body2.CalendarEventContent[0].Data)
	}
}

// TestUpdateBodySynthesizesCalendarCard: STATUS changed but NO calendar card on
// the row (events from some clients) -> a signed card is synthesized rather than
// silently losing the change.
func TestUpdateBodySynthesizesCalendarCard(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	sharedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:uid-m4b\r\n" +
		"DTSTART:20220307T090000Z\r\n" +
		"DTEND:20220307T100000Z\r\n" +
		"SEQUENCE:0\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"
	row := &eventRow{CalendarEvent: papi.CalendarEvent{
		ID: "row-m4b", UID: "uid-m4b",
		StartTime: time.Date(2022, 3, 7, 9, 0, 0, 0, time.UTC).Unix(),
		EndTime:   time.Date(2022, 3, 7, 10, 0, 0, 0, time.UTC).Unix(),
		SharedEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeSigned, Data: sharedCard},
		},
	}}
	cur := decryptEvent(row.CalendarEvent, calKR)

	in := EventInput{Start: cur.Start, End: cur.End, Status: "CANCELLED"}
	body, err := buildUpdateBody(row, &cur, in, calKR, signerKR, nil)
	if err != nil {
		t.Fatalf("buildUpdateBody: %v", err)
	}
	if len(body.CalendarEventContent) != 1 {
		t.Fatalf("got %d calendar cards, want 1 synthesized", len(body.CalendarEventContent))
	}
	part := body.CalendarEventContent[0]
	if part.Type != cardSigned {
		t.Errorf("synthesized card type = %d, want signed", part.Type)
	}
	for _, want := range []string{"UID:uid-m4b", "STATUS:CANCELLED", "TRANSP:OPAQUE"} {
		if !strings.Contains(part.Data, want) {
			t.Errorf("synthesized card missing %q:\n%s", want, part.Data)
		}
	}
	sig, err := crypto.NewPGPSignatureFromArmored(part.Signature)
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	if err := signerKR.VerifyDetached(crypto.NewPlainMessage([]byte(part.Data)), sig, crypto.GetUnixTime()); err != nil {
		t.Errorf("synthesized card signature does not cover Data bytes: %v", err)
	}

	// Without a status change: nothing is synthesized.
	body2, err := buildUpdateBody(row, &cur, EventInput{Start: cur.Start, End: cur.End}, calKR, signerKR, nil)
	if err != nil {
		t.Fatalf("buildUpdateBody(same): %v", err)
	}
	if len(body2.CalendarEventContent) != 0 {
		t.Errorf("calendar card synthesized without a status change: %+v", body2.CalendarEventContent)
	}
}

// TestUpdateRefusesDegraded: an undecryptable card forbids the re-seal
// (ErrEventDegraded -> 403 on the CalDAV side), never a silent loss.
func TestUpdateRefusesDegraded(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	otherKR := newTestKeyRing(t, "other@proton.test")
	kp, data, _, err := encryptAndSign("BEGIN:VEVENT\r\nUID:u\r\nEND:VEVENT", otherKR, otherKR)
	if err != nil {
		t.Fatalf("encryptAndSign: %v", err)
	}
	row := &eventRow{CalendarEvent: papi.CalendarEvent{
		ID: "row-bad", UID: "u",
		SharedKeyPacket: kp, // encrypted for ANOTHER calendar key
		SharedEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned, Data: data},
		},
	}}
	cur := Event{UID: "u", Start: time.Unix(0, 0), End: time.Unix(3600, 0)}
	_, err = buildUpdateBody(row, &cur, EventInput{Start: cur.Start, End: cur.End}, calKR, signerKR, nil)
	if !errors.Is(err, ErrEventDegraded) {
		t.Fatalf("err = %v, want ErrEventDegraded", err)
	}
}

// TestGetEventGoneMapsNotFound: Proton's "does not exist" (Code 2501) must
// surface as ErrEventNotFound (-> 404 CalDAV), not as a generic error (500).
func TestGetEventGoneMapsNotFound(t *testing.T) {
	fx := newFixture(t)
	_, err := fx.account.GetEvent(context.Background(), testCalID, "vanished")
	if !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("err = %v, want ErrEventNotFound", err)
	}
}

// TestBuildFragmentsExDates: the create path renders the EXDATEs in the same
// form as DTSTART.
func TestBuildFragmentsExDates(t *testing.T) {
	now := time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
	start := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	f := buildFragments("uid-ex", now, EventInput{
		UID: "uid-ex", Start: start, End: start.Add(time.Hour),
		RRule:   "FREQ=DAILY;COUNT=5",
		ExDates: []time.Time{start.Add(24 * time.Hour)},
	})
	if !strings.Contains(f.sharedSigned, "\r\nEXDATE:20260718T150000Z\r\n") {
		t.Errorf("sharedSigned missing EXDATE:\n%q", f.sharedSigned)
	}
	// Without RRULE, no orphan EXDATE.
	f2 := buildFragments("uid-ex2", now, EventInput{
		UID: "uid-ex2", Start: start, End: start.Add(time.Hour),
		ExDates: []time.Time{start.Add(24 * time.Hour)},
	})
	if strings.Contains(f2.sharedSigned, "EXDATE") {
		t.Errorf("orphan EXDATE without RRULE:\n%q", f2.sharedSigned)
	}
}

// TestUpdatePreservesAttendeesCard (anti-regression M5a): the in-place patch of
// an update NEVER touches the AttendeesEventContent card (re-sealed verbatim
// with the original shared session key) nor the cleartext Attendees array
// (tokens + Status re-emitted identically) — the attendees and their RSVPs
// survive a title update.
func TestUpdatePreservesAttendeesCard(t *testing.T) {
	calKR := newTestKeyRing(t, "cal@proton.test")
	signerKR := newTestKeyRing(t, "alice@proton.test")

	uid := "uid-att-keep"
	tok := attendeeToken(uid, "bob@example.com")
	attCard := attendeesFragment(uid,
		[]AttendeeInput{{Email: "bob@example.com", CN: "Bob"}}, []string{tok})
	signedCard := "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n" +
		"UID:" + uid + "\r\n" +
		"DTSTART:20260901T090000Z\r\n" +
		"DTEND:20260901T100000Z\r\n" +
		"ORGANIZER;CN=Alice:mailto:alice@example.com\r\n" +
		"SEQUENCE:0\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"

	// Creation-type sealing: shared (encrypted) and attendees cards on the SAME
	// session key — the shared key packet is the row's.
	frags := fragments{
		sharedSigned:    signedCard,
		sharedEncrypted: "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\nSUMMARY:Lunch\r\nEND:VEVENT\r\nEND:VCALENDAR",
		calSigned:       "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\nSTATUS:CONFIRMED\r\nEND:VEVENT\r\nEND:VCALENDAR",
		calEncrypted:    "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:" + uid + "\r\nCOMMENT:\r\nEND:VEVENT\r\nEND:VCALENDAR",
		attendees:       attCard,
	}
	sealed, err := sealCards(frags, calKR, signerKR)
	if err != nil {
		t.Fatalf("sealCards: %v", err)
	}

	row := &eventRow{CalendarEvent: papi.CalendarEvent{
		ID: "row-att-keep", UID: uid,
		StartTime:         time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC).Unix(),
		EndTime:           time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC).Unix(),
		SharedKeyPacket:   sealed.SharedKeyPacket,
		CalendarKeyPacket: sealed.CalendarKeyPacket,
		SharedEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeSigned, Data: frags.sharedSigned},
			{Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned, Data: sealed.SharedEventContent[1].Data},
		},
		CalendarEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeSigned, Data: frags.calSigned},
			{Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned, Data: sealed.CalendarEventContent[1].Data},
		},
		AttendeesEvents: []papi.CalendarEventPart{
			{Type: papi.CalendarEventTypeEncrypted | papi.CalendarEventTypeSigned, Data: sealed.AttendeesEventContent[0].Data},
		},
		Attendees: []papi.CalendarAttendee{{Token: tok, Status: papi.CalendarAttendeeStatusYes}},
	}}
	cur := decryptEvent(row.CalendarEvent, calKR)
	if cur.DecryptFailed {
		t.Fatal("fixture must decrypt cleanly")
	}

	// Update: ONLY the title changes.
	in := EventInput{
		Title: "Lunch (moved)",
		Start: cur.Start, End: cur.End,
	}
	body, err := buildUpdateBody(row, &cur, in, calKR, signerKR, nil)
	if err != nil {
		t.Fatalf("buildUpdateBody: %v", err)
	}

	// The re-sealed attendees card opens with the ORIGINAL key packet and
	// carries EXACTLY the same plaintext (X-PM-TOKEN included).
	if len(body.AttendeesEventContent) != 1 {
		t.Fatalf("AttendeesEventContent = %d cards, want 1", len(body.AttendeesEventContent))
	}
	att := body.AttendeesEventContent[0]
	plain, err := cardPlaintext(papi.CalendarEventPart{
		Type: papi.CalendarEventType(att.Type), Data: att.Data,
	}, sealed.SharedKeyPacket, calKR)
	if err != nil {
		t.Fatalf("re-sealed attendees card unreadable with the original key packet: %v", err)
	}
	if plain != attCard {
		t.Errorf("attendees card ALTERED by the update:\ngot  %q\nwant %q", plain, attCard)
	}
	// The cleartext array is re-emitted verbatim (token + live RSVP Status).
	var rows []attendeeRow
	if err := json.Unmarshal(body.Attendees, &rows); err != nil {
		t.Fatalf("Attendees JSON: %v (%s)", err, body.Attendees)
	}
	if len(rows) != 1 || rows[0].Token != tok || rows[0].Status != 3 {
		t.Errorf("Attendees re-emitted = %+v, want [{%s 3 null}]", rows, tok)
	}
	// And the ORGANIZER of the signed card survives the patch.
	if !strings.Contains(body.SharedEventContent[0].Data, "ORGANIZER;CN=Alice:mailto:alice@example.com") {
		t.Errorf("ORGANIZER lost in the patch:\n%s", body.SharedEventContent[0].Data)
	}
}

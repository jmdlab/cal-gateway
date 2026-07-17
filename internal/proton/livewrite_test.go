package proton

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	papi "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// TestLiveSignatureVerify is an OPT-IN test (CALGW_LIVE=1) that, via a REAL
// Proton session, redoes the read path on a created event and VERIFIES the
// detached signature of its SharedSigned card against the REAL address keys of
// the account — the definitive proof that the write signature is valid for any
// Proton client (not just that it decrypts).
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway CALGW_CALID=... CALGW_UID=... \
//	  go test ./internal/proton/ -run TestLiveSignatureVerify -v
func TestLiveSignatureVerify(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live signature check")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	calID := os.Getenv("CALGW_CALID")
	uid := os.Getenv("CALGW_UID")
	if dataDir == "" || calID == "" || uid == "" {
		t.Fatal("need CALGW_DATADIR, CALGW_CALID, CALGW_UID")
	}

	ctx := context.Background()
	// FRESH session (no cache shared with the daemon).
	acct, err := RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	eventID, found, err := acct.FindEventByUID(ctx, calID, uid)
	if err != nil || !found {
		t.Fatalf("FindEventByUID: found=%v err=%v", found, err)
	}
	raw, err := acct.client.GetCalendarEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetCalendarEvent: %v", err)
	}
	if len(raw.SharedEvents) == 0 {
		t.Fatal("event has no SharedEvents card")
	}
	signed := raw.SharedEvents[0] // signed card (UID/DTSTAMP/DTSTART/DTEND/SEQUENCE)
	if signed.Signature == "" {
		t.Fatal("SharedSigned card has no signature")
	}
	sig, err := crypto.NewPGPSignatureFromArmored(signed.Signature)
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	msg := crypto.NewPlainMessage([]byte(signed.Data))

	// The signature must verify against AT LEAST one of the real address keys.
	var ok bool
	for _, addr := range acct.addresses {
		kr := acct.addrKRs[addr.ID]
		if kr == nil {
			continue
		}
		if err := kr.VerifyDetached(msg, sig, crypto.GetUnixTime()); err == nil {
			ok = true
			t.Logf("signature verified against address %s", addr.Email)
			break
		}
	}
	if !ok {
		t.Fatal("detached signature did NOT verify against any real address key — Proton clients would reject it")
	}
}

// TestLiveUpdateRoundTrip is the OPT-IN test (CALGW_LIVE=1) of the M3 path on
// the real account: create a test recurring event → UpdateEvent (title changed
// + EXDATE added) → re-fetch/decryption (title, RRULE, EXDATE) → verification
// of the detached signature against the real address keys → DELETE →
// verification of the disappearance (ErrEventNotFound / Code 2501). NO debris:
// cleanup in defer even on failure.
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway CALGW_CALID=<cal VIDE> \
//	  go test ./internal/proton/ -run TestLiveUpdateRoundTrip -v
func TestLiveUpdateRoundTrip(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live update round-trip")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	calID := os.Getenv("CALGW_CALID")
	if dataDir == "" || calID == "" {
		t.Fatal("need CALGW_DATADIR, CALGW_CALID")
	}

	ctx := context.Background()
	acct, err := RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}

	// 1) Create: daily test recurring event.
	start := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Hour)
	in := EventInput{
		Title: "cal-gateway M3 test",
		Start: start, End: start.Add(time.Hour),
		RRule: "FREQ=DAILY;COUNT=5",
	}
	eventID, err := acct.CreateEvent(ctx, calID, in)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, eventID) // no debris, even on failure
		}
	}()
	t.Logf("created event %s", eventID)

	// 2) Update: title changed + EXDATE on the 2nd occurrence (the Apple
	// "delete this occurrence" gesture).
	ex := start.Add(24 * time.Hour)
	in2 := in
	in2.Title = "cal-gateway M3 test (edited)"
	in2.ExDates = []time.Time{ex}
	if err := acct.UpdateEvent(ctx, calID, eventID, in2); err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}

	// 3) Re-fetch + decryption: title, RRULE preserved, EXDATE present.
	ev, err := acct.GetEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetEvent after update: %v", err)
	}
	if ev.DecryptFailed {
		t.Fatal("updated event does not decrypt cleanly")
	}
	if ev.Title != in2.Title {
		t.Errorf("Title = %q, want %q", ev.Title, in2.Title)
	}
	if ev.RRule != in.RRule {
		t.Errorf("RRULE = %q, want %q (lost on update?)", ev.RRule, in.RRule)
	}
	if len(ev.ExDates) != 1 || !ev.ExDates[0].Equal(ex) {
		t.Errorf("ExDates = %v, want [%v]", ev.ExDates, ex)
	}
	if ev.Sequence != 1 {
		t.Errorf("Sequence = %d, want 1", ev.Sequence)
	}

	// 4) Detached signature of the re-sealed SharedSigned card: it must verify
	// against a REAL address key (proof for any Proton client).
	raw, err := acct.client.GetCalendarEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetCalendarEvent: %v", err)
	}
	var signedPart *papi.CalendarEventPart
	for i := range raw.SharedEvents {
		if raw.SharedEvents[i].Type&papi.CalendarEventTypeEncrypted == 0 {
			signedPart = &raw.SharedEvents[i]
			break
		}
	}
	if signedPart == nil || signedPart.Signature == "" {
		t.Fatal("no signed shared card with signature after update")
	}
	sig, err := crypto.NewPGPSignatureFromArmored(signedPart.Signature)
	if err != nil {
		t.Fatalf("parse signature: %v", err)
	}
	msg := crypto.NewPlainMessage([]byte(signedPart.Data))
	verified := false
	for _, addr := range acct.addresses {
		if kr := acct.addrKRs[addr.ID]; kr != nil {
			if err := kr.VerifyDetached(msg, sig, crypto.GetUnixTime()); err == nil {
				verified = true
				break
			}
		}
	}
	if !verified {
		t.Fatal("re-sealed card signature did NOT verify against any real address key")
	}

	// 5) Delete + clean disappearance (Code 2501 → ErrEventNotFound).
	if err := acct.DeleteEvent(ctx, calID, eventID); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	deleted = true
	if _, err := acct.GetEvent(ctx, calID, eventID); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("event still readable after delete (err = %v), want ErrEventNotFound", err)
	}
}

// liveTestCalendarPrefix anchors the live write tests on the EMPTY test
// calendar (the account's live calendar is off-limits). Overridable via
// CALGW_TEST_CALID_PREFIX; falls back to "TEST".
var liveTestCalendarPrefix = func() string {
	if p := os.Getenv("CALGW_TEST_CALID_PREFIX"); p != "" {
		return p
	}
	return "TEST"
}()

// resolveLiveTestCalendar resolves the test calendar by ID prefix — the
// absolute guardrail of the live write tests (not an env var that could point
// at the live calendar by mistake).
func resolveLiveTestCalendar(t *testing.T, ctx context.Context, acct *Account) string {
	t.Helper()
	cals, err := acct.ListCalendars(ctx)
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	for _, c := range cals {
		if strings.HasPrefix(c.ID, liveTestCalendarPrefix) {
			return c.ID
		}
	}
	t.Fatalf("no calendar with ID prefix %q (test calendar missing?)", liveTestCalendarPrefix)
	return ""
}

// TestLiveTZIDCardForm is the OPT-IN test (CALGW_LIVE=1) of the FORM written
// into the Proton cards (DST fix 2026-07-16): create a TZID Europe/Paris
// recurring event → the SharedSigned card carries DTSTART;TZID=Europe/Paris
// (wall-clock time); update adding an EXDATE in Z form (empty TZID — what Apple
// used to return back in the bare-UTC days) → the anti-regression guard
// (writeTZ) rewrites the EXDATE in the ORIGINAL zone: the re-read card carries
// EXDATE;TZID=Europe/Paris, NEVER a bare Z (the recurring-master corruption
// case). DELETE + disappearance (2501). Test calendar resolved by ID prefix
// (see liveTestCalendarPrefix); no debris (cleanup in defer even on failure).
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//	  go test ./internal/proton/ -run TestLiveTZIDCardForm -v
func TestLiveTZIDCardForm(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live TZID card-form round-trip")
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

	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}

	// 1) Create: weekly recurring event in TZID Europe/Paris.
	start := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Hour)
	in := EventInput{
		Title: "cal-gateway TZ card test",
		Start: start, End: start.Add(time.Hour),
		TZID:  "Europe/Paris",
		RRule: "FREQ=WEEKLY;COUNT=8",
	}
	eventID, err := acct.CreateEvent(ctx, calID, in)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, eventID) // no debris, even on failure
		}
	}()

	// sharedCard re-reads the RAW SharedSigned card (signed plaintext) of the
	// row — this is the form actually stored in Proton. Content is 100%
	// synthetic (test event), no risk of personal data.
	sharedCard := func() string {
		raw, gerr := acct.client.GetCalendarEvent(ctx, calID, eventID)
		if gerr != nil {
			t.Fatalf("GetCalendarEvent: %v", gerr)
		}
		for i := range raw.SharedEvents {
			if raw.SharedEvents[i].Type&papi.CalendarEventTypeEncrypted == 0 {
				return raw.SharedEvents[i].Data
			}
		}
		t.Fatal("no signed shared card on the row")
		return ""
	}
	card := sharedCard()
	wantStart := "DTSTART;TZID=Europe/Paris:" + start.In(paris).Format("20060102T150405")
	if !strings.Contains(card, wantStart) {
		t.Fatalf("creation: card without %q:\n%s", wantStart, card)
	}

	// 2) Update in Z FORM (empty TZID): instant unchanged + EXDATE added —
	// the guard must write the EXDATE in the ORIGINAL zone, not as a bare Z.
	ex := start.AddDate(0, 0, 7)
	in2 := in
	in2.TZID = ""
	in2.ExDates = []time.Time{ex}
	if err := acct.UpdateEvent(ctx, calID, eventID, in2); err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	card = sharedCard()
	wantEx := "EXDATE;TZID=Europe/Paris:" + ex.In(paris).Format("20060102T150405")
	if !strings.Contains(card, wantEx) {
		t.Errorf("card without %q (writeTZ guard):\n%s", wantEx, card)
	}
	if strings.Contains(card, "EXDATE:") {
		t.Errorf("bare Z reintroduced into the card (auto-corruption):\n%s", card)
	}
	if !strings.Contains(card, wantStart) {
		t.Errorf("DTSTART lost its TZID form:\n%s", card)
	}

	// 3) Decrypted re-read: exact EXDATE instant (DST-correct).
	ev, err := acct.GetEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if len(ev.ExDates) != 1 || !ev.ExDates[0].Equal(ex) {
		t.Errorf("ExDates = %v, want [%v]", ev.ExDates, ex)
	}
	if ev.TZ != "Europe/Paris" {
		t.Errorf("StartTimezone column = %q, want Europe/Paris", ev.TZ)
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

// TestLivePropertyFidelity is the OPT-IN test (CALGW_LIVE=1) of M4 property
// fidelity on the real account: create with VALARM (-15 min) +
// STATUS:CANCELLED (TENTATIVE is REJECTED by the server — "Unknown
// EventStatus", verified live 2026-07-16) → raw re-read (Notifications column +
// STATUS card) → update (alarm -30 min, STATUS:CONFIRMED) → delete →
// disappearance. NO debris: cleanup in defer even on failure. The target
// calendar is resolved by ID prefix (liveTestCalendarPrefix) — no CALGW_CALID
// to provide.
//
//	CALGW_LIVE=1 CALGW_DATADIR=/var/lib/cal-gateway \
//	  go test ./internal/proton/ -run TestLivePropertyFidelity -v
func TestLivePropertyFidelity(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live property-fidelity round-trip")
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

	// Test calendar resolution — the guardrail is the ID prefix, not an env var
	// that could point at the live calendar by mistake.
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

	// 1) Create: VALARM -15 min + STATUS:CANCELLED (the other value accepted by
	// the server alongside CONFIRMED).
	start := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Hour)
	in := EventInput{
		Title:         "cal-gateway M4 fidelity test",
		Start:         start,
		End:           start.Add(time.Hour),
		Status:        "CANCELLED",
		Transp:        "TRANSPARENT",
		Notifications: []Notification{{Type: NotificationDevice, Trigger: "-PT15M"}},
	}
	eventID, err := acct.CreateEvent(ctx, calID, in)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, eventID) // no debris, even on failure
		}
	}()
	t.Logf("created event %s on calendar %s…", eventID, calID[:6])

	// 2) Re-read: the Notifications column and the signed calendar card must
	// carry exactly what we wrote.
	ev, err := acct.GetEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetEvent: %v", err)
	}
	if ev.DecryptFailed {
		t.Fatal("created event does not decrypt cleanly")
	}
	if ev.Status != "CANCELLED" || ev.Transp != "TRANSPARENT" {
		t.Errorf("Status/Transp = %q/%q, want CANCELLED/TRANSPARENT", ev.Status, ev.Transp)
	}
	if len(ev.Notifications) != 1 ||
		ev.Notifications[0].Type != NotificationDevice ||
		ev.Notifications[0].Trigger != "-PT15M" {
		t.Errorf("Notifications = %+v, want [{DEVICE -PT15M}]", ev.Notifications)
	}

	// 3) Update: alarm -30 min + back to STATUS:CONFIRMED.
	in2 := in
	in2.Status = "CONFIRMED"
	in2.Notifications = []Notification{{Type: NotificationDevice, Trigger: "-PT30M"}}
	if err := acct.UpdateEvent(ctx, calID, eventID, in2); err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	ev2, err := acct.GetEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetEvent after update: %v", err)
	}
	if ev2.DecryptFailed {
		t.Fatal("updated event does not decrypt cleanly")
	}
	if ev2.Status != "CONFIRMED" {
		t.Errorf("Status after update = %q, want CONFIRMED", ev2.Status)
	}
	if ev2.Transp != "TRANSPARENT" {
		t.Errorf("Transp after update = %q, want TRANSPARENT (unchanged)", ev2.Transp)
	}
	if len(ev2.Notifications) != 1 || ev2.Notifications[0].Trigger != "-PT30M" {
		t.Errorf("Notifications after update = %+v, want [{DEVICE -PT30M}]", ev2.Notifications)
	}
	if ev2.Title != in.Title {
		t.Errorf("Title after update = %q, want %q (lost?)", ev2.Title, in.Title)
	}

	// 4) Delete + clean disappearance.
	if err := acct.DeleteEvent(ctx, calID, eventID); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	deleted = true
	if _, err := acct.GetEvent(ctx, calID, eventID); !errors.Is(err, ErrEventNotFound) {
		t.Fatalf("event still readable after delete (err = %v), want ErrEventNotFound", err)
	}
}

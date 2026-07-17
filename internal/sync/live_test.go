package sync

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/caldav"
	"github.com/jmdlab/cal-gateway/internal/proton"
	"github.com/jmdlab/cal-gateway/internal/store"
)

// liveTestCalendarPrefix returns the ID prefix that scopes the opt-in live
// tests to a dedicated EMPTY test calendar — NEVER the account owner's live
// calendar. Read from CALGW_TEST_CALID_PREFIX (fallback "TEST") so no real
// calendar ID is committed.
func liveTestCalendarPrefix() string {
	if p := os.Getenv("CALGW_TEST_CALID_PREFIX"); p != "" {
		return p
	}
	return "TEST"
}

// TestLiveCachedWriteThrough is the OPT-IN test (CALGW_LIVE=1) of the cache on
// the real account: initial sync → create via CachedSource → immediate read
// from the CACHE (zero API re-fetch) → delete → immediate 404 from the cache.
// ONLY on the EMPTY test calendar (ID starting with the configured prefix),
// never the main calendar. NO debris: cleanup in defer even on failure. The
// test store lives in a TempDir — session.json is NEVER rewritten by this test
// (session read only via RestoreAccount).
//
//	CALGW_LIVE=1 CALGW_DATADIR=<data-dir> CALGW_CALID=<test-calendar-id> \
//	  go test ./internal/sync/ -run TestLiveCachedWriteThrough -v
func TestLiveCachedWriteThrough(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live cached write-through")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	calID := os.Getenv("CALGW_CALID")
	if dataDir == "" || calID == "" {
		t.Fatal("need CALGW_DATADIR, CALGW_CALID")
	}
	// ABSOLUTE safeguard: never write live outside the empty test calendar
	// (resolved by the configured ID prefix) — the owner's main calendar is
	// untouchable.
	if !strings.HasPrefix(calID, liveTestCalendarPrefix()) {
		t.Fatalf("refusing: CALGW_CALID does not have the required empty-test-calendar prefix %q", liveTestCalendarPrefix())
	}

	ctx := context.Background()
	acct, err := proton.RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	cached := NewCachedSource(acct, st)
	poller := NewPoller(acct, st, time.Minute)

	// 1) Full initial sync (measures the cold-start cost).
	t0 := time.Now()
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce: %v", err)
	}
	t.Logf("initial sync: %s", time.Since(t0).Round(time.Millisecond))

	// 2) Create via the cache (write-through).
	start := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Hour)
	eventID, err := cached.CreateEvent(ctx, calID, proton.EventInput{
		Title: "cal-gateway cache test",
		Start: start, End: start.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, eventID) // no debris, even on failure
		}
	}()

	// 3) Immediate read: served by the CACHE (memory latency).
	tRead := time.Now()
	ev, err := cached.GetEvent(ctx, calID, eventID)
	if err != nil {
		t.Fatalf("GetEvent post-create from the cache: %v", err)
	}
	readLat := time.Since(tRead)
	if ev.Title != "cal-gateway cache test" {
		t.Fatalf("cached event = %+v", ev)
	}
	t.Logf("GetEvent from the cache: %s", readLat)
	if readLat > 50*time.Millisecond {
		t.Errorf("cache read abnormally slow (%s) — did it hit the API?", readLat)
	}

	// 4) Delete → immediate 404 from the cache.
	if err := cached.DeleteEvent(ctx, calID, eventID); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	deleted = true
	if _, err := cached.GetEvent(ctx, calID, eventID); !errors.Is(err, proton.ErrEventNotFound) {
		t.Fatalf("GetEvent post-delete = %v, want ErrEventNotFound", err)
	}
}

// liveCountingSource wraps the real Account and COUNTS, per call type, the
// number of fetches — the metric that proves delta polling: after the initial
// snapshot, an EMPTY cycle NEVER re-calls ListEvents (full), it only consumes
// CalendarEventChanges (1 req/calendar). Embed = all the caldav.Source +
// deltaSource methods pass through to the Account; we only intercept the three
// we care about.
type liveCountingSource struct {
	*proton.Account
	listEventsCalls int
	changesCalls    int
	latestCalls     int
}

func (c *liveCountingSource) ListEvents(ctx context.Context, calID string, start, end time.Time) ([]proton.Event, error) {
	c.listEventsCalls++
	return c.Account.ListEvents(ctx, calID, start, end)
}

func (c *liveCountingSource) CalendarEventChanges(ctx context.Context, calID, since string) (proton.CalendarDelta, error) {
	c.changesCalls++
	return c.Account.CalendarEventChanges(ctx, calID, since)
}

func (c *liveCountingSource) LatestCalendarCursor(ctx context.Context, calID string) (string, error) {
	c.latestCalls++
	return c.Account.LatestCalendarCursor(ctx, calID)
}

// TestLiveDeltaPolling is the OPT-IN test (CALGW_LIVE=1) of DELTA polling on
// the real account — the proof of the 2026-07-17 perf audit gain:
//
//  1. initial sync = full snapshot (measures the cold start) → lays the cursor;
//  2. EMPTY delta cycle → 0 ListEvents (full), ~1 CalendarEventChanges per
//     calendar, 0 event touched, near-zero wall-clock;
//  3. create via the RAW API (acct, not the cache) → the next delta cycle sees
//     it WITHOUT a full snapshot (listEventsCalls frozen);
//  4. delete via the raw API → the next delta cycle removes it.
//
// Writes confined to the empty test calendar; cleanup in defer; session.json
// never rewritten (read-only via RestoreAccount).
//
//	CALGW_LIVE=1 CALGW_DATADIR=<data-dir> CALGW_CALID=<test-calendar-id> \
//	  go test ./internal/sync/ -run TestLiveDeltaPolling -v
func TestLiveDeltaPolling(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live delta polling test")
	}
	dataDir := os.Getenv("CALGW_DATADIR")
	calID := os.Getenv("CALGW_CALID")
	if dataDir == "" || calID == "" {
		t.Fatal("need CALGW_DATADIR, CALGW_CALID")
	}
	if !strings.HasPrefix(calID, liveTestCalendarPrefix()) {
		t.Fatalf("refusing: CALGW_CALID does not have the required empty-test-calendar prefix %q", liveTestCalendarPrefix())
	}

	ctx := context.Background()
	acct, err := proton.RestoreAccount(ctx, dataDir)
	if err != nil {
		t.Fatalf("RestoreAccount: %v", err)
	}
	src := &liveCountingSource{Account: acct}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	poller := NewPoller(src, st, time.Minute)

	// 1) Initial sync = full snapshot (cold start).
	t0 := time.Now()
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce: %v", err)
	}
	fullDur := time.Since(t0)
	fullLE := src.listEventsCalls
	t.Logf("initial sync (FULL): %s — %d ListEvents, %d cursors laid", fullDur.Round(time.Millisecond), fullLE, src.latestCalls)
	if fullLE == 0 {
		t.Fatal("the initial sync must do at least one full ListEvents")
	}

	// 2) EMPTY delta cycle: no full, ~1 CalendarEventChanges/calendar.
	beforeChanges := src.changesCalls
	t1 := time.Now()
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("empty delta SyncOnce: %v", err)
	}
	emptyDur := time.Since(t1)
	emptyChanges := src.changesCalls - beforeChanges
	t.Logf("empty delta cycle: %s — %d CalendarEventChanges, 0 full (ListEvents frozen at %d)", emptyDur.Round(time.Millisecond), emptyChanges, src.listEventsCalls)
	if src.listEventsCalls != fullLE {
		t.Fatalf("the empty delta cycle redid a FULL snapshot (ListEvents %d→%d)", fullLE, src.listEventsCalls)
	}
	if emptyChanges == 0 {
		t.Fatal("the delta cycle must query CalendarEventChanges at least once")
	}
	if emptyDur > 3*time.Second {
		t.Errorf("empty delta cycle abnormally slow (%s) — ~1 req expected per calendar", emptyDur)
	}

	// 3) Create via the RAW API (bypasses the write-through cache) → seen by delta.
	start := time.Now().UTC().Add(96 * time.Hour).Truncate(time.Hour)
	eventID, err := acct.CreateEvent(ctx, calID, proton.EventInput{
		Title: "cal-gateway delta test",
		Start: start, End: start.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEvent (raw API): %v", err)
	}
	deleted := false
	defer func() {
		if !deleted {
			_ = acct.DeleteEvent(ctx, calID, eventID)
		}
	}()

	beforeLE := src.listEventsCalls
	t2 := time.Now()
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("delta SyncOnce post-create: %v", err)
	}
	t.Logf("delta cycle post-create: %s — ListEvents %d (expected frozen)", time.Since(t2).Round(time.Millisecond), src.listEventsCalls)
	if src.listEventsCalls != beforeLE {
		t.Fatalf("the create must be seen by DELTA, not a full snapshot (ListEvents %d→%d)", beforeLE, src.listEventsCalls)
	}
	if _, ok := st.Event(calID, eventID); !ok {
		t.Fatal("the event created via the raw API was not caught by the delta")
	}

	// 4) Delete via the raw API → removed by the next delta cycle.
	if err := acct.DeleteEvent(ctx, calID, eventID); err != nil {
		t.Fatalf("DeleteEvent (raw API): %v", err)
	}
	deleted = true
	beforeLE = src.listEventsCalls
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("delta SyncOnce post-delete: %v", err)
	}
	if src.listEventsCalls != beforeLE {
		t.Fatalf("the delete must go through DELTA (ListEvents %d→%d)", beforeLE, src.listEventsCalls)
	}
	if _, ok := st.Event(calID, eventID); ok {
		t.Fatal("the event deleted via the raw API stayed in the store after the delta")
	}
}

// TestLiveFoldedSeriesRoundTrip is THE live test of the M4 folding
// (CALGW_LIVE=1), at the full CalDAV level (real Backend + CachedSource + Store,
// real Proton account) — the "Error 2" bug scenario replayed end to end:
//
//  1. creation PUT of a weekly recurring event (resource name chosen by the
//     client = {uid}.ics → alias to {rowID}.ics);
//  2. folded PUT master + RECURRENCE-ID child (2nd occurrence moved by 2h)
//     → Proton exception-row created (RecurrenceID, SEQUENCE ≥ master);
//  3. re-read: ONE resource, 2 VEVENT, correct RECURRENCE-ID, no EXDATE or
//     RRULE on the child;
//  4. PUT removing the child + EXDATE on the master → exception-row deleted on
//     the Proton side (GET → 2501/ErrEventNotFound), EXDATE present;
//  5. DELETE of the resource → NO same-UID row left, zero debris.
//
// Store in a TempDir; session.json never rewritten (read-only via
// RestoreAccount). Cleanup in defer even on failure.
//
//	CALGW_LIVE=1 CALGW_DATADIR=<data-dir> \
//	  go test ./internal/sync/ -run TestLiveFoldedSeriesRoundTrip -v
func TestLiveFoldedSeriesRoundTrip(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live folded-series round-trip")
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
	// ABSOLUTE safeguard: resolution by the configured ID prefix — the owner's
	// live calendar is untouchable.
	cals, err := acct.ListCalendars(ctx)
	if err != nil {
		t.Fatalf("ListCalendars: %v", err)
	}
	calID := ""
	for _, c := range cals {
		if strings.HasPrefix(c.ID, liveTestCalendarPrefix()) {
			calID = c.ID
			break
		}
	}
	if calID == "" {
		t.Fatalf("no calendar with ID prefix %q (test calendar missing?)", liveTestCalendarPrefix())
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	cached := NewCachedSource(acct, st)
	if err := NewPoller(acct, st, time.Minute).SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce: %v", err)
	}
	backend := caldav.NewBackend(cached, "alice")
	colPath := "/alice/calendars/" + calID + "/"

	uid := "calgw-m4-fold-" + strconv.FormatInt(time.Now().Unix(), 10)
	// ABSOLUTE cleanup: any remaining same-UID row is purged in defer.
	defer func() {
		if rows, lerr := acct.ListEventsByUID(ctx, calID, uid); lerr == nil {
			for _, r := range rows {
				_ = acct.DeleteEvent(ctx, calID, r.ID)
			}
		}
	}()

	// Next Monday + 14 days, on the hour — far from any real event.
	start := time.Now().UTC().Add(14 * 24 * time.Hour).Truncate(time.Hour)
	occ2 := start.Add(7 * 24 * time.Hour) // 2nd occurrence
	fmtZ := func(ts time.Time) string { return ts.UTC().Format("20060102T150405Z") }
	decode := func(ics string) *ical.Calendar {
		cal, derr := ical.NewDecoder(strings.NewReader(ics)).Decode()
		if derr != nil {
			t.Fatalf("decode ICS: %v", derr)
		}
		return cal
	}
	masterICS := func(exdate string) string {
		s := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\n" +
			"UID:" + uid + "\r\nDTSTAMP:" + fmtZ(time.Now()) + "\r\n" +
			"DTSTART:" + fmtZ(start) + "\r\nDTEND:" + fmtZ(start.Add(time.Hour)) + "\r\n" +
			"RRULE:FREQ=WEEKLY;COUNT=6\r\nSUMMARY:calgw M4 fold test\r\n"
		if exdate != "" {
			s += "EXDATE:" + exdate + "\r\n"
		}
		return s + "END:VEVENT\r\n"
	}
	childICS := "BEGIN:VEVENT\r\n" +
		"UID:" + uid + "\r\nDTSTAMP:" + fmtZ(time.Now()) + "\r\n" +
		"RECURRENCE-ID:" + fmtZ(occ2) + "\r\n" +
		"DTSTART:" + fmtZ(occ2.Add(2*time.Hour)) + "\r\nDTEND:" + fmtZ(occ2.Add(3*time.Hour)) + "\r\n" +
		"SUMMARY:calgw M4 fold test (moved)\r\nEND:VEVENT\r\n"

	// 1) Creation PUT (client name = {uid}.ics).
	obj, err := backend.PutCalendarObject(ctx, colPath+uid+".ics", decode(masterICS("")+"END:VCALENDAR\r\n"), nil)
	if err != nil {
		t.Fatalf("creation PUT: %v", err)
	}
	anchorPath := obj.Path
	t.Logf("created: Location=%s", anchorPath)
	if strings.Contains(anchorPath, uid) {
		t.Errorf("Location must point to {rowID}.ics, not the client name: %s", anchorPath)
	}
	// The client name stays resolvable (related alias bug).
	if _, gerr := backend.GetCalendarObject(ctx, colPath+uid+".ics", nil); gerr != nil {
		t.Errorf("GET of the client name post-creation = %v, want the resource (alias)", gerr)
	}

	// 2) Folded PUT: master + RECURRENCE-ID child (moved occurrence).
	if _, err = backend.PutCalendarObject(ctx, anchorPath, decode(masterICS("")+childICS+"END:VCALENDAR\r\n"), nil); err != nil {
		t.Fatalf("folded PUT (add child): %v", err)
	}

	// 3) Re-read: ONE resource, 2 VEVENT, correct RECURRENCE-ID, no EXDATE/RRULE
	// on the child — and the AUTHORITATIVE Proton state does have 2 rows
	// (master + exception-row SEQUENCE ≥ master).
	obj, err = backend.GetCalendarObject(ctx, anchorPath, nil)
	if err != nil {
		t.Fatalf("GET post folded PUT: %v", err)
	}
	events := obj.Data.Events()
	if len(events) != 2 {
		t.Fatalf("folded resource carries %d VEVENT, want 2", len(events))
	}
	rid := events[1].Props.Get(ical.PropRecurrenceID)
	if rid == nil {
		t.Fatal("child without RECURRENCE-ID")
	}
	if got, derr := rid.DateTime(time.UTC); derr != nil || !got.Equal(occ2) {
		t.Errorf("RECURRENCE-ID = %v (%v), want %v", got, derr, occ2)
	}
	if events[1].Props.Get(ical.PropExceptionDates) != nil || events[1].Props.Get(ical.PropRecurrenceRule) != nil {
		t.Error("the child must carry neither EXDATE nor RRULE")
	}
	rows, err := acct.ListEventsByUID(ctx, calID, uid)
	if err != nil || len(rows) != 2 {
		t.Fatalf("Proton rows = %d (%v), want 2", len(rows), err)
	}
	if rows[0].RecurrenceID != 0 || rows[1].RecurrenceID != occ2.Unix() {
		t.Fatalf("RecurrenceID columns = %d/%d, want 0/%d", rows[0].RecurrenceID, rows[1].RecurrenceID, occ2.Unix())
	}
	if rows[1].Sequence < rows[0].Sequence {
		t.Errorf("exception SEQUENCE (%d) < master (%d)", rows[1].Sequence, rows[0].Sequence)
	}
	excID := rows[1].ID
	t.Logf("exception-row created: %s… (RecurrenceID=%d)", excID[:8], rows[1].RecurrenceID)

	// 4) PUT removing the child + EXDATE on the master (occurrence deleted).
	if _, err = backend.PutCalendarObject(ctx, anchorPath, decode(masterICS(fmtZ(occ2))+"END:VCALENDAR\r\n"), nil); err != nil {
		t.Fatalf("PUT remove child + EXDATE: %v", err)
	}
	if _, gerr := acct.GetEvent(ctx, calID, excID); !errors.Is(gerr, proton.ErrEventNotFound) {
		t.Fatalf("exception-row still present on the Proton side (err=%v), want 2501/ErrEventNotFound", gerr)
	}
	rows, err = acct.ListEventsByUID(ctx, calID, uid)
	if err != nil || len(rows) != 1 {
		t.Fatalf("Proton rows post-removal = %d (%v), want 1", len(rows), err)
	}
	if len(rows[0].ExDates) != 1 || !rows[0].ExDates[0].Equal(occ2) {
		t.Fatalf("master EXDATE = %v, want [%v]", rows[0].ExDates, occ2)
	}
	obj, err = backend.GetCalendarObject(ctx, anchorPath, nil)
	if err != nil || len(obj.Data.Events()) != 1 {
		t.Fatalf("re-read post-removal: %v (VEVENT=%d), want 1", err, len(obj.Data.Events()))
	}

	// 5) DELETE of the folded resource: no row left, zero debris.
	if err := backend.DeleteCalendarObject(ctx, anchorPath); err != nil {
		t.Fatalf("DELETE resource: %v", err)
	}
	rows, err = acct.ListEventsByUID(ctx, calID, uid)
	if err != nil {
		t.Fatalf("ListEventsByUID post-delete: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("debris after DELETE: %d row(s)", len(rows))
	}
	if _, gerr := backend.GetCalendarObject(ctx, anchorPath, nil); gerr == nil {
		t.Fatal("resource still served by the cache after DELETE")
	}
	t.Log("full folded round-trip: zero debris")
}

// TestLiveTimezoneRoundTrip is THE live test of TZID rendering (CALGW_LIVE=1) —
// the DST root fix (2026-07-16) replayed end to end on the real account, at the
// full CalDAV level (real Backend + CachedSource + Store):
//
//  1. creation PUT: weekly series TZID Europe/Paris anchored on a past JANUARY
//     Monday (09:00 wall = 08:00Z, winter) with a past SUMMER EXDATE (09:00
//     wall = 07:00Z), TZID forms as Apple emits them;
//  2. GET: DTSTART;TZID=Europe/Paris, VTIMEZONE block present, EXDATE in the
//     SAME form, wall-clock hours STABLE winter/summer, DST-correct instants,
//     ETag at schema v3;
//  3. update PUT adding a future EXDATE (TZID form) WITHOUT resending the past
//     EXDATE (Apple's display horizon) → Proton re-read: the past history
//     SURVIVED (anti-overwrite guard) and both instants are DST-correct;
//  4. DELETE → no same-UID row left (2501/ErrEventNotFound), zero debris.
//
// Store in a TempDir; session.json never rewritten (read-only via
// RestoreAccount). ABSOLUTE safeguard: calendar resolved by the configured ID
// prefix — the owner's live calendar is untouchable. Cleanup in defer even on
// failure.
//
//	CALGW_LIVE=1 CALGW_DATADIR=<data-dir> \
//	  go test ./internal/sync/ -run TestLiveTimezoneRoundTrip -v
func TestLiveTimezoneRoundTrip(t *testing.T) {
	if os.Getenv("CALGW_LIVE") == "" {
		t.Skip("set CALGW_LIVE=1 to run the live timezone round-trip")
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
		if strings.HasPrefix(c.ID, liveTestCalendarPrefix()) {
			calID = c.ID
			break
		}
	}
	if calID == "" {
		t.Fatalf("no calendar with ID prefix %q (test calendar missing?)", liveTestCalendarPrefix())
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	cached := NewCachedSource(acct, st)
	if err := NewPoller(acct, st, time.Minute).SyncOnce(ctx); err != nil {
		t.Fatalf("initial SyncOnce: %v", err)
	}
	backend := caldav.NewBackend(cached, "alice")
	colPath := "/alice/calendars/" + calID + "/"

	paris, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		t.Fatalf("LoadLocation: %v", err)
	}
	now := time.Now().UTC()
	// Year anchored to GUARANTEE strictly past July Mondays (the "historical"
	// summer EXDATE of the guard).
	year := now.Year()
	if now.Month() < time.August {
		year--
	}
	// First Monday of January, 09:00 Paris wall time (winter).
	masterStart := time.Date(year, time.January, 1, 9, 0, 0, 0, paris)
	for masterStart.Weekday() != time.Monday {
		masterStart = masterStart.AddDate(0, 0, 1)
	}
	// Weekly step in WALL time (AddDate in local zone crosses DST): first Monday
	// of July = past summer EXDATE, then first strictly-future occurrence =
	// EXDATE added at the update (on the "master client" side).
	exPast := masterStart
	for exPast.Month() != time.July {
		exPast = exPast.AddDate(0, 0, 7)
	}
	exFuture := exPast
	for !exFuture.After(now.Add(48 * time.Hour)) {
		exFuture = exFuture.AddDate(0, 0, 7)
	}
	// Fixture safeguard: winter and summer must have different offsets.
	_, offWinter := masterStart.Zone()
	_, offSummer := exPast.Zone()
	if offWinter == offSummer {
		t.Fatalf("fixture without DST (offsets %d/%d)", offWinter, offSummer)
	}
	until := exFuture.AddDate(0, 0, 60)

	uid := "calgw-tz-" + strconv.FormatInt(now.Unix(), 10)
	defer func() {
		if rows, lerr := acct.ListEventsByUID(ctx, calID, uid); lerr == nil {
			for _, r := range rows {
				_ = acct.DeleteEvent(ctx, calID, r.ID) // no debris, even on failure
			}
		}
	}()

	local := func(ts time.Time) string { return ts.In(paris).Format("20060102T150405") }
	masterICS := func(exdates ...time.Time) string {
		s := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n" +
			"BEGIN:VEVENT\r\nUID:" + uid + "\r\nDTSTAMP:" + now.Format("20060102T150405Z") + "\r\n" +
			"DTSTART;TZID=Europe/Paris:" + local(masterStart) + "\r\n" +
			"DTEND;TZID=Europe/Paris:" + local(masterStart.Add(time.Hour)) + "\r\n" +
			"RRULE:FREQ=WEEKLY;BYDAY=MO;UNTIL=" + until.UTC().Format("20060102T150405Z") + "\r\n"
		for _, ex := range exdates {
			s += "EXDATE;TZID=Europe/Paris:" + local(ex) + "\r\n"
		}
		return s + "SUMMARY:calgw TZ fix test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	}
	decode := func(ics string) *ical.Calendar {
		cal, derr := ical.NewDecoder(strings.NewReader(ics)).Decode()
		if derr != nil {
			t.Fatalf("decode ICS: %v", derr)
		}
		return cal
	}

	// 1) Creation PUT: past summer EXDATE.
	obj, err := backend.PutCalendarObject(ctx, colPath+uid+".ics", decode(masterICS(exPast)), nil)
	if err != nil {
		t.Fatalf("creation PUT: %v", err)
	}
	anchorPath := obj.Path
	t.Logf("created: Location=%s", anchorPath)

	// 2) GET: TZID form + VTIMEZONE + stable wall-clock hours + ETag v2.
	obj, err = backend.GetCalendarObject(ctx, anchorPath, nil)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	events := obj.Data.Events()
	if len(events) != 1 {
		t.Fatalf("GET carries %d VEVENT, want 1", len(events))
	}
	startProp := events[0].Props.Get(ical.PropDateTimeStart)
	if startProp == nil || startProp.Params.Get(ical.ParamTimezoneID) != "Europe/Paris" || startProp.Value != local(masterStart) {
		t.Errorf("DTSTART = %+v, want TZID=Europe/Paris:%s", startProp, local(masterStart))
	}
	exProps := events[0].Props[ical.PropExceptionDates]
	if len(exProps) != 1 || exProps[0].Params.Get(ical.ParamTimezoneID) != "Europe/Paris" || exProps[0].Value != local(exPast) {
		t.Errorf("EXDATE = %+v, want TZID=Europe/Paris:%s (stable summer wall time)", exProps, local(exPast))
	}
	if gotStart, perr := startProp.DateTime(time.UTC); perr != nil || !gotStart.Equal(masterStart) {
		t.Errorf("DTSTART instant = %v (%v), want %v", gotStart, perr, masterStart)
	}
	if gotEx, perr := exProps[0].DateTime(time.UTC); perr != nil || !gotEx.Equal(exPast) {
		t.Errorf("EXDATE instant = %v (%v), want %v — DST divergence", gotEx, perr, exPast)
	}
	hasVTZ := false
	for _, comp := range obj.Data.Children {
		if comp.Name == ical.CompTimezone {
			hasVTZ = true
		}
	}
	if !hasVTZ {
		t.Error("VTIMEZONE absent from the served resource")
	}
	if !strings.HasPrefix(obj.ETag, "v3-") {
		t.Errorf("ETag = %q, want schema v3 (client self-healing)", obj.ETag)
	}
	t.Logf("GET: DTSTART;TZID winter %s / EXDATE summer %s, stable wall-clock, VTIMEZONE ok", local(masterStart), local(exPast))

	// 3) Update PUT: ONLY the future EXDATE (Apple's horizon purged the past) →
	// the guard keeps the history, the client stays master of the future.
	if _, err := backend.PutCalendarObject(ctx, anchorPath, decode(masterICS(exFuture)), nil); err != nil {
		t.Fatalf("update PUT EXDATE: %v", err)
	}
	rows, err := acct.ListEventsByUID(ctx, calID, uid)
	if err != nil || len(rows) != 1 {
		t.Fatalf("Proton rows = %d (%v), want 1", len(rows), err)
	}
	rowID := rows[0].ID
	if len(rows[0].ExDates) != 2 {
		t.Fatalf("Proton ExDates = %v, want [past kept + client's future]", rows[0].ExDates)
	}
	seen := map[int64]bool{}
	for _, ex := range rows[0].ExDates {
		seen[ex.Unix()] = true
	}
	if !seen[exPast.Unix()] || !seen[exFuture.Unix()] {
		t.Errorf("ExDates = %v, want DST-correct instants %v and %v", rows[0].ExDates, exPast.UTC(), exFuture.UTC())
	}

	// 4) DELETE: no row left, 2501 on direct re-read.
	if err := backend.DeleteCalendarObject(ctx, anchorPath); err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	if rows, err := acct.ListEventsByUID(ctx, calID, uid); err != nil || len(rows) != 0 {
		t.Fatalf("debris after DELETE: %d row(s) (%v)", len(rows), err)
	}
	if _, gerr := acct.GetEvent(ctx, calID, rowID); !errors.Is(gerr, proton.ErrEventNotFound) {
		t.Fatalf("GetEvent post-delete = %v, want ErrEventNotFound (2501)", gerr)
	}
	t.Log("full TZID round-trip: stable forms, EXDATE history preserved, zero debris")
}

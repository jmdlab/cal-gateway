package sync

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	gosync "sync" // the package is already named sync — alias required
	"testing"
	"time"

	"github.com/emersion/go-ical"

	"github.com/jmdlab/cal-gateway/internal/caldav"
	"github.com/jmdlab/cal-gateway/internal/proton"
	"github.com/jmdlab/cal-gateway/internal/store"
)

// fakeSource simulates the real Proton Source (backend tests pattern) and
// COUNTS the reads — the central property to prove is "zero API call on a
// client read request".
type fakeSource struct {
	calendars []proton.Calendar
	events    map[string]map[string]proton.Event // calID -> eventID -> event

	listCalendarsCalls int
	listEventsCalls    int
	getEventCalls      int

	nextID int

	// onListEvents is called during ListEvents — lets us simulate a concurrent
	// write-through in the middle of a poller cycle fetch.
	onListEvents func()

	failGetEvent     bool  // force the post-write re-read to fail
	listCalendarsErr error // force ListCalendars to fail
	listEventsErr    error // force ListEvents to fail (partial poller cycle)

	// onCreateEvent is called at the start of CreateEvent — lets us prove write
	// serialization (two concurrent creates of the same UID).
	onCreateEvent func()

	mu gosync.Mutex // protects events/nextID on the concurrent tests
}

var _ caldav.Source = (*fakeSource)(nil)

func (f *fakeSource) ListCalendars(ctx context.Context) ([]proton.Calendar, error) {
	f.listCalendarsCalls++
	if f.listCalendarsErr != nil {
		return nil, f.listCalendarsErr
	}
	return f.calendars, nil
}

func (f *fakeSource) ListEvents(ctx context.Context, calID string, start, end time.Time) ([]proton.Event, error) {
	f.listEventsCalls++
	if f.listEventsErr != nil {
		return nil, f.listEventsErr
	}
	if f.onListEvents != nil {
		f.onListEvents()
	}
	var out []proton.Event
	for _, ev := range f.events[calID] {
		out = append(out, ev)
	}
	return out, nil
}

func (f *fakeSource) GetEvent(ctx context.Context, calID, eventID string) (*proton.Event, error) {
	f.getEventCalls++
	if f.failGetEvent {
		return nil, errors.New("fake: re-read unavailable")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ev, ok := f.events[calID][eventID]
	if !ok {
		return nil, fmt.Errorf("fake: %w", proton.ErrEventNotFound)
	}
	return &ev, nil
}

func (f *fakeSource) CreateEvent(ctx context.Context, calID string, in proton.EventInput) (string, error) {
	if f.onCreateEvent != nil {
		f.onCreateEvent()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	id := fmt.Sprintf("proton-ev-%d", f.nextID)
	if f.events == nil {
		f.events = map[string]map[string]proton.Event{}
	}
	if f.events[calID] == nil {
		f.events[calID] = map[string]proton.Event{}
	}
	f.events[calID][id] = proton.Event{
		ID: id, UID: in.UID, CalendarID: calID,
		Title: in.Title, Start: in.Start, End: in.End,
		RRule: in.RRule, ExDates: in.ExDates,
		LastEdit: time.Now().UTC(),
	}
	return id, nil
}

// ListEventsByUID / AuthoritativeEventsByUID: same content on the fake — the
// listEventsCalls counter traces the "API" access of the authoritative path.
func (f *fakeSource) ListEventsByUID(ctx context.Context, calID, uid string) ([]proton.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []proton.Event
	for _, ev := range f.events[calID] {
		if ev.UID == uid {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (f *fakeSource) AuthoritativeEventsByUID(ctx context.Context, calID, uid string) ([]proton.Event, error) {
	f.listEventsCalls++
	return f.ListEventsByUID(ctx, calID, uid)
}

func (f *fakeSource) UpdateEvent(ctx context.Context, calID, eventID string, in proton.EventInput) error {
	ev, ok := f.events[calID][eventID]
	if !ok {
		return fmt.Errorf("fake: %w", proton.ErrEventNotFound)
	}
	ev.Title, ev.Start, ev.End = in.Title, in.Start, in.End
	ev.RRule, ev.ExDates = in.RRule, in.ExDates
	ev.Sequence++
	ev.LastEdit = time.Now().UTC()
	f.events[calID][eventID] = ev
	return nil
}

func (f *fakeSource) DeleteEvent(ctx context.Context, calID, eventID string) error {
	if _, ok := f.events[calID][eventID]; !ok {
		return fmt.Errorf("fake: %w", proton.ErrEventNotFound)
	}
	delete(f.events[calID], eventID)
	return nil
}

func newTestStack(t *testing.T) (*fakeSource, *store.Store, *CachedSource, *Poller) {
	t.Helper()
	now := time.Now().UTC()
	src := &fakeSource{
		calendars: []proton.Calendar{{ID: "cal1", Name: "Family"}},
		events: map[string]map[string]proton.Event{
			"cal1": {
				"seed1": {ID: "seed1", UID: "seed1@p", CalendarID: "cal1", Title: "seed",
					Start: now, End: now.Add(time.Hour), LastEdit: now},
			},
		},
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return src, st, NewCachedSource(src, st), NewPoller(src, st, time.Minute)
}

// TestReadsNeverHitSource: after the initial sync, all reads are served from
// the store — zero call to the real Source (the property that kills the
// dataaccessd timeout).
func TestReadsNeverHitSource(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)

	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	base := src.listCalendarsCalls + src.listEventsCalls + src.getEventCalls

	cals, err := cached.ListCalendars(ctx)
	if err != nil || len(cals) != 1 {
		t.Fatalf("ListCalendars = %v, %v", cals, err)
	}
	now := time.Now().UTC()
	evs, err := cached.ListEvents(ctx, "cal1", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil || len(evs) != 1 || evs[0].ID != "seed1" {
		t.Fatalf("ListEvents = %v, %v", evs, err)
	}
	if _, err := cached.GetEvent(ctx, "cal1", "seed1"); err != nil {
		t.Fatalf("GetEvent: %v", err)
	}

	if got := src.listCalendarsCalls + src.listEventsCalls + src.getEventCalls; got != base {
		t.Fatalf("the reads hit the real Source (%d extra API calls)", got-base)
	}
}

// TestWriteThroughCreate: a CreateEvent is visible in the cache BEFORE
// answering (Apple re-reads immediately after the PUT).
func TestWriteThroughCreate(t *testing.T) {
	ctx := context.Background()
	_, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	id, err := cached.CreateEvent(ctx, "cal1", proton.EventInput{
		UID: "new@apple", Title: "appt", Start: now, End: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	ev, err := cached.GetEvent(ctx, "cal1", id)
	if err != nil {
		t.Fatalf("GetEvent immediately post-create: %v (stale cache)", err)
	}
	if ev.Title != "appt" || ev.UID != "new@apple" {
		t.Fatalf("cached event = %+v", ev)
	}
}

// TestWriteThroughUpdate: the update is visible immediately, fresh ETag.
func TestWriteThroughUpdate(t *testing.T) {
	ctx := context.Background()
	_, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	before, _ := cached.GetEvent(ctx, "cal1", "seed1")

	now := time.Now().UTC()
	err := cached.UpdateEvent(ctx, "cal1", "seed1", proton.EventInput{
		UID: "seed1@p", Title: "seed (edited)", Start: now, End: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("UpdateEvent: %v", err)
	}
	after, err := cached.GetEvent(ctx, "cal1", "seed1")
	if err != nil {
		t.Fatalf("GetEvent post-update: %v", err)
	}
	if after.Title != "seed (edited)" {
		t.Fatalf("title not reflected: %q (stale cache)", after.Title)
	}
	if !after.LastEdit.After(before.LastEdit) {
		t.Fatal("LastEdit (ETag) must advance after update")
	}
}

// TestWriteThroughDelete: GetEvent of a deleted event answers ErrEventNotFound
// IMMEDIATELY after the DELETE — from the cache.
func TestWriteThroughDelete(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if err := cached.DeleteEvent(ctx, "cal1", "seed1"); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	base := src.getEventCalls
	if _, err := cached.GetEvent(ctx, "cal1", "seed1"); !errors.Is(err, proton.ErrEventNotFound) {
		t.Fatalf("GetEvent post-delete = %v, want ErrEventNotFound", err)
	}
	if src.getEventCalls != base {
		t.Fatal("the post-delete 404 must come from the cache, not the API")
	}
	now := time.Now().UTC()
	if evs, _ := cached.ListEvents(ctx, "cal1", now.Add(-time.Hour), now.Add(time.Hour)); len(evs) != 0 {
		t.Fatalf("deleted event still listed: %v", evs)
	}
}

// TestWriteThroughSynthFallback: if the post-write re-read fails, the cache is
// populated by synthesizing from the input — never left stale.
func TestWriteThroughSynthFallback(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	src.failGetEvent = true
	now := time.Now().UTC().Truncate(time.Second)
	id, err := cached.CreateEvent(ctx, "cal1", proton.EventInput{
		UID: "synth@apple", Title: "fallback", Start: now, End: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	src.failGetEvent = false

	ev, err := cached.GetEvent(ctx, "cal1", id)
	if err != nil {
		t.Fatalf("GetEvent post-create (synthesis): %v", err)
	}
	if ev.Title != "fallback" || ev.UID != "synth@apple" || !ev.Start.Equal(now) {
		t.Fatalf("synthesized event = %+v", ev)
	}
}

// TestPollerDoesNotResurrectDeletes: a write-through delete during a poller
// cycle's fetch must NOT be overwritten by the stale snapshot.
func TestPollerDoesNotResurrectDeletes(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// During the next cycle's fetch, the client deletes seed1. The fake
	// snapshots BEFORE the hook (worst case: the poller's snapshot still
	// contains seed1).
	src.onListEvents = func() {
		src.onListEvents = nil // only once
		if err := cached.DeleteEvent(ctx, "cal1", "seed1"); err != nil {
			t.Errorf("concurrent DeleteEvent: %v", err)
		}
		// Re-inject seed1 into the fake AFTER the delete to materialize a stale
		// snapshot that still contains it.
		src.events["cal1"]["seed1"] = proton.Event{
			ID: "seed1", UID: "seed1@p", CalendarID: "cal1", Title: "seed",
			Start: time.Now().UTC(), End: time.Now().UTC().Add(time.Hour),
		}
	}
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
	if _, err := cached.GetEvent(ctx, "cal1", "seed1"); !errors.Is(err, proton.ErrEventNotFound) {
		t.Fatalf("seed1 resurrected by the stale snapshot (err=%v)", err)
	}

	// The next cycle (fresh generation) reconciles with the Proton state.
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.GetEvent(ctx, "cal1", "seed1"); err != nil {
		t.Fatalf("the next cycle must reconcile: %v", err)
	}
}

// TestPollerRefreshesCalendarsAndEvents: the cycle replaces the calendar list
// and the content per calendar.
func TestPollerRefreshesCalendarsAndEvents(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Changes on the Proton side: seed1 renamed, cal2 added.
	ev := src.events["cal1"]["seed1"]
	ev.Title = "renamed upstream"
	src.events["cal1"]["seed1"] = ev
	src.calendars = append(src.calendars, proton.Calendar{ID: "cal2", Name: "Shared"})
	src.events["cal2"] = map[string]proton.Event{}

	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	cals, _ := cached.ListCalendars(ctx)
	if len(cals) != 2 {
		t.Fatalf("Calendars = %v, want 2", cals)
	}
	got, err := cached.GetEvent(ctx, "cal1", "seed1")
	if err != nil || got.Title != "renamed upstream" {
		t.Fatalf("GetEvent post-refresh = %+v, %v", got, err)
	}
}

// TestWriteThroughDeleteSeries: deleting a MASTER purges the whole same-UID
// group from the cache — mirror of the Proton batch-delete, otherwise the
// exception-rows stay served as debris ("Error 2").
func TestWriteThroughDeleteSeries(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	now := time.Now().UTC()
	occ := now.Add(7 * 24 * time.Hour)
	src.events["cal1"]["rec1"] = proton.Event{
		ID: "rec1", UID: "series@p", CalendarID: "cal1", Title: "series",
		Start: now, End: now.Add(time.Hour), RRule: "FREQ=WEEKLY", LastEdit: now,
	}
	src.events["cal1"]["exc1"] = proton.Event{
		ID: "exc1", UID: "series@p", CalendarID: "cal1", Title: "series (moved)",
		Start: occ.Add(2 * time.Hour), End: occ.Add(3 * time.Hour),
		RecurrenceID: occ.Unix(), LastEdit: now,
	}
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// The fake deletes ONLY the targeted row (worst case: no batch on the source
	// side) — the cache must still purge the whole group.
	if err := cached.DeleteEvent(ctx, "cal1", "rec1"); err != nil {
		t.Fatalf("DeleteEvent: %v", err)
	}
	if rows, _ := cached.ListEventsByUID(ctx, "cal1", "series@p"); len(rows) != 0 {
		t.Fatalf("same-UID debris in the cache after deleting master: %+v", rows)
	}
	if _, err := cached.GetEvent(ctx, "cal1", "exc1"); !errors.Is(err, proton.ErrEventNotFound) {
		t.Fatalf("exception still served after deleting the master: %v", err)
	}
}

// TestWriteThroughDeleteExceptionOnly: deleting an exception-row alone does NOT
// touch the master.
func TestWriteThroughDeleteExceptionOnly(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	now := time.Now().UTC()
	occ := now.Add(7 * 24 * time.Hour)
	src.events["cal1"]["rec1"] = proton.Event{
		ID: "rec1", UID: "series@p", CalendarID: "cal1",
		Start: now, End: now.Add(time.Hour), RRule: "FREQ=WEEKLY", LastEdit: now,
	}
	src.events["cal1"]["exc1"] = proton.Event{
		ID: "exc1", UID: "series@p", CalendarID: "cal1",
		Start: occ, End: occ.Add(time.Hour), RecurrenceID: occ.Unix(), LastEdit: now,
	}
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cached.DeleteEvent(ctx, "cal1", "exc1"); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.GetEvent(ctx, "cal1", "rec1"); err != nil {
		t.Fatalf("master wrongly purged by deleting an exception: %v", err)
	}
}

// TestAliasCreateResolvable: after a creation PUT via the backend (resource
// name chosen by the client ≠ rowID), the original name stays resolvable on
// GET — the related 201+Location bug (dataaccessd re-GETs the original name
// before it integrated the Location).
func TestAliasCreateResolvable(t *testing.T) {
	ctx := context.Background()
	_, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	backend := caldav.NewBackend(cached, "alice")

	now := time.Now().UTC().Truncate(time.Hour).Add(48 * time.Hour)
	ics := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\n" +
		"UID:client-uid-1\r\nDTSTAMP:" + now.Format("20060102T150405Z") + "\r\n" +
		"DTSTART:" + now.Format("20060102T150405Z") + "\r\n" +
		"DTEND:" + now.Add(time.Hour).Format("20060102T150405Z") + "\r\n" +
		"SUMMARY:alias\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
	cal, err := ical.NewDecoder(strings.NewReader(ics)).Decode()
	if err != nil {
		t.Fatal(err)
	}
	obj, err := backend.PutCalendarObject(ctx, "/alice/calendars/cal1/client-uid-1.ics", cal, nil)
	if err != nil {
		t.Fatalf("creation PUT: %v", err)
	}
	if strings.Contains(obj.Path, "client-uid-1") {
		t.Fatalf("the Location must point to the Proton rowID, not the client name: %q", obj.Path)
	}
	// GET of the original name: must resolve the alias to the same resource.
	got, err := backend.GetCalendarObject(ctx, "/alice/calendars/cal1/client-uid-1.ics", nil)
	if err != nil {
		t.Fatalf("GET of the client name after create = %v, want the resource (alias)", err)
	}
	if got.Path != obj.Path {
		t.Fatalf("alias GET serves %q, want the canonical path %q", got.Path, obj.Path)
	}
	// DELETE via the original name: same resolution.
	if err := backend.DeleteCalendarObject(ctx, "/alice/calendars/cal1/client-uid-1.ics"); err != nil {
		t.Fatalf("DELETE of the client name = %v", err)
	}
	if _, err := backend.GetCalendarObject(ctx, obj.Path, nil); err == nil {
		t.Fatal("resource still served after DELETE by alias")
	}
}

// TestConcurrentCreateSameUIDSingleRow: two concurrent creation PUTs of the
// same UID (owner's iPhone + Mac pushing the same event) must produce only ONE
// Proton row — writeMu serializes, and the anti-duplicate re-check under the
// lock dedupes the second create (idempotent no-op, same ID).
func TestConcurrentCreateSameUIDSingleRow(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// The two goroutines start at the same time (worst case: both backend
	// checks already happened, both "UID absent").
	start := make(chan struct{})
	now := time.Now().UTC().Truncate(time.Second)
	in := proton.EventInput{UID: "double@apple", Title: "appt", Start: now, End: now.Add(time.Hour)}

	var wg gosync.WaitGroup
	ids := make([]string, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			ids[i], errs[i] = cached.CreateEvent(ctx, "cal1", in)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("CreateEvent #%d: %v", i, err)
		}
	}
	if ids[0] != ids[1] {
		t.Fatalf("the two concurrent creates must converge on the same row: %q vs %q", ids[0], ids[1])
	}
	rows, _ := src.ListEventsByUID(ctx, "cal1", "double@apple")
	if len(rows) != 1 {
		t.Fatalf("Proton duplicate: %d rows for the same UID, want 1", len(rows))
	}
}

// TestPollerEmptyCalendarListGuard: a cycle where the API returns 0 active
// calendar while the store has some is DROPPED — a Proton blip must never empty
// the served calendar (neither the list nor the events).
func TestPollerEmptyCalendarListGuard(t *testing.T) {
	ctx := context.Background()
	src, st, cached, poller := newTestStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}

	src.calendars = nil // blip: no active calendar returned anymore
	if err := poller.SyncOnce(ctx); err == nil {
		t.Fatal("a cycle with a suspicious empty list must return an error")
	}
	if cals, _ := cached.ListCalendars(ctx); len(cals) != 1 {
		t.Fatalf("the served list was emptied by the blip: %+v", cals)
	}
	if _, ok := st.Event("cal1", "seed1"); !ok {
		t.Fatal("the events were purged by the blip")
	}
}

// TestPollerMarksSyncedOnlyOnCleanCycle: the Synced flag (semantics of
// Empty()) is only set at the end of a COMPLETE cycle without error — never by
// a partial cycle (otherwise the next boot would serve a store with holes).
func TestPollerMarksSyncedOnlyOnCleanCycle(t *testing.T) {
	ctx := context.Background()
	src, st, _, poller := newTestStack(t)

	src.listEventsErr = errors.New("fake: API down")
	if err := poller.SyncOnce(ctx); err == nil {
		t.Fatal("a cycle with errors must return an error")
	}
	if !st.Empty() {
		t.Fatal("a PARTIAL cycle must not mark the store Synced")
	}
	if !poller.LastOK().IsZero() {
		t.Fatal("a partial cycle must not refresh LastOK (healthz)")
	}

	src.listEventsErr = nil
	before := time.Now()
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st.Empty() {
		t.Fatal("a complete successful cycle must mark the store Synced")
	}
	if ok := poller.LastOK(); ok.Before(before) {
		t.Fatalf("LastOK not refreshed by the successful cycle: %v", ok)
	}
}

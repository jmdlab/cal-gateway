package sync

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/jmdlab/cal-gateway/internal/proton"
	"github.com/jmdlab/cal-gateway/internal/store"
)

// fakeDeltaSource extends fakeSource with the calendar event-loop (cursor +
// deltas), to prove the poller's delta path: after the initial full snapshot,
// the following cycles NEVER re-list everything — they only consume the change
// log. The cursor is the index (stringified int) into the per-calendar log.
type fakeDeltaSource struct {
	*fakeSource

	changeLog    map[string][]deltaChange // calID -> ordered log
	forceRefresh bool                     // the next CalendarEventChanges returns Refresh

	latestCalls  int
	changesCalls int

	// onChanges is called at the start of CalendarEventChanges — lets us
	// simulate a concurrent write-through during the delta fetch (generation
	// guard).
	onChanges func()
}

type deltaChange struct {
	id     string
	action int // 0 = delete, 1 = create/update
}

func newDeltaSource(f *fakeSource) *fakeDeltaSource {
	return &fakeDeltaSource{fakeSource: f, changeLog: map[string][]deltaChange{}}
}

func (f *fakeDeltaSource) LatestCalendarCursor(ctx context.Context, calID string) (string, error) {
	f.latestCalls++
	return strconv.Itoa(len(f.changeLog[calID])), nil
}

func (f *fakeDeltaSource) CalendarEventChanges(ctx context.Context, calID, since string) (proton.CalendarDelta, error) {
	f.changesCalls++
	if f.onChanges != nil {
		hook := f.onChanges
		f.onChanges = nil // only once
		hook()
	}
	if f.forceRefresh {
		f.forceRefresh = false
		return proton.CalendarDelta{Refresh: true, NewCursor: strconv.Itoa(len(f.changeLog[calID]))}, nil
	}
	idx, _ := strconv.Atoi(since)
	log := f.changeLog[calID]
	final := map[string]int{}
	var order []string
	for i := idx; i < len(log); i++ {
		c := log[i]
		if _, seen := final[c.id]; !seen {
			order = append(order, c.id)
		}
		final[c.id] = c.action
	}
	d := proton.CalendarDelta{NewCursor: strconv.Itoa(len(log))}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range order {
		if final[id] == 0 {
			d.DeletedIDs = append(d.DeletedIDs, id)
			continue
		}
		ev, ok := f.events[calID][id]
		if !ok {
			d.DeletedIDs = append(d.DeletedIDs, id)
			continue
		}
		d.Upserts = append(d.Upserts, ev)
	}
	return d, nil
}

// remoteCreate simulates a creation on the Proton side (event + log entry).
func (f *fakeDeltaSource) remoteCreate(calID string, ev proton.Event) {
	f.mu.Lock()
	if f.events[calID] == nil {
		f.events[calID] = map[string]proton.Event{}
	}
	f.events[calID][ev.ID] = ev
	f.mu.Unlock()
	f.changeLog[calID] = append(f.changeLog[calID], deltaChange{id: ev.ID, action: 1})
}

// remoteDelete simulates a deletion on the Proton side (removal + log entry).
func (f *fakeDeltaSource) remoteDelete(calID, id string) {
	f.mu.Lock()
	delete(f.events[calID], id)
	f.mu.Unlock()
	f.changeLog[calID] = append(f.changeLog[calID], deltaChange{id: id, action: 0})
}

func newDeltaStack(t *testing.T) (*fakeDeltaSource, *store.Store, *CachedSource, *Poller) {
	t.Helper()
	now := time.Now().UTC()
	base := &fakeSource{
		calendars: []proton.Calendar{{ID: "cal1", Name: "Family"}},
		events: map[string]map[string]proton.Event{
			"cal1": {
				"seed1": {ID: "seed1", UID: "seed1@p", CalendarID: "cal1", Title: "seed",
					Start: now, End: now.Add(time.Hour), LastEdit: now},
			},
		},
	}
	src := newDeltaSource(base)
	st, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	return src, st, NewCachedSource(src, st), NewPoller(src, st, time.Minute)
}

// TestDeltaBaselineThenEmptyCycle: the 1st cycle is a full snapshot (lays the
// baseline cursor); the next cycle WITHOUT a change re-lists NOTHING
// (listEventsCalls frozen) and touches no event — the perf goal.
func TestDeltaBaselineThenEmptyCycle(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newDeltaStack(t)

	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce baseline: %v", err)
	}
	if src.listEventsCalls != 1 {
		t.Fatalf("baseline must do 1 full ListEvents, got %d", src.listEventsCalls)
	}
	if src.latestCalls != 1 {
		t.Fatalf("baseline must lay 1 cursor (LatestCalendarCursor), got %d", src.latestCalls)
	}

	// Force the delta path on the next cycle: without it, fullDue stays false
	// (6h) — but we also want to check the cursor does not move.
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce empty delta: %v", err)
	}
	if src.listEventsCalls != 1 {
		t.Fatalf("an empty delta cycle MUST NOT re-list: listEventsCalls=%d (expected 1)", src.listEventsCalls)
	}
	if src.changesCalls != 1 {
		t.Fatalf("an empty delta cycle must call CalendarEventChanges 1×, got %d", src.changesCalls)
	}
	// seed1 still served, intact.
	now := time.Now().UTC()
	if evs := mustList(t, cached, "cal1", now.Add(-time.Hour), now.Add(time.Hour)); len(evs) != 1 {
		t.Fatalf("seed1 must stay served, got %d events", len(evs))
	}
}

// TestDeltaSeesCreate: an event created on the Proton side appears on the next
// delta cycle WITHOUT a full snapshot.
func TestDeltaSeesCreate(t *testing.T) {
	ctx := context.Background()
	src, _, cached, poller := newDeltaStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	baseLE := src.listEventsCalls

	now := time.Now().UTC().Truncate(time.Second)
	src.remoteCreate("cal1", proton.Event{
		ID: "remote1", UID: "remote1@p", CalendarID: "cal1", Title: "remote",
		Start: now, End: now.Add(time.Hour), LastEdit: now,
	})

	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce delta create: %v", err)
	}
	if src.listEventsCalls != baseLE {
		t.Fatalf("the create must be seen by DELTA, not by a full snapshot (listEventsCalls %d→%d)", baseLE, src.listEventsCalls)
	}
	ev, err := cached.GetEvent(ctx, "cal1", "remote1")
	if err != nil {
		t.Fatalf("remote event not reflected by the delta: %v", err)
	}
	if ev.Title != "remote" {
		t.Fatalf("delta event = %+v", ev)
	}
}

// TestDeltaSeesDelete: a remote deletion removes the event from the store on
// the next delta cycle, without a full snapshot.
func TestDeltaSeesDelete(t *testing.T) {
	ctx := context.Background()
	src, st, _, poller := newDeltaStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	baseLE := src.listEventsCalls

	src.remoteDelete("cal1", "seed1")
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce delta delete: %v", err)
	}
	if src.listEventsCalls != baseLE {
		t.Fatalf("the delete must go through DELTA (listEventsCalls %d→%d)", baseLE, src.listEventsCalls)
	}
	if _, ok := st.Event("cal1", "seed1"); ok {
		t.Fatal("seed1 must disappear from the store after the delta delete")
	}
}

// TestDeltaRefreshFallsBackToFull: when the server signals Refresh (cursor
// lost), the poller redoes a full snapshot.
func TestDeltaRefreshFallsBackToFull(t *testing.T) {
	ctx := context.Background()
	src, _, _, poller := newDeltaStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	baseLE := src.listEventsCalls

	src.forceRefresh = true
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce refresh: %v", err)
	}
	if src.listEventsCalls != baseLE+1 {
		t.Fatalf("Refresh must trigger ONE full snapshot (listEventsCalls %d→%d, expected +1)", baseLE, src.listEventsCalls)
	}
}

// TestDeltaGenerationGuard: a concurrent write-through during the delta fetch
// bumps the generation → the delta is REFUSED (does not overwrite the fresh
// write) and the cursor DOES NOT ADVANCE; the next cycle reconciles.
func TestDeltaGenerationGuard(t *testing.T) {
	ctx := context.Background()
	src, st, cached, poller := newDeltaStack(t)
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	curBefore, _ := st.Cursor("cal1")

	// The server has deleted seed1 (pending delta). But during the fetch, a
	// client write-through re-introduces/modifies an event → generation bump.
	src.remoteDelete("cal1", "seed1")
	src.onChanges = func() {
		if err := st.UpsertEvent(proton.Event{
			ID: "wt1", UID: "wt1@p", CalendarID: "cal1", Title: "write-through",
			Start: time.Now().UTC(), End: time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Errorf("concurrent UpsertEvent: %v", err)
		}
	}
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce generation guard: %v", err)
	}
	// The delta was refused: the cursor did not advance.
	if curAfter, _ := st.Cursor("cal1"); curAfter != curBefore {
		t.Fatalf("the refused delta must NOT advance the cursor (%q→%q)", curBefore, curAfter)
	}
	// The write-through write survives.
	if _, ok := st.Event("cal1", "wt1"); !ok {
		t.Fatal("the concurrent write-through write was overwritten")
	}
	// The next cycle (stable generation) replays the delta and applies the delete.
	if err := poller.SyncOnce(ctx); err != nil {
		t.Fatalf("SyncOnce reconciliation: %v", err)
	}
	if _, err := cached.GetEvent(ctx, "cal1", "seed1"); err == nil {
		t.Fatal("seed1 should have been deleted by the delta replayed on the next cycle")
	}
}

func mustList(t *testing.T, c *CachedSource, calID string, start, end time.Time) []proton.Event {
	t.Helper()
	evs, err := c.ListEvents(context.Background(), calID, start, end)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	return evs
}

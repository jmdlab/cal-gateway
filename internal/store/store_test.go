package store

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jmdlab/cal-gateway/internal/atrest"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

func testEvent(calID, id string, start time.Time) proton.Event {
	return proton.Event{
		ID:         id,
		UID:        id + "@test",
		CalendarID: calID,
		Title:      "t-" + id,
		Start:      start,
		End:        start.Add(time.Hour),
		LastEdit:   start,
	}
}

func TestOpenEmptyAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !s.Empty() {
		t.Fatal("a fresh store should be Empty")
	}

	cal := proton.Calendar{ID: "cal1", Name: "Personal"}
	if err := s.ReplaceCalendars([]proton.Calendar{cal}); err != nil {
		t.Fatalf("ReplaceCalendars: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	ev := testEvent("cal1", "ev1", now)
	if _, err := s.ReplaceCalendarEvents("cal1", []proton.Event{ev}, 0); err != nil {
		t.Fatalf("ReplaceCalendarEvents: %v", err)
	}

	// Empty = "never completed a sync", NOT "0 calendar": as long as MarkSynced
	// has not been called (end of a complete cycle), a half-populated store
	// (initial sync killed by SIGTERM) stays Empty → re-sync.
	if !s.Empty() {
		t.Fatal("a populated store never MarkSynced must stay Empty")
	}
	if err := s.MarkSynced(); err != nil {
		t.Fatalf("MarkSynced: %v", err)
	}
	if s.Empty() {
		t.Fatal("a MarkSynced store must no longer be Empty")
	}

	// Disk round-trip: a second Open must recover the same state.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	if s2.Empty() {
		t.Fatal("a reloaded store should not be Empty")
	}
	cals := s2.Calendars()
	if len(cals) != 1 || cals[0].ID != "cal1" || cals[0].Name != "Personal" {
		t.Fatalf("Calendars = %+v", cals)
	}
	got, ok := s2.Event("cal1", "ev1")
	if !ok {
		t.Fatal("Event ev1 absent after reload")
	}
	if got.Title != ev.Title || !got.Start.Equal(ev.Start) {
		t.Fatalf("reloaded Event = %+v, want %+v", got, ev)
	}
}

// TestFilePermissions: the store contains DECRYPTED events (personal data) —
// 0600 STRICT, like session.json.
func TestFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, _ := Open(path)
	if err := s.UpsertEvent(testEvent("cal1", "ev1", time.Now())); err != nil {
		t.Fatalf("UpsertEvent: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store.json permissions = %o, want 0600 (decrypted personal data)", perm)
	}
}

func TestEventsWindowFiltering(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "store.json"))
	base := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	inside := testEvent("c", "inside", base)
	before := testEvent("c", "before", base.Add(-72*time.Hour))
	after := testEvent("c", "after", base.Add(72*time.Hour))
	recur := testEvent("c", "recur", base.Add(-500*time.Hour)) // old master
	recur.RRule = "FREQ=DAILY"
	for _, ev := range []proton.Event{inside, before, after, recur} {
		if err := s.UpsertEvent(ev); err != nil {
			t.Fatalf("UpsertEvent: %v", err)
		}
	}

	got := s.Events("c", base.Add(-24*time.Hour), base.Add(24*time.Hour))
	ids := map[string]bool{}
	for _, ev := range got {
		ids[ev.ID] = true
	}
	if !ids["inside"] {
		t.Error("the event within the window must be served")
	}
	if !ids["recur"] {
		t.Error("a recurring master must ALWAYS be served (occurrences outside DTSTART)")
	}
	if ids["before"] || ids["after"] {
		t.Errorf("events outside the window served: %v", ids)
	}
	// Sorted by Start (proton.Account.ListEvents contract).
	for i := 1; i < len(got); i++ {
		if got[i].Start.Before(got[i-1].Start) {
			t.Fatal("Events not sorted by Start")
		}
	}
}

// TestReplaceGenerationGuard is THE anti-regression guard: a poller snapshot
// taken before a write-through write must never overwrite it (otherwise a
// deleted event resurrects → "Error 2" loop).
func TestReplaceGenerationGuard(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "store.json"))
	now := time.Now().UTC()

	// Poller cycle: reads the generation, then "fetches" (during which a
	// write-through delete passes), then attempts the replacement.
	gen := s.Generation("c")
	snapshot := []proton.Event{testEvent("c", "ev1", now), testEvent("c", "ev2", now)}

	if err := s.UpsertEvent(testEvent("c", "ev1", now)); err != nil { // initial state
		t.Fatal(err)
	}
	// The concurrent write-through: ev1 deleted during the poller's fetch.
	if err := s.DeleteEvent("c", "ev1"); err != nil {
		t.Fatal(err)
	}

	replaced, err := s.ReplaceCalendarEvents("c", snapshot, gen)
	if err != nil {
		t.Fatalf("ReplaceCalendarEvents: %v", err)
	}
	if replaced {
		t.Fatal("the stale snapshot overwrote the write-through — ev1 resurrected")
	}
	if _, ok := s.Event("c", "ev1"); ok {
		t.Fatal("ev1 must stay deleted")
	}

	// Next cycle, fresh generation: the replacement passes.
	replaced, err = s.ReplaceCalendarEvents("c", snapshot, s.Generation("c"))
	if err != nil || !replaced {
		t.Fatalf("replacement at fresh generation: replaced=%v err=%v", replaced, err)
	}
	if _, ok := s.Event("c", "ev1"); !ok {
		t.Fatal("the next cycle must reconcile ev1")
	}
}

// TestApplyCalendarDelta: upserts + deletions applied and cursor advanced, all
// under the per-generation guard. A stale delta (write-through passed during
// the fetch) is refused and the cursor does not advance; it persists and
// survives a reopen.
func TestApplyCalendarDelta(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, _ := Open(path)
	now := time.Now().UTC()

	if _, ok := s.Cursor("c"); ok {
		t.Fatal("no cursor at the start")
	}
	// Nominal delta: creates ev1, lays the cursor.
	gen := s.Generation("c")
	applied, err := s.ApplyCalendarDelta("c", []proton.Event{testEvent("c", "ev1", now)}, nil, "cur-1", gen)
	if err != nil || !applied {
		t.Fatalf("nominal delta: applied=%v err=%v", applied, err)
	}
	if cur, ok := s.Cursor("c"); !ok || cur != "cur-1" {
		t.Fatalf("cursor = %q,%v (expected cur-1)", cur, ok)
	}
	if _, ok := s.Event("c", "ev1"); !ok {
		t.Fatal("ev1 must be present after the delta")
	}

	// Stale delta: the poller read gen before the fetch, but a write-through
	// (UpsertEvent) bumps the generation meanwhile → delta refused, cursor
	// frozen.
	staleGen := s.Generation("c")
	if err := s.UpsertEvent(testEvent("c", "ev2", now)); err != nil {
		t.Fatal(err)
	}
	applied, err = s.ApplyCalendarDelta("c", nil, []string{"ev1"}, "cur-2", staleGen)
	if err != nil {
		t.Fatalf("stale ApplyCalendarDelta: %v", err)
	}
	if applied {
		t.Fatal("the stale delta must NOT apply")
	}
	if _, ok := s.Event("c", "ev1"); !ok {
		t.Fatal("the stale delta should not have deleted ev1")
	}
	if cur, _ := s.Cursor("c"); cur != "cur-1" {
		t.Fatalf("cursor advanced by a refused delta: %q", cur)
	}

	// The cursor survives a reopen (persistence).
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if cur, ok := s2.Cursor("c"); !ok || cur != "cur-1" {
		t.Fatalf("cursor not persisted: %q,%v", cur, ok)
	}
}

// TestReplaceCalendarsTombstonesRemoved: a calendar absent from the new list is
// no longer LISTED, but its content is KEPT (tombstone) — an API blip that
// omits a calendar must not empty it; if it reappears, everything is there.
func TestReplaceCalendarsTombstonesRemoved(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "store.json"))
	if err := s.UpsertEvent(testEvent("gone", "ev1", time.Now())); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceCalendars([]proton.Calendar{{ID: "gone"}, {ID: "kept"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceCalendars([]proton.Calendar{{ID: "kept"}}); err != nil {
		t.Fatal(err)
	}
	cals := s.Calendars()
	if len(cals) != 1 || cals[0].ID != "kept" {
		t.Fatalf("Calendars = %+v, want [kept] only", cals)
	}
	if _, ok := s.Event("gone", "ev1"); !ok {
		t.Fatal("the events of a vanished calendar must be KEPT (tombstone)")
	}
	// Reappearance: the content is servable immediately.
	if err := s.ReplaceCalendars([]proton.Calendar{{ID: "gone"}, {ID: "kept"}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Event("gone", "ev1"); !ok {
		t.Fatal("after the calendar reappears, its events must be served")
	}
}

// TestSyncedMigrationLegacyStore: a historical store.json (without the Synced
// or SchemaVersion field) must load its content BUT stay Empty — safe
// migration: the boot redoes a full sync before serving.
func TestSyncedMigrationLegacyStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	legacy := `{"Calendars":[{"ID":"cal1","Name":"Family"}],"Events":{"cal1":{}},"Gens":{},"Aliases":{}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(s.Calendars()) != 1 {
		t.Fatalf("the legacy content must be loaded: %+v", s.Calendars())
	}
	if !s.Empty() {
		t.Fatal("a legacy store (Synced field absent) must be Empty → re-sync at boot")
	}
}

// TestSchemaVersionUnknown: a blob of a HIGHER version (downgraded binary) is
// treated as corrupted — we restart empty, resync.
func TestSchemaVersionUnknown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	future := `{"SchemaVersion":99,"Synced":true,"Calendars":[{"ID":"cal1"}]}`
	if err := os.WriteFile(path, []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on an unknown schema must succeed (reconstructible cache): %v", err)
	}
	if !s.Empty() || len(s.Calendars()) != 0 {
		t.Fatalf("an unknown schema must restart empty: Empty=%v cals=%+v", s.Empty(), s.Calendars())
	}
}

// TestSchemaVersionStamped: every persist stamps the current version. Since the
// file is SEALED at rest, we decrypt it before inspecting the JSON.
func TestSchemaVersionStamped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	s, _ := Open(path)
	if err := s.MarkSynced(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !atrest.IsSealed(raw) {
		t.Fatal("the persisted store must be sealed at rest (atrest magic expected)")
	}
	cipher, err := atrest.Load(atrest.KeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := cipher.Open(raw)
	if err != nil {
		t.Fatalf("unseal: %v", err)
	}
	var d struct {
		SchemaVersion int
		Synced        bool
	}
	if err := json.Unmarshal(plain, &d); err != nil {
		t.Fatal(err)
	}
	if d.SchemaVersion != schemaVersion || !d.Synced {
		t.Fatalf("blob = %+v, want SchemaVersion=%d Synced=true", d, schemaVersion)
	}
}

// TestOpenCorruptFile: a corrupted store is not fatal (pure reconstructible
// cache) — we restart empty.
func TestOpenCorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on a corrupted file must succeed (reconstructible cache): %v", err)
	}
	if !s.Empty() {
		t.Fatal("a corrupted store must restart empty")
	}
}

// TestSealedAtRest: the persisted store is SEALED at rest — the plaintext
// (event titles = personal data) must never appear on disk.
func TestSealedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, _ := Open(path)
	if err := s.UpsertEvent(testEvent("cal1", "ev-secret", time.Now())); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !atrest.IsSealed(raw) {
		t.Fatal("store.json must be sealed (atrest magic)")
	}
	if bytes.Contains(raw, []byte("t-ev-secret")) {
		t.Fatal("the event title (personal data) must NOT appear in the clear on disk")
	}
}

// TestPlaintextMigration: a LEGACY PLAINTEXT store.json (deployment) is read
// as-is, then re-sealed on the first persist — content preserved, format
// migrated.
func TestPlaintextMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	// Legitimate store marked Synced, written in the CLEAR (legacy pre-encryption format).
	legacy := `{"SchemaVersion":1,"Synced":true,"Calendars":[{"ID":"cal1","Name":"Family"}],` +
		`"Events":{"cal1":{}},"Gens":{},"Aliases":{}}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open on legacy plaintext: %v", err)
	}
	if s.Empty() {
		t.Fatal("a legitimate plaintext store (Synced=true) must be loaded, not restart empty")
	}
	if len(s.Calendars()) != 1 || s.Calendars()[0].Name != "Family" {
		t.Fatalf("plaintext content not loaded: %+v", s.Calendars())
	}

	// A persist (mutation) must re-seal in place.
	if err := s.UpsertEvent(testEvent("cal1", "ev1", time.Now())); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !atrest.IsSealed(raw) {
		t.Fatal("after persist, the legacy plaintext store must be re-sealed")
	}

	// Reopen: the sealed format re-reads correctly.
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("re-Open sealed: %v", err)
	}
	if _, ok := s2.Event("cal1", "ev1"); !ok {
		t.Fatal("the event must survive the sealed round-trip")
	}
}

// TestEventsByUIDAndGroupDelete: the same-UID group (master + exceptions) is
// found sorted master first, and DeleteEventsByUID purges the whole group
// (write-through mirror of the Proton batch-delete).
func TestEventsByUIDAndGroupDelete(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "store.json"))
	now := time.Now().UTC()
	master := testEvent("cal1", "master", now)
	master.UID = "series@test"
	master.RRule = "FREQ=WEEKLY"
	exc := testEvent("cal1", "exc", now.Add(7*24*time.Hour))
	exc.UID = "series@test"
	exc.RecurrenceID = now.Add(7 * 24 * time.Hour).Unix()
	other := testEvent("cal1", "other", now)
	for _, ev := range []proton.Event{exc, master, other} { // exception inserted BEFORE the master
		if err := s.UpsertEvent(ev); err != nil {
			t.Fatal(err)
		}
	}

	group := s.EventsByUID("cal1", "series@test")
	if len(group) != 2 || group[0].ID != "master" || group[1].ID != "exc" {
		t.Fatalf("EventsByUID = %+v, want master first then exception", group)
	}

	gen := s.Generation("cal1")
	if err := s.DeleteEventsByUID("cal1", "series@test"); err != nil {
		t.Fatal(err)
	}
	if got := s.EventsByUID("cal1", "series@test"); len(got) != 0 {
		t.Fatalf("group not purged: %+v", got)
	}
	if _, ok := s.Event("cal1", "other"); !ok {
		t.Fatal("another UID must not be touched")
	}
	if s.Generation("cal1") == gen {
		t.Fatal("DeleteEventsByUID must increment the generation")
	}
}

// TestAliasRoundTripAndCleanup: the client-name → rowID alias survives a
// reopen, and disappears when its target is deleted or absent from a poller
// snapshot.
func TestAliasRoundTripAndCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, _ := Open(path)
	now := time.Now().UTC()
	if err := s.UpsertEvent(testEvent("cal1", "row1", now)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAlias("cal1", "client-name", "row1"); err != nil {
		t.Fatal(err)
	}

	// Persistence: reopen from disk.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := s2.ResolveAlias("cal1", "client-name"); !ok || id != "row1" {
		t.Fatalf("alias not persisted: %q %v", id, ok)
	}

	// Deleting the target → alias purged.
	if err := s2.DeleteEvent("cal1", "row1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.ResolveAlias("cal1", "client-name"); ok {
		t.Fatal("orphan alias after DeleteEvent")
	}

	// Target absent from a poller snapshot → alias purged too.
	s3, _ := Open(filepath.Join(t.TempDir(), "store2.json"))
	if err := s3.UpsertEvent(testEvent("cal1", "row2", now)); err != nil {
		t.Fatal(err)
	}
	if err := s3.SetAlias("cal1", "n2", "row2"); err != nil {
		t.Fatal(err)
	}
	gen := s3.Generation("cal1")
	if _, err := s3.ReplaceCalendarEvents("cal1", nil, gen); err != nil {
		t.Fatal(err)
	}
	if _, ok := s3.ResolveAlias("cal1", "n2"); ok {
		t.Fatal("orphan alias after poller snapshot")
	}
}

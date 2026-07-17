// Package store is the local shadow store: the materialized view of the Proton
// calendar that the CalDAV server serves without EVER touching the API on a
// client request (root cause of the "Error 2" bug of 2026-07-16: live
// fetch+decrypt of ~116 events during a PROPFIND → dataaccessd cancels the
// connection).
//
// Storage choice: a single JSON file, all state in memory under an RWMutex.
// For a few thousand events max this is the simplest and most robust in pure Go
// (CGO_ENABLED=0 builds): zero new dependency, zero-latency reads, atomic
// tmp+rename write. SQLite (modernc.org/sqlite) or bbolt would be oversized for
// a simple reconstructible mirror.
//
// PERSONAL DATA: the file contains the DECRYPTED events of the account owner's
// calendar. It is therefore SEALED at rest via internal/atrest (AES-256-GCM,
// local .atrest.key key 0600) ON TOP OF strict permissions: file 0600,
// data_dir directory already 0700 cal-gw (/var/lib/cal-gateway). Since the
// store is a pure RECONSTRUCTIBLE cache, an unreadable blob (wrong key,
// corruption, or a non-migratable legacy plaintext) is never fatal: we restart
// empty, the initial sync repopulates. A legacy plaintext JSON (deployment) IS
// read as-is (migration) then re-sealed on the first persist.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/jmdlab/cal-gateway/internal/atrest"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

// schemaVersion is the version of the on-disk format. Bumped on every
// INCOMPATIBLE change to the shape of `data`; a file of a HIGHER version
// (downgraded binary) is treated as corrupted → we restart empty, the initial
// sync repopulates (the store is a pure reconstructible cache).
// Version 0 (field absent) = historical format, readable as-is.
const schemaVersion = 1

// data is the state serialized on disk.
type data struct {
	// SchemaVersion stamps the format of the blob (see schemaVersion).
	SchemaVersion int
	// Synced is true as soon as ONE COMPLETE sync cycle has succeeded (set by
	// MarkSynced at the end of the first SyncOnce without error — after the
	// ReplaceCalendarEvents, never after ReplaceCalendars alone). This is THE
	// semantics of Empty(): "never completed a sync", not "0 calendar" — a boot
	// interrupted mid initial sync (watchdog SIGTERM) leaves calendars persisted
	// with 0 events, and serving that would make clients "see" an emptied
	// calendar. Field absent (historical store) = false = re-sync at boot: safe.
	Synced bool
	// Calendars is the list served by ListCalendars, Proton API order.
	Calendars []proton.Calendar
	// Events indexes the decrypted events: calendarID → eventID → event.
	Events map[string]map[string]proton.Event
	// Gens counts the write-through writes per calendar. The poller reads the
	// generation BEFORE its Proton fetch and re-checks it at replace time: if it
	// moved, its snapshot predates a client write and must NOT overwrite it
	// (otherwise a deleted event would resurrect, or an update would be served
	// stale — the "Error 2" loop we just killed).
	Gens map[string]uint64
	// Aliases maps, per calendar, the resource name CHOSEN BY THE CLIENT at the
	// creation PUT (typically "{uid}.ics" → segment "{uid}") to the Proton row
	// ID created. The 201 returns Location pointing to {rowID}.ics (server
	// rename, legal) but dataaccessd may re-GET the original name before it has
	// integrated the Location: the alias keeps that name resolvable.
	// calendarID → client name → eventID.
	Aliases map[string]map[string]string
	// Cursors keeps, per calendar, the cursor of the Proton calendar event-loop
	// (last CalendarModelEventID applied,
	// GET /calendar/v1/{calID}/modelevents/…). The poller resumes from there in
	// delta: `latest` unchanged → 0 decryption. Absent (historical store /
	// calendar never synced) = no baseline → full snapshot, which re-lays the
	// cursor: soft migration, no schema bump required (purely additive field,
	// an old binary's JSON ignores the unknown key). calendarID → cursor.
	Cursors map[string]string
}

// Store is the thread-safe shadow store. All reads are served from memory;
// each mutation persists to disk (atomic, 0600).
type Store struct {
	mu     sync.RWMutex
	path   string
	cipher *atrest.Cipher // seals/opens the blob at rest (AES-256-GCM)
	data   data

	// lastHash is the FNV-64a fingerprint of the last PLAINTEXT blob (JSON,
	// before sealing) actually written: persistLocked skips the WriteFile+Rename
	// if the state is identical (the family calendar is almost static, the
	// poller re-snapshots identically 1440×/day — without this guard, ~470 MB/day
	// of useless rewrites, perf audit 2026-07-17). The hash is over the
	// PLAINTEXT: the sealing nonce changes on EVERY Seal, hashing the ciphertext
	// would break the skip (systematic rewrite).
	lastHash uint64
}

// Open loads the store from path (created on the first persist if it does not
// exist). A corrupted file is NOT fatal: the store is a pure reconstructible
// cache, we restart empty (the initial sync repopulates) and signal it.
func Open(path string) (*Store, error) {
	s := &Store{path: path}
	s.data = data{
		Events:  make(map[string]map[string]proton.Event),
		Gens:    make(map[string]uint64),
		Aliases: make(map[string]map[string]string),
		Cursors: make(map[string]string),
	}

	// At-rest key shared with session.json: it lives in the same data_dir (the
	// store's directory), generated on the first call if absent.
	cipher, err := atrest.Load(atrest.KeyPath(filepath.Dir(path)))
	if err != nil {
		return nil, fmt.Errorf("store: loading at-rest key: %w", err)
	}
	s.cipher = cipher

	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// First start: empty store, nothing to load.
	case err != nil:
		return nil, fmt.Errorf("store: reading %s: %w", path, err)
	default:
		// Unseal. A legacy plaintext JSON (no magic) is read as-is (migration,
		// re-sealed on the first persist); a sealed but unreadable blob (wrong
		// key/corruption) is treated as absent → resync.
		plain := raw
		if atrest.IsSealed(raw) {
			plain, err = s.cipher.Open(raw)
			if err != nil {
				log.Printf("store: %s sealed but unreadable (%v) — cache rebuilt by initial sync", path, err)
				return s, nil
			}
		}
		var d data
		if uerr := json.Unmarshal(plain, &d); uerr != nil {
			log.Printf("store: %s corrupted (%v) — cache rebuilt by initial sync", path, uerr)
		} else if d.SchemaVersion > schemaVersion {
			// File written by a newer binary: we don't know how to interpret it
			// — same treatment as a corrupted file.
			log.Printf("store: %s unknown schema v%d (max supported v%d, downgraded binary?) — cache rebuilt by initial sync", path, d.SchemaVersion, schemaVersion)
		} else {
			if d.Events == nil {
				d.Events = make(map[string]map[string]proton.Event)
			}
			if d.Gens == nil {
				d.Gens = make(map[string]uint64)
			}
			if d.Aliases == nil {
				d.Aliases = make(map[string]map[string]string)
			}
			if d.Cursors == nil {
				d.Cursors = make(map[string]string)
			}
			s.data = d
		}
	}
	return s, nil
}

// Empty reports whether the store has NEVER yet completed a sync cycle (Synced
// flag, see data) — startup then holds the service at 503 (readiness gate)
// until the initial sync completes. The historical "0 calendar" criterion was
// misleading: an initial sync killed by SIGTERM after ReplaceCalendars left
// calendars persisted with 0 events, and the next boot served empty
// collections (events "vanished" on the client side).
func (s *Store) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.data.Synced
}

// MarkSynced records that a COMPLETE sync cycle has succeeded (to call after a
// cycle's ReplaceCalendarEvents without error, never before). Idempotent;
// persists on the first pass. The returned error is a persistence error only
// (memory is up to date).
func (s *Store) MarkSynced() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Synced {
		return nil
	}
	s.data.Synced = true
	return s.persistLocked()
}

// Calendars returns the known calendars (copy).
func (s *Store) Calendars() []proton.Calendar {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]proton.Calendar, len(s.data.Calendars))
	copy(out, s.data.Calendars)
	return out
}

// Events returns the events of the calendar overlapping [start, end), sorted
// by Start (same contract as proton.Account.ListEvents). Recurring masters are
// always included: their occurrences can spill past their DTSTART/DTEND, RRULE
// expansion is the CalDAV client's job.
func (s *Store) Events(calendarID string, start, end time.Time) []proton.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	evs := s.data.Events[calendarID]
	out := make([]proton.Event, 0, len(evs))
	for _, ev := range evs {
		if ev.RRule == "" && (!ev.Start.Before(end) || ev.End.Before(start)) {
			continue
		}
		out = append(out, ev)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// Event returns a specific event, ok=false if it is unknown (deleted or never
// seen) — the Source wrapper translates it to ErrEventNotFound/404.
func (s *Store) Event(calendarID, eventID string) (proton.Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev, ok := s.data.Events[calendarID][eventID]
	return ev, ok
}

// EventsByUID returns all the rows of a UID (master + exception-rows), sorted
// master first then by ascending RecurrenceID — the same order as
// proton.Account.ListEventsByUID, for a deterministic CalDAV folding. Linear
// scan: the store holds a few hundred events in memory.
func (s *Store) EventsByUID(calendarID, uid string) []proton.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []proton.Event
	for _, ev := range s.data.Events[calendarID] {
		if ev.UID == uid {
			out = append(out, ev)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].RecurrenceID == 0) != (out[j].RecurrenceID == 0) {
			return out[i].RecurrenceID == 0 // master first
		}
		if out[i].RecurrenceID != out[j].RecurrenceID {
			return out[i].RecurrenceID < out[j].RecurrenceID
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Generation returns the calendar's write-through write counter. Read BEFORE a
// Proton fetch, pass back to ReplaceCalendarEvents.
func (s *Store) Generation(calendarID string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Gens[calendarID]
}

// UpsertEvent inserts or replaces an event (write-through path after
// CreateEvent/UpdateEvent). Increments the calendar's generation and persists.
// The returned error is a PERSISTENCE error only: memory is already up to date,
// the caller logs it without failing the client.
func (s *Store) UpsertEvent(ev proton.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	evs := s.data.Events[ev.CalendarID]
	if evs == nil {
		evs = make(map[string]proton.Event)
		s.data.Events[ev.CalendarID] = evs
	}
	evs[ev.ID] = ev
	s.data.Gens[ev.CalendarID]++
	return s.persistLocked()
}

// DeleteEvent removes an event (write-through path after Proton DeleteEvent).
// Idempotent. Increments the generation — even if the event was already absent
// from the cache, a deletion just happened on the Proton side and a poller
// cycle snapshotted BEFORE it must not undo it.
func (s *Store) DeleteEvent(calendarID, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Events[calendarID], eventID)
	s.dropAliasesToLocked(calendarID, map[string]struct{}{eventID: {}})
	s.data.Gens[calendarID]++
	return s.persistLocked()
}

// DeleteEventsByUID removes ALL the rows of a UID (master + exception-rows) —
// the write-through mirror of the same-UID batch-delete of proton.DeleteEvent:
// without it, the exception-rows would stay served until the next poller cycle
// (ghost debris = the "Error 2" loop). Idempotent; generation incremented in
// all cases (a Proton deletion just happened).
func (s *Store) DeleteEventsByUID(calendarID, uid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := make(map[string]struct{})
	for id, ev := range s.data.Events[calendarID] {
		if ev.UID == uid {
			delete(s.data.Events[calendarID], id)
			removed[id] = struct{}{}
		}
	}
	s.dropAliasesToLocked(calendarID, removed)
	s.data.Gens[calendarID]++
	return s.persistLocked()
}

// SetAlias records a client-name → row-ID alias (creation PUT, see
// data.Aliases). Persists; the error is a persistence error only (memory is up
// to date).
func (s *Store) SetAlias(calendarID, name, eventID string) error {
	if name == "" || name == eventID {
		return nil // nothing to resolve
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.data.Aliases[calendarID]
	if m == nil {
		m = make(map[string]string)
		s.data.Aliases[calendarID] = m
	}
	m[name] = eventID
	return s.persistLocked()
}

// ResolveAlias returns the row ID behind a client name, ok=false if no alias is
// registered for that name.
func (s *Store) ResolveAlias(calendarID, name string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.data.Aliases[calendarID][name]
	return id, ok
}

// dropAliasesToLocked purges the aliases pointing to deleted rows. Called with
// s.mu held for writing.
func (s *Store) dropAliasesToLocked(calendarID string, ids map[string]struct{}) {
	if len(ids) == 0 {
		return
	}
	for name, target := range s.data.Aliases[calendarID] {
		if _, gone := ids[target]; gone {
			delete(s.data.Aliases[calendarID], name)
		}
	}
}

// ReplaceCalendars replaces the calendar list (poller cycle). The events,
// generations and aliases of the calendars ABSENT from the new list are KEPT
// (tombstone): an API blip that omits a calendar (partial list, Active flag
// momentarily dropped) must never destroy its content. The vanished calendar is
// no longer listed nor served (Calendars drives all CalDAV discovery), but its
// content becomes servable again the instant it reappears — at worst, a few KB
// of dead data in a reconstructible cache.
func (s *Store) ReplaceCalendars(cals []proton.Calendar) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The poller calls this every cycle; the calendar list almost never
	// changes. Skipping the no-op replace avoids re-marshaling the WHOLE
	// store (all decrypted events) every cycle just for persistLocked's hash
	// to conclude "unchanged" (perf audit 2026-07-17).
	if calendarsEqual(s.data.Calendars, cals) {
		return nil
	}
	s.data.Calendars = append([]proton.Calendar(nil), cals...)
	return s.persistLocked()
}

// calendarsEqual reports element-wise equality (proton.Calendar is a small
// all-string struct, directly comparable).
func calendarsEqual(a, b []proton.Calendar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ReplaceCalendarEvents atomically replaces ALL the events of a calendar with
// the poller cycle's snapshot. gen is the generation read at the start of the
// cycle: if a write-through write happened meanwhile, the snapshot is stale and
// the replacement is REFUSED (replaced=false) — the next cycle will restart
// from a state including the write. The returned error is a persistence error
// only.
func (s *Store) ReplaceCalendarEvents(calendarID string, events []proton.Event, gen uint64) (replaced bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Gens[calendarID] != gen {
		return false, nil
	}
	evs := make(map[string]proton.Event, len(events))
	for _, ev := range events {
		evs[ev.ID] = ev
	}
	s.data.Events[calendarID] = evs
	// Aliases whose target vanished from the snapshot: purged (the row no longer
	// exists on the Proton side, the client name has nothing left to resolve).
	for name, target := range s.data.Aliases[calendarID] {
		if _, ok := evs[target]; !ok {
			delete(s.data.Aliases[calendarID], name)
		}
	}
	return true, s.persistLocked()
}

// Cursor returns the calendar's known event-loop cursor (last
// CalendarModelEventID applied). ok=false = no baseline → the poller does a
// full snapshot (which will re-lay the cursor). Read BEFORE the delta fetch.
func (s *Store) Cursor(calendarID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.data.Cursors[calendarID]
	return c, ok
}

// SetCursor lays the calendar's baseline cursor after a full snapshot APPLIED
// (never if the snapshot was refused by the generation guard). No-op if
// unchanged (avoids a disk rewrite). The error is a persistence error only
// (memory is up to date).
func (s *Store) SetCursor(calendarID, cursor string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Cursors == nil {
		s.data.Cursors = make(map[string]string)
	}
	if s.data.Cursors[calendarID] == cursor {
		return nil
	}
	s.data.Cursors[calendarID] = cursor
	return s.persistLocked()
}

// ApplyCalendarDelta applies a delta from the calendar event-loop (upserts +
// deletions) and advances the cursor, ALL under the SAME per-generation guard
// as ReplaceCalendarEvents: gen is the generation read at the start of the
// cycle. If a write-through write happened during the delta fetch (several
// GET+decrypts), gen moved → the delta is REFUSED (applied=false) and the
// cursor DOES NOT ADVANCE: the next cycle will replay the delta from the same
// cursor (idempotent), never overwriting the fresher client write.
// Applied: the upserts replace the row by ID, the deletions remove it (+ alias
// purge), the cursor advances. The generation is NOT incremented (poller
// reconciliation, not a client write — same posture as
// ReplaceCalendarEvents). The returned error is a persistence error.
func (s *Store) ApplyCalendarDelta(calendarID string, upserts []proton.Event, deletes []string, newCursor string, gen uint64) (applied bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Gens[calendarID] != gen {
		return false, nil
	}
	evs := s.data.Events[calendarID]
	if evs == nil {
		evs = make(map[string]proton.Event)
		s.data.Events[calendarID] = evs
	}
	removed := make(map[string]struct{}, len(deletes))
	for _, id := range deletes {
		delete(evs, id)
		removed[id] = struct{}{}
	}
	for _, ev := range upserts {
		evs[ev.ID] = ev
	}
	s.dropAliasesToLocked(calendarID, removed)
	if s.data.Cursors == nil {
		s.data.Cursors = make(map[string]string)
	}
	s.data.Cursors[calendarID] = newCursor
	return true, s.persistLocked()
}

// persistLocked serializes the state to disk, SEALED at rest (atrest),
// atomically (tmp + rename) and 0600 STRICT: the file contains decrypted events
// (personal data), cf. package doc. Called with s.mu held for writing.
func (s *Store) persistLocked() error {
	s.data.SchemaVersion = schemaVersion
	blob, err := json.Marshal(&s.data)
	if err != nil {
		return fmt.Errorf("store: encoding state: %w", err)
	}
	// Anti-rewrite guard: state unchanged since the last persist → skip the
	// WriteFile+Rename (a poller cycle on a static calendar changes nothing).
	// The hash is over the PLAINTEXT (blob) and NOT over the ciphertext: the
	// sealing nonce changes on every Seal, hashing the ciphertext would break
	// the skip. The hash already covers SchemaVersion (inside the blob).
	h := fnv.New64a()
	h.Write(blob)
	sum := h.Sum64()
	if sum == s.lastHash && s.lastHash != 0 {
		return nil
	}
	sealed, err := s.cipher.Seal(blob)
	if err != nil {
		return fmt.Errorf("store: sealing state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("store: creating dir: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return fmt.Errorf("store: writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("store: replacing %s: %w", s.path, err)
	}
	s.lastHash = sum // only after a successful write
	return nil
}

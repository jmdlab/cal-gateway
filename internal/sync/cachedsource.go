// Package sync reconciles the remote Proton state with the local shadow store:
// CachedSource serves all CalDAV READS from the store (never again the Proton
// API directly on a client request — root cause of the "Error 2" bug of
// 2026-07-16: live fetch+decrypt during a PROPFIND → dataaccessd cancels the
// connection), and reflects the WRITES into the store synchronously
// (write-through); the Poller refreshes the store in the background.
package sync

import (
	"context"
	"errors"
	"fmt"
	"log"
	gosync "sync" // the package is already named sync — alias required
	"time"

	"github.com/jmdlab/cal-gateway/internal/caldav"
	"github.com/jmdlab/cal-gateway/internal/proton"
	"github.com/jmdlab/cal-gateway/internal/store"
)

// CachedSource implements caldav.Source on top of the real Proton Source:
//
//   - ListCalendars/ListEvents/GetEvent: served FROM THE STORE, zero API call
//     — memory latency, no more dataaccessd timeout.
//   - CreateEvent/UpdateEvent/DeleteEvent: delegated to the real Source THEN
//     reflected SYNCHRONOUSLY into the store BEFORE answering (strict
//     write-through: Apple re-reads immediately after a PUT/DELETE; any stale
//     read post-write would recreate the "Error 2" loop). A master DELETE
//     purges the whole same-UID GROUP from the store (mirror of the
//     proton.DeleteEvent batch-delete — otherwise the exception-rows would stay
//     served as debris until the next poller cycle).
//   - ListEventsByUID (read folding): served FROM THE STORE;
//     AuthoritativeEventsByUID (write routing): delegated to the real one — the
//     anti-duplicate guard must see the authoritative Proton state.
//   - RecordAlias/ResolveAlias (caldav.AliasResolver): persisted in the store —
//     the resource name chosen by the client at the creation PUT stays
//     resolvable after the server rename to {rowID}.ics.
type CachedSource struct {
	src caldav.Source
	st  *store.Store

	// writeMu serializes ALL the writes (create/update/delete). The CalDAV
	// backend does check-then-act (AuthoritativeEventsByUID then
	// create/update): two concurrent PUTs of the same UID (owner's iPhone + Mac)
	// would both pass the check and create TWO Proton rows. Global and not
	// per-UID: the write volume of a family calendar does not justify sharding.
	// READS never take this lock (they stay concurrent, served from the store
	// under its RWMutex).
	writeMu gosync.Mutex
}

var (
	_ caldav.Source        = (*CachedSource)(nil)
	_ caldav.AliasResolver = (*CachedSource)(nil)
)

// NewCachedSource builds the cache wrapper on top of the real Source
// (typically *proton.Account) and the shadow store.
func NewCachedSource(src caldav.Source, st *store.Store) *CachedSource {
	return &CachedSource{src: src, st: st}
}

// ---- Reads: store only ----

// ListCalendars serves the list materialized by the last poller cycle.
func (c *CachedSource) ListCalendars(ctx context.Context) ([]proton.Calendar, error) {
	return c.st.Calendars(), nil
}

// ListEvents serves the window's events from the store.
func (c *CachedSource) ListEvents(ctx context.Context, calendarID string, start, end time.Time) ([]proton.Event, error) {
	return c.st.Events(calendarID, start, end), nil
}

// GetEvent serves an event from the store. An absent event (deleted by
// write-through or by the poller) answers ErrEventNotFound IMMEDIATELY — the
// backend maps it to 404, a clean disappearance for dataaccessd.
func (c *CachedSource) GetEvent(ctx context.Context, calendarID, eventID string) (*proton.Event, error) {
	ev, ok := c.st.Event(calendarID, eventID)
	if !ok {
		return nil, fmt.Errorf("store: event %s/%s: %w", calendarID, eventID, proton.ErrEventNotFound)
	}
	return &ev, nil
}

// ---- Writes: delegated then synchronous write-through ----

// CreateEvent delegates to the real Source then materializes the created event
// in the store before answering. Under writeMu, with an anti-duplicate
// RE-CHECK: the backend's existence check (AuthoritativeEventsByUID) happened
// BEFORE taking the lock — if a concurrent create of the same UID just
// succeeded (iPhone + Mac pushing the same event), re-creating would make a
// SECOND Proton row for the same UID. We then answer the existing row
// (idempotent no-op, same posture as the same-UID create of M2).
func (c *CachedSource) CreateEvent(ctx context.Context, calendarID string, in proton.EventInput) (string, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if in.UID != "" {
		// An exception-row (RecurrenceID set) legitimately coexists with its
		// same-UID master: the duplicate is a row with the SAME RecurrenceID
		// (0 = master/simple).
		var want int64
		if in.RecurrenceID != nil {
			want = in.RecurrenceID.Unix()
		}
		if rows, err := c.src.AuthoritativeEventsByUID(ctx, calendarID, in.UID); err == nil {
			for _, row := range rows {
				if row.RecurrenceID == want {
					log.Printf("cache: create deduplicated (UID already present, concurrent PUT?) cal=%s event=%s", short(calendarID), short(row.ID))
					return row.ID, nil
				}
			}
		}
		// Re-check failed: we attempt the create anyway (the backend's check,
		// fresher than nothing, already happened).
	}

	eventID, err := c.src.CreateEvent(ctx, calendarID, in)
	if err != nil {
		return "", err
	}
	c.writeThrough(ctx, "create", calendarID, eventID, in)
	return eventID, nil
}

// UpdateEvent delegates to the real Source then refreshes the event in the
// store before answering. Serialized under writeMu (see the field).
func (c *CachedSource) UpdateEvent(ctx context.Context, calendarID, eventID string, in proton.EventInput) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.src.UpdateEvent(ctx, calendarID, eventID, in); err != nil {
		return err
	}
	c.writeThrough(ctx, "update", calendarID, eventID, in)
	return nil
}

// DeleteEvent delegates to the real Source then removes the event from the
// store before answering: the next GET on the same href answers 404 from the
// cache, immediately. An ErrEventNotFound on the Proton side (row already gone)
// also purges the cache — in all cases the resource no longer exists. Deleting
// a MASTER (RecurrenceID == 0 in our mirror) purges the whole same-UID group,
// mirroring the batch-delete of proton.DeleteEvent.
func (c *CachedSource) DeleteEvent(ctx context.Context, calendarID, eventID string) error {
	// Serialized under writeMu (see the field) — a delete concurrent with an
	// update of the same UID must not interleave on the Proton side.
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// The UID and the role (master/exception) are read in the mirror BEFORE the
	// deletion — afterward, the row no longer exists anywhere.
	prev, known := c.st.Event(calendarID, eventID)

	err := c.src.DeleteEvent(ctx, calendarID, eventID)
	if err != nil && !errors.Is(err, proton.ErrEventNotFound) {
		return err
	}
	if known && prev.RecurrenceID == 0 && prev.UID != "" {
		if perr := c.st.DeleteEventsByUID(calendarID, prev.UID); perr != nil {
			log.Printf("store: persist after write-through delete (group): %v", perr)
		}
	} else if perr := c.st.DeleteEvent(calendarID, eventID); perr != nil {
		log.Printf("store: persist after write-through delete: %v", perr)
	}
	log.Printf("cache: write-through delete cal=%s event=%s", short(calendarID), short(eventID))
	return err
}

// ListEventsByUID (read folding) is served FROM THE STORE — same rule as the
// other reads: zero API call on a client request.
func (c *CachedSource) ListEventsByUID(ctx context.Context, calendarID, uid string) ([]proton.Event, error) {
	return c.st.EventsByUID(calendarID, uid), nil
}

// AuthoritativeEventsByUID (write routing) is delegated to the real Source
// (see the type doc): routing a folded PUT on a stale cache would create
// duplicate exception-rows or destroy a fresh edit on the Proton side.
func (c *CachedSource) AuthoritativeEventsByUID(ctx context.Context, calendarID, uid string) ([]proton.Event, error) {
	return c.src.AuthoritativeEventsByUID(ctx, calendarID, uid)
}

// UpdateAttendeeStatus (M6b, outbound RSVP) delegates the PARTSTAT PATCH to the
// real Source (dedicated attendee endpoint) THEN refreshes the row in the store
// — the PARTSTAT served to the client reflects the new status immediately,
// without waiting for the poller cycle. Serialized under writeMu like the other
// writes. Implements caldav.AttendeeStatusUpdater; typed no-op if the
// underlying Source cannot patch (never the case in prod: *proton.Account
// implements it).
func (c *CachedSource) UpdateAttendeeStatus(ctx context.Context, calendarID, eventID, attendeeID string, status int) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	updater, ok := c.src.(interface {
		UpdateAttendeeStatus(context.Context, string, string, string, int) error
	})
	if !ok {
		return fmt.Errorf("cache: the underlying Source does not support PARTSTAT updates")
	}
	if err := updater.UpdateAttendeeStatus(ctx, calendarID, eventID, attendeeID, status); err != nil {
		return err
	}
	// Authoritative re-read to refresh the served PARTSTAT (best-effort: the
	// poller will fix it anyway on the next cycle).
	if ev, err := c.src.GetEvent(ctx, calendarID, eventID); err == nil {
		if perr := c.st.UpsertEvent(*ev); perr != nil {
			log.Printf("store: persist after RSVP attendee: %v", perr)
		}
	}
	log.Printf("cache: write-through RSVP cal=%s event=%s status=%d", short(calendarID), short(eventID), status)
	return nil
}

// RecordAlias persists a client-name → row-ID alias (caldav.AliasResolver).
func (c *CachedSource) RecordAlias(calendarID, name, eventID string) {
	if err := c.st.SetAlias(calendarID, name, eventID); err != nil {
		log.Printf("store: persist creation alias: %v", err)
	}
}

// ResolveAlias resolves a client name to its row ID (caldav.AliasResolver).
func (c *CachedSource) ResolveAlias(calendarID, name string) (string, bool) {
	return c.st.ResolveAlias(calendarID, name)
}

// writeThrough materializes in the store the post-write state of an event.
// Nominal path: authoritative re-read from the real Source (fresh LastEdit →
// correct ETag). If the re-read fails, we synthesize the event from the input
// rather than leaving the cache STALE — a cache one write behind is exactly the
// bug we kill; the approximation (Sequence, LastEdit=now) is fixed on the next
// poller cycle.
func (c *CachedSource) writeThrough(ctx context.Context, op, calendarID, eventID string, in proton.EventInput) {
	ev, err := c.src.GetEvent(ctx, calendarID, eventID)
	if err != nil {
		log.Printf("cache: post-%s re-read impossible (%v) — synthesizing from the input", op, err)
		synth := c.synthesize(calendarID, eventID, in)
		ev = &synth
	}
	if perr := c.st.UpsertEvent(*ev); perr != nil {
		log.Printf("store: persist after write-through %s: %v", op, perr)
	}
	// One line per write-through, truncated IDs, never any event content
	// (personal data).
	log.Printf("cache: write-through %s cal=%s event=%s", op, short(calendarID), short(eventID))
}

// synthesize builds a fallback proton.Event from the EventInput accepted by
// Proton (all the modeled fields are there). The UID comes from the input
// (always set by the backend), otherwise from the existing cache entry;
// Sequence is advanced as best as possible from the existing one.
func (c *CachedSource) synthesize(calendarID, eventID string, in proton.EventInput) proton.Event {
	ev := proton.Event{
		ID:          eventID,
		UID:         in.UID,
		CalendarID:  calendarID,
		Title:       in.Title,
		Description: in.Description,
		Location:    in.Location,
		Start:       in.Start,
		End:         in.End,
		TZ:          in.TZID,
		EndTZ:       in.EndTZID,
		AllDay:      in.AllDay,
		RRule:       in.RRule,
		ExDates:     in.ExDates,
		LastEdit:    time.Now().UTC(),
	}
	if in.RecurrenceID != nil {
		// Exception-row: the mirror column RecurrenceID (folding by UID).
		ev.RecurrenceID = in.RecurrenceID.Unix()
	}
	// Invitation (M5a): reflect the organizer + guests from the input (Status 0
	// = NEEDS-ACTION, Token unknown here) — corrected on the authoritative
	// re-read or the next poller cycle.
	ev.Organizer = in.Organizer
	for _, at := range in.Attendees {
		ev.Attendees = append(ev.Attendees, proton.Attendee{Email: at.Email, CN: at.CN})
	}
	if prev, ok := c.st.Event(calendarID, eventID); ok {
		if ev.UID == "" {
			ev.UID = prev.UID
		}
		ev.Sequence = prev.Sequence + 1
	}
	return ev
}

// short truncates a Proton ID for the logs (enough to correlate, not enough to
// be exploitable data).
func short(id string) string {
	if len(id) > 8 {
		return id[:8] + "…"
	}
	return id
}

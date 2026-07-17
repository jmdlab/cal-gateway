package sync

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"github.com/jmdlab/cal-gateway/internal/caldav"
	"github.com/jmdlab/cal-gateway/internal/proton"
	"github.com/jmdlab/cal-gateway/internal/store"
)

// Window refreshed by the poller = the backend's service window (single
// source: internal/caldav) — the store must cover everything the backend can
// serve.
const (
	windowPast   = caldav.DefaultWindowPast
	windowFuture = caldav.DefaultWindowFuture
)

// defaultFullResyncEvery: periodicity of the safety full snapshot per calendar,
// even when the delta is running. Net against a delta that would have silently
// diverged (bug, botched cursor) — 6h = 4 full/day/calendar instead of 1440,
// the overwhelming majority of cycles stays in delta (~1 req).
const defaultFullResyncEvery = 6 * time.Hour

// deltaSource is the OPTIONAL subset of Source exposing the Proton calendar
// event-loop (cursor + typed deltas). The real Account implements it; a Source
// that does not (test fakes) falls back cleanly to the full snapshot every
// cycle — the historical behavior, never broken.
type deltaSource interface {
	LatestCalendarCursor(ctx context.Context, calendarID string) (string, error)
	CalendarEventChanges(ctx context.Context, calendarID, sinceCursor string) (proton.CalendarDelta, error)
}

// Poller periodically refreshes the shadow store from Proton: the calendar
// list then, per calendar, a full snapshot of the window's events
// (proton.Account.ListEvents already paginates the 93-day slices imposed by the
// API and the 4 Type buckets). Each cycle atomically replaces the content per
// calendar — UNLESS a write-through write happened during the fetch
// (per-generation guard, see store.ReplaceCalendarEvents): the stale snapshot
// is dropped, the next cycle reconciles.
type Poller struct {
	src      caldav.Source
	st       *store.Store
	interval time.Duration

	// fullEvery: periodicity of the safety full snapshot per calendar (see
	// defaultFullResyncEvery). lastFull stamps the last full snapshot APPLIED
	// per calendar — in process memory (SyncOnce is serialized by Run, never
	// concurrent). Zero value (boot, new calendar) = full due: we re-establish a
	// clean baseline before switching to delta.
	fullEvery time.Duration
	lastFull  map[string]time.Time

	// lastOK is the timestamp (UnixNano) of the last COMPLETE SyncOnce without
	// error — the freshness exposed by /healthz. 0 = no successful cycle since
	// the process started.
	lastOK atomic.Int64
}

// NewPoller builds the poller on the REAL Proton Source (never the
// CachedSource: it would serve itself from the store it feeds).
func NewPoller(src caldav.Source, st *store.Store, interval time.Duration) *Poller {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &Poller{
		src:       src,
		st:        st,
		interval:  interval,
		fullEvery: defaultFullResyncEvery,
		lastFull:  make(map[string]time.Time),
	}
}

// fullDue reports whether a calendar must redo a full snapshot (never done
// since this start, or the periodic full deadline exceeded).
func (p *Poller) fullDue(calID string) bool {
	last, ok := p.lastFull[calID]
	return !ok || time.Since(last) >= p.fullEvery
}

// Run loops until the context is cancelled: one cycle per interval. A cycle
// error is logged and does not stop the loop (the store keeps serving its last
// good state — the whole point of the cache).
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.SyncOnce(ctx); err != nil && ctx.Err() == nil {
				log.Printf("poller: cycle failed: %v", err)
			}
		}
	}
}

// SyncOnce runs one complete refresh cycle. A calendar in error does not block
// the others; errors are aggregated.
func (p *Poller) SyncOnce(ctx context.Context) error {
	t0 := time.Now()

	cals, err := p.src.ListCalendars(ctx)
	if err != nil {
		return fmt.Errorf("poller: listing calendars: %w", err)
	}
	// "Suspicious empty list" guard: the API answers but 0 ACTIVE calendar
	// while the store has some — a blip on the Proton side (flags dropped,
	// partial response) must NEVER empty the served calendar. We drop the whole
	// cycle; the next one will reconcile if the disappearance is real and
	// lasting.
	if len(cals) == 0 && len(p.st.Calendars()) > 0 {
		return errors.New("poller: 0 active calendar returned while the store has some — suspicious API blip, cycle ignored (nothing purged)")
	}
	if perr := p.st.ReplaceCalendars(cals); perr != nil {
		log.Printf("poller: persist calendars: %v", perr)
	}

	now := time.Now()
	start, end := now.Add(-windowPast), now.Add(windowFuture)

	// Event-loop delta if the Source exposes it (real Account); otherwise a full
	// snapshot every cycle (fallback, historical behavior).
	ds, _ := p.src.(deltaSource)

	var errs []error
	total, skipped, deltas, fulls := 0, 0, 0, 0
	for _, cal := range cals {
		// Generation BEFORE the fetch: if a write-through passes during the
		// fetch (several seconds), the snapshot/delta is dropped, never the
		// reverse.
		gen := p.st.Generation(cal.ID)
		touched, wasFull, replaced, err := p.syncCalendarEvents(ctx, ds, cal.ID, start, end, gen)
		if err != nil {
			errs = append(errs, fmt.Errorf("calendar %s: %w", short(cal.ID), err))
			continue
		}
		if wasFull {
			fulls++
		} else {
			deltas++
		}
		if !replaced {
			skipped++
			continue
		}
		total += touched
	}

	// One line per cycle: volumes + duration + delta/full split, never any event
	// content. Deltas dominant + low total = the perf goal reached.
	log.Printf("poller: cycle — %d calendars (%d delta, %d full), %d events touched, %d snapshot(s)/delta(s) dropped (concurrent write-through), %s",
		len(cals), deltas, fulls, total, skipped, time.Since(t0).Round(time.Millisecond))

	if err := errors.Join(errs...); err != nil {
		// Partial cycle: the calendars in error kept their content (continue
		// above), nothing was purged — and we mark neither the healthz freshness
		// nor the Synced flag.
		return err
	}
	p.lastOK.Store(time.Now().UnixNano())
	// First COMPLETE cycle succeeded: the store stops being "never synced"
	// (semantics of Empty(), readiness of the next boot). Set AFTER the
	// ReplaceCalendarEvents — never after ReplaceCalendars alone.
	if perr := p.st.MarkSynced(); perr != nil {
		log.Printf("poller: persist Synced flag: %v", perr)
	}
	return nil
}

// syncCalendarEvents refreshes ONE calendar. Preferred path: event-loop delta
// (ds != nil, cursor present, outside the periodic full deadline) — 1 request
// `modelevents/{cursor}`; cursor unchanged = 0 decryption, only the rows
// actually modified are re-GET+decrypted. Full snapshot path (first pass,
// server Refresh signal, safety full deadline, or a Source without delta): the
// old full ListEvents path, which then re-lays the baseline cursor. The
// per-generation guard (gen read before the fetch) is honored by
// ReplaceCalendarEvents AND ApplyCalendarDelta: a concurrent write-through
// drops the stale result (replaced=false), never the reverse.
//
// Returns the number of events touched, wasFull (delta vs full, for the log),
// replaced (false = result dropped by the generation guard), and the error.
func (p *Poller) syncCalendarEvents(ctx context.Context, ds deltaSource, calID string, start, end time.Time, gen uint64) (touched int, wasFull, replaced bool, err error) {
	cursor, hasCursor := p.st.Cursor(calID)

	// Delta path: capable Source + known baseline + not at the full deadline.
	if ds != nil && hasCursor && !p.fullDue(calID) {
		delta, derr := ds.CalendarEventChanges(ctx, calID, cursor)
		if derr != nil {
			return 0, false, false, derr
		}
		if !delta.Refresh {
			if len(delta.Upserts) == 0 && len(delta.DeletedIDs) == 0 {
				// Nothing to apply. Advance the cursor only if it moved (0
				// decryption, the ultra-frequent nominal case). Under gen guard.
				if delta.NewCursor != "" && delta.NewCursor != cursor {
					if _, aerr := p.st.ApplyCalendarDelta(calID, nil, nil, delta.NewCursor, gen); aerr != nil {
						log.Printf("poller: persist cursor for calendar %s: %v", short(calID), aerr)
					}
				}
				return 0, false, true, nil
			}
			applied, aerr := p.st.ApplyCalendarDelta(calID, delta.Upserts, delta.DeletedIDs, delta.NewCursor, gen)
			if aerr != nil {
				log.Printf("poller: persist delta for calendar %s: %v", short(calID), aerr)
			}
			if !applied {
				return 0, false, false, nil
			}
			return len(delta.Upserts) + len(delta.DeletedIDs), false, true, nil
		}
		// Server Refresh: cursor lost → fall through to the full snapshot below.
	}

	// Full snapshot path. Baseline read BEFORE the fetch so we miss no change
	// occurring during the snapshot (replayed on the next delta).
	var baseline string
	if ds != nil {
		if c, cerr := ds.LatestCalendarCursor(ctx, calID); cerr == nil {
			baseline = c
		} else {
			log.Printf("poller: baseline cursor for calendar %s unavailable: %v — delta deferred to the next full", short(calID), cerr)
		}
	}
	events, ferr := p.src.ListEvents(ctx, calID, start, end)
	if ferr != nil {
		return 0, true, false, ferr
	}
	ok, perr := p.st.ReplaceCalendarEvents(calID, events, gen)
	if perr != nil {
		log.Printf("poller: persist calendar %s: %v", short(calID), perr)
	}
	if !ok {
		return 0, true, false, nil
	}
	// Snapshot applied: lay the baseline cursor (if known) and the full clock.
	if baseline != "" {
		if cerr := p.st.SetCursor(calID, baseline); cerr != nil {
			log.Printf("poller: persist baseline cursor for calendar %s: %v", short(calID), cerr)
		}
	}
	p.lastFull[calID] = time.Now()
	return len(events), true, true, nil
}

// LastOK returns the timestamp of the last complete successful cycle (zero
// value = never since this start). Consumed by /healthz (internal/server).
func (p *Poller) LastOK() time.Time {
	n := p.lastOK.Load()
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n)
}

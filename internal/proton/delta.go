package proton

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// Proton CALENDAR event-loop (delta polling). Shape verified against the
// reference study (WebClients, packages/shared/lib/api/calendars.ts +
// interfaces/calendar/EventManager.ts) and modeled on the core event-loop of
// go-proton-api (GetLatestEventID / GetEvent):
//
//	GET /calendar/v1/{calID}/modelevents/latest
//	    → { CalendarModelEventID }  (the "now" cursor)
//	GET /calendar/v1/{calID}/modelevents/{lastEventID}
//	    → { CalendarModelEventID, More, Refresh,
//	         CalendarEvents: [ { ID, Action, Event? } ] }
//
// Action follows EVENT_ACTIONS (WebClients constants.ts): 0=delete, 1=create,
// 2=update. Refresh != 0 means "re-synchronize everything" (cursor lost on the
// server side, too far behind) → the caller redoes a full snapshot. More=1 is
// pagination: follow the new cursor. The Event payload of create/update is
// "without blob" (no encrypted card): we RE-GET the full row to decrypt it,
// exactly like ListEvents — so folding by UID and aliases stay consistent.
const (
	calEventActionDelete = 0
	calEventActionCreate = 1
	calEventActionUpdate = 2

	// Anti-loop guardrail: cap on the number of pages within a single delta
	// call (the server should never chain that many pages; beyond it we switch
	// to a refresh rather than spinning forever on a cursor that does not
	// advance).
	maxDeltaPages = 1000
)

// CalendarDelta is the consolidated result of a sweep of the calendar
// event-loop from a cursor: the rows to upsert (ALREADY decrypted), the IDs to
// delete, the cursor to remember, and Refresh=true when the server demands a
// full re-sync (the rest is then empty, only the full snapshot matters).
type CalendarDelta struct {
	Upserts    []Event
	DeletedIDs []string
	NewCursor  string
	Refresh    bool
}

// calendarLatestCursor is the response of …/modelevents/latest.
type calendarLatestCursor struct {
	CalendarModelEventID string
}

// calendarEventChange is an entry of CalendarEvents[]: the row ID and the
// action. The Event blob (without-blob) is ignored — we re-GET the row to
// obtain the encrypted cards.
type calendarEventChange struct {
	ID     string
	Action int
}

// calendarModelEventsPage is a page of …/modelevents/{cursor}.
type calendarModelEventsPage struct {
	CalendarModelEventID string
	More                 int
	Refresh              int
	CalendarEvents       []calendarEventChange
}

// LatestCalendarCursor returns the "now" cursor of a calendar's event-loop
// (GET …/modelevents/latest). Used to set the baseline just BEFORE a full
// snapshot: any change occurring during the snapshot will be replayed on the
// next delta cycle (at worst a redundant re-decryption, never a loss). Goes
// through doAuthed (captured resty) — the poller always calls ListCalendars
// first, so the client is captured.
func (a *Account) LatestCalendarCursor(ctx context.Context, calendarID string) (string, error) {
	var res calendarLatestCursor
	path := "/calendar/v1/" + calendarID + "/modelevents/latest"
	if err := a.doAuthed(ctx, http.MethodGet, path, nil, &res); err != nil {
		return "", fmt.Errorf("proton: latest model-event cursor for calendar %s: %w", calendarID, err)
	}
	if res.CalendarModelEventID == "" {
		return "", fmt.Errorf("proton: empty model-event cursor for calendar %s", calendarID)
	}
	return res.CalendarModelEventID, nil
}

// CalendarEventChanges sweeps a calendar's event-loop from sinceCursor and
// returns the consolidated delta. Paginates on More; on Refresh != 0, returns
// Refresh=true immediately (the caller does a full snapshot). Created/updated
// rows are RE-GET then decrypted (like ListEvents) — ONLY the rows that
// actually changed are decrypted (0 decryptions if nothing moved). Actions are
// consolidated by ID (last action wins, order of first appearance preserved):
// create-then-delete within the same sweep = a single deletion, never an
// upsert of a vanished event.
func (a *Account) CalendarEventChanges(ctx context.Context, calendarID, sinceCursor string) (CalendarDelta, error) {
	// Keyring ready before any row GET — same primitive as ListEvents.
	calKR, err := a.calendarKeyRing(ctx, calendarID)
	if err != nil {
		return CalendarDelta{}, err
	}

	cursor := sinceCursor
	final := make(map[string]int)
	order := make([]string, 0)

	for page := 0; ; page++ {
		if page >= maxDeltaPages {
			// The cursor is no longer advancing fast enough: treat as a refresh
			// (full snapshot) rather than looping indefinitely.
			return CalendarDelta{Refresh: true, NewCursor: cursor}, nil
		}
		var res calendarModelEventsPage
		path := "/calendar/v1/" + calendarID + "/modelevents/" + cursor
		if derr := a.doAuthed(ctx, http.MethodGet, path, nil, &res); derr != nil {
			return CalendarDelta{}, fmt.Errorf("proton: model events for calendar %s: %w", calendarID, derr)
		}
		if res.Refresh != 0 {
			// Cursor stale on the server side: nothing is reliable, full re-sync.
			return CalendarDelta{Refresh: true, NewCursor: res.CalendarModelEventID}, nil
		}
		for _, ch := range res.CalendarEvents {
			if _, seen := final[ch.ID]; !seen {
				order = append(order, ch.ID)
			}
			final[ch.ID] = ch.Action
		}
		// Cursor that does not advance (More=1 but same ID) = effectively the
		// end, we stop to avoid looping.
		if res.CalendarModelEventID == "" || res.CalendarModelEventID == cursor {
			cursor = res.CalendarModelEventID
			break
		}
		cursor = res.CalendarModelEventID
		if res.More != 1 {
			break
		}
	}

	delta := CalendarDelta{NewCursor: cursor}
	for _, id := range order {
		switch final[id] {
		case calEventActionDelete:
			delta.DeletedIDs = append(delta.DeletedIDs, id)
		case calEventActionCreate, calEventActionUpdate:
			row, rerr := a.getEventRow(ctx, calendarID, id)
			if errors.Is(rerr, ErrEventNotFound) {
				// Created/updated THEN deleted after our page: gone on the
				// Proton side → deletion (never an upsert of a phantom row).
				delta.DeletedIDs = append(delta.DeletedIDs, id)
				continue
			}
			if rerr != nil {
				return CalendarDelta{}, rerr
			}
			ev := a.decryptEvent(row.CalendarEvent, row.AddressKeyPacket, calKR)
			ev.Notifications = parseNotifications(row.Notifications)
			ev.RecurrenceID = row.RecurrenceID
			delta.Upserts = append(delta.Upserts, ev)
		default:
			// Unknown action: ignored (lenient, like reading events).
		}
	}
	return delta, nil
}

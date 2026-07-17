// Package caldav exposes Proton calendars over CalDAV via go-webdav.
//
// M1 = READ-ONLY mirror: every read method is served from internal/proton
// (on-the-fly decryption); write methods return 403 with an explicit message.
// TODO M3: serve from the shadow store (internal/store) fed by the poller,
// never again hitting the Proton API directly on a client request.
package caldav

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-ical"
	"github.com/emersion/go-webdav"
	webcaldav "github.com/emersion/go-webdav/caldav"

	"github.com/jmdlab/cal-gateway/internal/invite"
	"github.com/jmdlab/cal-gateway/internal/proton"
)

// Default window served when the client does not bound its request (deep
// PROPFIND, REPORT without a time-range): a "living agenda" mirror.
const (
	// Exported: the poller (internal/sync) must cover exactly the same window
	// as the backend, otherwise the cache would have holes.
	DefaultWindowPast   = 180 * 24 * time.Hour // 6 months back
	DefaultWindowFuture = 365 * 24 * time.Hour // 12 months forward
)

// maxInviteesPerEvent bounds the number of invitees on an outgoing event: a
// ceiling on the "send mail via the account owner's account" capability
// (security audit 2026-07-16, P1-a), well above normal family usage.
const maxInviteesPerEvent = 20

// Path layout:
//
//	/                                     root (serves current-user-principal)
//	/{user}/                              current principal
//	/{user}/calendars/                    home set
//	/{user}/calendars/{calID}/            calendar collection
//	/{user}/calendars/{calID}/{evID}.ics  event object (evID = Proton row ID)
//
// go-webdav v0.7.0 CONSTRAINT (caldav/server.go, resourceTypeAtPath): the
// resource type is inferred from the path DEPTH — 1 segment = principal,
// 2 = home set, 3 = calendar, 4 = object. The principal therefore CANNOT be
// "/" (the root never serves calendar-home-set) and the home set cannot be at
// depth 1 (it would be routed as a principal and compared — without matching —
// to CurrentUserPrincipal, yielding an empty multistatus without ever calling
// ListCalendars). Hence the mandatory {user} segment.

// Source is what the backend consumes from internal/proton. An interface so
// unit tests can use a simulated account, with no network.
type Source interface {
	ListCalendars(ctx context.Context) ([]proton.Calendar, error)
	ListEvents(ctx context.Context, calendarID string, start, end time.Time) ([]proton.Event, error)
	GetEvent(ctx context.Context, calendarID, eventID string) (*proton.Event, error)

	// ListEventsByUID returns ALL rows of a UID (master + exception-rows),
	// sorted master first then by ascending RecurrenceID — the primitive of
	// READ folding (1 UID = 1 CalDAV resource, M4). A caching wrapper MAY serve
	// it from its local mirror.
	ListEventsByUID(ctx context.Context, calendarID, uid string) ([]proton.Event, error)
	// AuthoritativeEventsByUID: same content, but ALWAYS the real Proton state
	// — the guardrail of the WRITE ROUTING of a folded PUT (routing on a stale
	// cache would create duplicate exception-rows or destroy a fresh edit made
	// in the Proton app).
	AuthoritativeEventsByUID(ctx context.Context, calendarID, uid string) ([]proton.Event, error)

	// Write half (M2/M3). CreateEvent encrypts+creates an event (an
	// exception-row when in.RecurrenceID is set) and returns its Proton row ID.
	// UpdateEvent modifies an existing event by in-place merge of the modelled
	// fields (everything else kept verbatim in Proton). DeleteEvent deletes a
	// row (a master: ALL same-UID rows, in one sync call).
	CreateEvent(ctx context.Context, calendarID string, in proton.EventInput) (string, error)
	UpdateEvent(ctx context.Context, calendarID, eventID string, in proton.EventInput) error
	DeleteEvent(ctx context.Context, calendarID, eventID string) error
}

// AliasResolver is the OPTIONAL contract (implemented by CachedSource) for
// creation aliases: on PUT the client chooses the resource name (typically
// {uid}.ics); we answer 201 + Location to {rowID}.ics (a server rename, legal)
// BUT the original name must stay resolvable — dataaccessd may re-GET it before
// it has picked up the Location, and a bare 404 at that instant disorients it.
// Without an implementation (bare Account, tests), the GET of the original name
// stays a 404 — the prod path goes through CachedSource.
type AliasResolver interface {
	RecordAlias(calendarID, name, eventID string)
	ResolveAlias(calendarID, name string) (eventID string, ok bool)
}

// InviteSender sends the iMIP email of ONE invitation (implemented by
// invite.Sender in prod, by a fake in tests). See ConfigureInvites.
type InviteSender interface {
	Send(ctx context.Context, m invite.Message) error
}

// AttendeeStatusUpdater is the OPTIONAL contract (implemented by *proton.Account,
// delegated by CachedSource) that patches the PARTSTAT of ONE attendee via the
// dedicated endpoint — outgoing RSVP (M6b): when the account owner replies to a
// received invitation, we update THEIR row in Proton without rewriting the
// third party's event. Status: 0=NEEDS-ACTION, 1=TENTATIVE, 2=DECLINED, 3=ACCEPTED.
type AttendeeStatusUpdater interface {
	UpdateAttendeeStatus(ctx context.Context, calendarID, eventID, attendeeID string, status int) error
}

// Backend implements webcaldav.Backend (read half) on top of a Source.
type Backend struct {
	src           Source
	principalPath string // "/{user}/"
	homeSetPath   string // "/{user}/calendars/"

	// Outgoing-invitation policy (M5a), see ConfigureInvites.
	owners         map[string]bool // Proton account addresses (lowercase)
	inviteSender   InviteSender    // nil = invitations disabled (403)
	inviteFromName string          // display name of the sender
	inviteQuota    inviteRateLimiter
}

// NewBackend builds the read-only CalDAV backend. username is the gateway's
// Basic-auth identifier; it becomes the first path segment (principal), escaped
// so it stays a valid URL segment.
func NewBackend(src Source, username string) *Backend {
	seg := url.PathEscape(username)
	if seg == "" {
		seg = "user"
	}
	principal := "/" + seg + "/"
	return &Backend{
		src:           src,
		principalPath: principal,
		homeSetPath:   principal + "calendars/",
	}
}

// ConfigureInvites arms the outgoing-invitation policy (M5a):
// ownerAddresses = addresses of the bridged Proton account (a PUT's ORGANIZER
// must be one of them to be an OUTGOING invitation — otherwise it is a received
// booking, attendees stripped as since M3); sender = iMIP transport (nil or
// empty owners = invitations disabled: an outgoing PUT with ATTENDEE → 403, the
// pre-M5a behavior); fromName = display name.
func (b *Backend) ConfigureInvites(ownerAddresses []string, fromName string, sender InviteSender) {
	b.owners = make(map[string]bool, len(ownerAddresses))
	for _, a := range ownerAddresses {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			b.owners[a] = true
		}
	}
	b.inviteSender = sender
	b.inviteFromName = fromName
}

// isOwner recognizes a Proton account address (case-insensitive).
func (b *Backend) isOwner(email string) bool {
	return email != "" && b.owners[strings.ToLower(email)]
}

var _ webcaldav.Backend = (*Backend)(nil)

// CurrentUserPrincipal: one account per gateway, fixed principal /{user}/.
func (b *Backend) CurrentUserPrincipal(ctx context.Context) (string, error) {
	return b.principalPath, nil
}

// CalendarHomeSetPath: all calendars live under /{user}/calendars/.
func (b *Backend) CalendarHomeSetPath(ctx context.Context) (string, error) {
	return b.homeSetPath, nil
}

// ListCalendars maps Proton calendars into CalDAV collections.
func (b *Backend) ListCalendars(ctx context.Context) ([]webcaldav.Calendar, error) {
	cals, err := b.src.ListCalendars(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]webcaldav.Calendar, 0, len(cals))
	for _, c := range cals {
		out = append(out, webcaldav.Calendar{
			Path:                  b.calendarPath(c.ID),
			Name:                  c.Name,
			Description:           c.Description,
			SupportedComponentSet: []string{ical.CompEvent},
		})
	}
	return out, nil
}

// GetCalendar looks up a collection by path.
func (b *Backend) GetCalendar(ctx context.Context, urlPath string) (*webcaldav.Calendar, error) {
	calID, _, err := b.parsePath(urlPath)
	if err != nil {
		return nil, err
	}
	cals, err := b.ListCalendars(ctx)
	if err != nil {
		return nil, err
	}
	want := b.calendarPath(calID)
	for i := range cals {
		if cals[i].Path == want {
			return &cals[i], nil
		}
	}
	return nil, webdav.NewHTTPError(http.StatusNotFound, fmt.Errorf("caldav: calendar %s not found", calID))
}

// GetCalendarObject serves a resource: a simple event as-is, or a folded
// RECURRING series (master + same-UID exception-rows in ONE VCALENDAR, anchored
// on the master's href). The href of a row folded under its anchor answers 404
// — the canonical resource is the anchor's.
func (b *Backend) GetCalendarObject(ctx context.Context, urlPath string, req *webcaldav.CalendarCompRequest) (*webcaldav.CalendarObject, error) {
	calID, eventID, err := b.parsePath(urlPath)
	if err != nil {
		return nil, err
	}
	if eventID == "" {
		return nil, webdav.NewHTTPError(http.StatusNotFound, errors.New("caldav: not a calendar object path"))
	}
	ev, err := b.src.GetEvent(ctx, calID, eventID)
	if err != nil && errors.Is(err, proton.ErrEventNotFound) {
		// Resource name chosen by the client at the creation PUT (alias
		// uid→rowID): resolvable as long as the client has not switched to the
		// 201's Location (see AliasResolver).
		if ar, ok := b.src.(AliasResolver); ok {
			if id, found := ar.ResolveAlias(calID, eventID); found {
				ev, err = b.src.GetEvent(ctx, calID, id)
			}
		}
	}
	if err != nil {
		// An event deleted on the Proton side must vanish CLEANLY (404 in the
		// multistatus) — not leak as a 500, which makes dataaccessd re-loop on
		// the phantom href after a successful DELETE.
		return nil, mapSourceError(err)
	}

	if ev.RRule == "" && ev.RecurrenceID == 0 {
		return b.toObject(*ev)
	}
	// Row of a series: serve the full folded group. Lenient fallback to the
	// single row if the group is unrecoverable (never a broken collection).
	group, gerr := b.src.ListEventsByUID(ctx, calID, ev.UID)
	if gerr != nil || len(group) == 0 {
		return b.toObject(*ev)
	}
	folded, extras, ferr := b.foldGroup(group)
	if ferr != nil {
		return b.toObject(*ev)
	}
	if folded.Path == b.objectPath(calID, ev.ID) {
		return folded, nil
	}
	// Supernumerary master (degenerate data): served as a separate resource.
	for i := range extras {
		if extras[i].ID == ev.ID {
			return b.toObject(extras[i])
		}
	}
	return nil, webdav.NewHTTPError(http.StatusNotFound,
		fmt.Errorf("caldav: event %s is folded under %s", ev.ID, folded.Path))
}

// ListCalendarObjects enumerates the events of the default window.
func (b *Backend) ListCalendarObjects(ctx context.Context, urlPath string, req *webcaldav.CalendarCompRequest) ([]webcaldav.CalendarObject, error) {
	calID, _, err := b.parsePath(urlPath)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return b.objectsInWindow(ctx, calID, now.Add(-DefaultWindowPast), now.Add(DefaultWindowFuture))
}

// QueryCalendarObjects serves a calendar-query REPORT: the window is taken from
// the filter's time-range when there is one, then the full filter is applied by
// the official webcaldav.Filter helper.
func (b *Backend) QueryCalendarObjects(ctx context.Context, urlPath string, query *webcaldav.CalendarQuery) ([]webcaldav.CalendarObject, error) {
	calID, _, err := b.parsePath(urlPath)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	start, end := now.Add(-DefaultWindowPast), now.Add(DefaultWindowFuture)
	if query != nil {
		if qs, qe, ok := timeRange(query.CompFilter); ok {
			if !qs.IsZero() {
				start = qs
			}
			if !qe.IsZero() {
				end = qe
			}
		}
	}

	objs, err := b.objectsInWindow(ctx, calID, start, end)
	if err != nil {
		return nil, err
	}
	return webcaldav.Filter(query, objs)
}

// ---- Writes ----
// M2 = create, M3 = update: PutCalendarObject parses the incoming ICS and
// routes by UID — unknown → CreateEvent (4 encrypted cards), known →
// UpdateEvent (in-place merge, session keys reused). DeleteCalendarObject
// deletes the row. CreateCalendar stays refused. NO MORE no-op 2xx: every
// unsupported path answers an honest code (403/404), otherwise the client never
// converges (cf. the "Error 2" bug: 201 without writing → EXDATE lost → loop).

// errNoCalendarCreate: creating a Proton calendar requires generating + sharing
// a calendar keyring — out of M2 scope (the third-party booking case writes
// into an existing calendar).
var errNoCalendarCreate = errors.New("cal-gateway does not support creating calendars; write events into an existing Proton calendar")

func (b *Backend) CreateCalendar(ctx context.Context, calendar *webcaldav.Calendar) error {
	return webdav.NewHTTPError(http.StatusForbidden, errNoCalendarCreate)
}

// PutCalendarObject routes the ICS PUT by the client — Apple always sends the
// COMPLETE STATE of the resource (master + all RECURRENCE-ID overrides, never a
// delta), and our mirror follows it faithfully:
//   - UID absent from Proton → CreateEvent of the master (third-party booking
//     case), plus one exception-row per RECURRENCE-ID child of the same PUT.
//   - existing master → UpdateEvent (in-place merge M3); its exception-rows are
//     RECONCILED from the payload: child with a row → update, child without a
//     row → CreateEvent of an exception-row (master's UID, SEQUENCE ≥ master),
//     row absent from the PUT → DeleteEvent (the matching EXDATE is already in
//     the master when the occurrence is deleted — Apple puts it there, we never
//     add it ourselves).
//   - RANGE=THISANDFUTURE (op. 5) → 403 (no Proton equivalent, M5 design).
//   - Undecryptable original event → honest 403, never a loss.
//
// Stale If-Match → 412 (RFC 7232): the client re-syncs and replays, instead of
// overwriting a state it never saw (the "Error 2" banner seen in prod).
func (b *Backend) PutCalendarObject(ctx context.Context, urlPath string, calendar *ical.Calendar, opts *webcaldav.PutCalendarObjectOptions) (*webcaldav.CalendarObject, error) {
	calID, resName, err := b.parsePath(urlPath)
	if err != nil {
		return nil, err
	}
	if calID == "" || resName == "" {
		return nil, webdav.NewHTTPError(http.StatusForbidden, errors.New("caldav: cannot PUT onto a collection path"))
	}

	// Invites (third-party booking, etc.) carry METHOD:PUBLISH; a collection
	// resource MUST NOT carry METHOD (RFC 4791) — we strip it first of all.
	calendar.Props.Del(ical.PropMethod)

	series, err := icalToSeriesInput(calendar)
	if err != nil {
		// Any gatekeeping refusal (THISANDFUTURE, floating time, RRULE
		// limits…) wraps errICalRefused → honest 403; the rest is a malformed
		// ICS → 400.
		if errors.Is(err, errICalRefused) {
			return nil, webdav.NewHTTPError(http.StatusForbidden, err)
		}
		return nil, webdav.NewHTTPError(http.StatusBadRequest, err)
	}

	// AUTHORITATIVE Proton state of the same-UID group (never the cache: routing
	// on a stale state would create duplicates or destroy a fresh edit on the
	// Proton app side). An error NEVER falls back to a create.
	rows, err := b.src.AuthoritativeEventsByUID(ctx, calID, series.uid)
	if err != nil {
		return nil, fmt.Errorf("caldav: resolving UID %s on calendar %s: %w", series.uid, calID, err)
	}
	var masterRow *proton.Event
	exceptions := make(map[int64]proton.Event) // occurrence (epoch) → row
	for i := range rows {
		if rows[i].RecurrenceID == 0 {
			if masterRow == nil {
				masterRow = &rows[i]
			}
			// Supernumerary master (degenerate data): out of routing.
		} else {
			exceptions[rows[i].RecurrenceID] = rows[i]
		}
	}

	if err := b.checkPreconditions(opts, rows); err != nil {
		return nil, err
	}

	sendInvites, lifecycle, rsvp, handled, err := b.decideInvitePolicy(ctx, calID, series, masterRow, exceptions)
	if handled {
		return rsvp, err
	}
	if err != nil {
		return nil, err
	}

	anchorID, err := b.reconcileSeriesWrite(ctx, calID, resName, series, masterRow, exceptions, sendInvites, lifecycle)
	if err != nil {
		return nil, err
	}

	return b.putResponse(ctx, calID, series.uid, anchorID)
}

// checkPreconditions enforces the conditional-PUT headers.
//
// Conditional update (RFC 7232): dataaccessd sends If-Match with the etag of
// ITS copy. If it is stale (the resource changed on the server side since its
// last sync — another device, the Proton app, a repair…), we answer 412: the
// client re-syncs and replays cleanly, instead of overwriting a state it never
// saw and then detecting the inconsistency (the "Error 2" banner seen in prod
// on 2026-07-16 on exactly this scenario). Returns nil when the preconditions
// pass.
func (b *Backend) checkPreconditions(opts *webcaldav.PutCalendarObjectOptions, rows []proton.Event) error {
	if opts != nil && opts.IfMatch.IsSet() && !opts.IfMatch.IsWildcard() {
		want, err := opts.IfMatch.ETag()
		if err != nil {
			return webdav.NewHTTPError(http.StatusBadRequest, err)
		}
		if len(rows) == 0 {
			return webdav.NewHTTPError(http.StatusPreconditionFailed,
				errors.New("caldav: If-Match on a resource that no longer exists"))
		}
		if cur := groupETag(sortSeriesRows(rows)); want != cur {
			return webdav.NewHTTPError(http.StatusPreconditionFailed,
				fmt.Errorf("caldav: If-Match %q stale (current %q)", want, cur))
		}
	}
	// If-None-Match: * = strict creation — refuse if the resource already exists.
	if opts != nil && opts.IfNoneMatch.IsWildcard() && len(rows) > 0 {
		return webdav.NewHTTPError(http.StatusPreconditionFailed,
			errors.New("caldav: resource already exists (If-None-Match: *)"))
	}
	return nil
}

// decideInvitePolicy resolves the invitation policy of a PUT (M5a creation, M5b
// lifecycle) — FEATURE-MATRIX §3 ATTENDEE. Decided HERE (no longer in the
// putguard middleware): only the backend knows whether the UID exists (create
// vs update) and whether the ORGANIZER is an account address (outgoing vs
// incoming).
//   - outgoing CREATION (ORGANIZER = account, unknown UID): written with
//     invitees THEN iMIP REQUEST emails — the whole series included (C-3, the
//     invitation ICS carries the RRULE);
//   - UPDATE of an invited event (M5b): event diff + invitee diff → REQUEST
//     (SEQUENCE bumped) to the kept ones if the when/where changes, REQUEST to
//     the added ones, CANCEL to the removed ones; cosmetic diff
//     (SUMMARY/DESCRIPTION/alarms) = update WITHOUT re-notification;
//   - editing an OCCURRENCE of an invited series → 403 (M6: per-RECURRENCE-ID
//     REQUEST not emitted); invited event organized by a THIRD PARTY → 403;
//     invitations disabled → 403 (pre-M5a preserved);
//   - incoming (third-party/undeterminable ORGANIZER, third-party booking case):
//     attendees STRIPPED, the bare event is stored — unchanged since M3.
//
// handled==true means "return rsvp, err from PutCalendarObject immediately" (the
// M6b outgoing-RSVP path already produced the response). Otherwise the caller
// proceeds with sendInvites/lifecycle. This helper mutates series in place
// (attendee stripping, AttendeesReplace) — the mutations propagate through
// series.master (pointer) and the shared series.children backing array.
func (b *Backend) decideInvitePolicy(ctx context.Context, calID string, series seriesInput, masterRow *proton.Event, exceptions map[int64]proton.Event) (sendInvites bool, lifecycle *invitePlan, rsvp *webcaldav.CalendarObject, handled bool, err error) {
	if series.master != nil {
		// M6b — OUTGOING RSVP: a PUT that changes ONLY the PARTSTAT of the
		// account owner's own row on a THIRD-PARTY-ORGANIZED event is not a
		// forbidden rewrite: it is a reply (accept/decline/tentative). We emit an
		// iMIP REPLY to the organizer + patch the account owner's row via the
		// dedicated endpoint, without ever touching the third party's event. Any
		// other change falls back to the 403 ATTENDEE-FOREIGN below.
		if b.inviteSender != nil && masterRow != nil && len(masterRow.Attendees) > 0 &&
			!b.isOwner(masterRow.Organizer) && len(series.children) == 0 && len(exceptions) == 0 {
			if reply, ok := b.detectOwnRSVP(*series.master, *masterRow); ok {
				obj, rerr := b.handleOutgoingRSVP(ctx, calID, series.uid, masterRow, reply)
				return false, nil, obj, true, rerr
			}
		}
		if len(series.master.Attendees) > 0 && !b.isOwner(series.master.Organizer) {
			series.master.Attendees = nil
			series.master.Organizer, series.master.OrganizerCN = "", ""
		}
		putAtts := len(series.master.Attendees) > 0
		rowAtts := masterRow != nil && len(masterRow.Attendees) > 0
		switch {
		case !putAtts && !rowAtts:
			// No invitee in the PUT nor on the Proton side: nothing to decide.
		case b.inviteSender == nil:
			return false, nil, nil, false, webdav.NewHTTPError(http.StatusForbidden,
				fmt.Errorf("%w: outgoing invitations (ATTENDEE) are disabled — enable the [invite] config section", errICalRefused))
		case rowAtts && !b.isOwner(masterRow.Organizer):
			// RECEIVED invitation (organized by a third party, synced from the
			// Proton app): the gateway is not the organizer — modifying it would
			// falsify the state at the organizer and the other invitees. Honest
			// refusal, edit in the Proton app.
			return false, nil, nil, false, webdav.NewHTTPError(http.StatusForbidden,
				fmt.Errorf("%w: ATTENDEE-FOREIGN — this event is organized by %s; edit it in a Proton client", errICalRefused, masterRow.Organizer))
		case len(series.children) > 0 || len(exceptions) > 0:
			// Edited occurrence of an invited series (RECURRENCE-ID child or
			// existing exception-row): the per-occurrence REQUEST/CANCEL is not
			// emitted yet (M6) — honest refusal, never a silently un-notified
			// edit.
			return false, nil, nil, false, webdav.NewHTTPError(http.StatusForbidden,
				fmt.Errorf("%w: ATTENDEE-RECURRING — editing single occurrences of an invited series is not supported yet (M6)", errICalRefused))
		case len(series.master.Attendees) > maxInviteesPerEvent:
			// SECURITY (audit 2026-07-16, P1-a): bounds the "send mail as the
			// account owner" capability — a PUT must not be able to trigger a
			// mass send, even authenticated. The ceiling also covers the invitees
			// ADDED in an update (the full set is bounded).
			return false, nil, nil, false, webdav.NewHTTPError(http.StatusForbidden,
				fmt.Errorf("%w: ATTENDEE-LIMIT — at most %d invitees per event", errICalRefused, maxInviteesPerEvent))
		case masterRow == nil:
			sendInvites = true // outgoing creation: write THEN send
		default:
			// UPDATE of an invited event: notification plan (significant/cosmetic
			// diff + added/removed invitees), sent AFTER the Proton sync succeeds.
			lifecycle = b.planInviteLifecycle(*series.master, *masterRow)
			series.master.AttendeesReplace = lifecycle.attendeesChanged()
		}
	}
	// Exception-rows never carry invitees (editing an occurrence of an invited
	// series is refused above; incoming is stripped) — defensive strip.
	for i := range series.children {
		series.children[i].in.Attendees = nil
		series.children[i].in.Organizer, series.children[i].in.OrganizerCN = "", ""
	}
	return sendInvites, lifecycle, nil, false, nil
}

// reconcileSeriesWrite performs the Proton create/update/delete calls for the
// master and its overrides, in identical order of side effects, and returns the
// anchor row ID for the response. sendInvites/lifecycle are the invitation
// decisions taken earlier by decideInvitePolicy.
func (b *Backend) reconcileSeriesWrite(ctx context.Context, calID, resName string, series seriesInput, masterRow *proton.Event, exceptions map[int64]proton.Event, sendInvites bool, lifecycle *invitePlan) (anchorID string, err error) {
	// masterSeq bounds the SEQUENCE of the CREATED exception-rows: the server
	// requires SEQUENCE ≥ that of the master (code 2001 otherwise — study
	// reference, event/smart.go). masterRow.Sequence+1 also covers the bump of a
	// structural update in the same PUT.
	masterSeq := 0
	switch {
	case series.master != nil && masterRow == nil:
		// Creation of the series (or of a simple event).
		id, cerr := b.src.CreateEvent(ctx, calID, *series.master)
		if cerr != nil {
			return "", cerr
		}
		anchorID = id
		// The resource name chosen by the client must stay resolvable until it
		// has picked up the 201's Location (see AliasResolver).
		if resName != id {
			if ar, ok := b.src.(AliasResolver); ok {
				ar.RecordAlias(calID, resName, id)
			}
		}
		// Outgoing invitation (M5a): the emails leave AFTER the Proton sync
		// succeeds — never before (if the sync fails, no email). A send failure
		// does NOT fail the PUT: the event exists, the calendar state is true —
		// we answer 201 and log per recipient.
		if sendInvites {
			b.sendInvitations(ctx, *series.master)
		}
	case series.master != nil:
		in := *series.master
		// The reconciliation of exception-rows is done HERE, from the same
		// payload — the master update's anti-corruption guard is lifted.
		in.SeriesManaged = true
		// History-overwrite guard (2026-07-16): Apple sends only the EXDATE it
		// DISPLAYS — its resync horizon purges past cancellations (46 values lost
		// on the recurring-master corruption case master). Existing STRICTLY past
		// EXDATE always survive; the client stays master of today/future
		// (FEATURE-MATRIX §2).
		if in.RRule != "" {
			in.ExDates = mergePastExDates(masterRow.ExDates, in.ExDates, time.Now().UTC())
		}
		// The notification plan compares the EXDATE actually WRITTEN (merged
		// set) — otherwise the SEQUENCE announced in the iMIP could diverge from
		// the card's (bump decided by diffPatches on the merged set).
		if lifecycle != nil {
			lifecycle.refreshSignificance(in, *masterRow)
		}
		if uerr := b.src.UpdateEvent(ctx, calID, masterRow.ID, in); uerr != nil {
			return "", mapSourceError(uerr)
		}
		anchorID = masterRow.ID
		masterSeq = masterRow.Sequence + 1
		// iMIP lifecycle notifications (M5b): AFTER the Proton sync succeeds,
		// best-effort — same posture as M5a (a send failure does not fail the
		// PUT, log ERROR per recipient).
		if lifecycle != nil {
			b.sendLifecycleInvitations(ctx, lifecycle)
		}
	default:
		// PUT without a master: only the round-trip of an ORPHAN resource
		// (exception-rows without a master, served folded together) is allowed.
		// An existing Proton master = incomplete state → honest refusal.
		if masterRow != nil {
			return "", webdav.NewHTTPError(http.StatusForbidden,
				fmt.Errorf("%w: the series master is missing from the PUT body", errICalRefused))
		}
		if len(exceptions) == 0 {
			return "", webdav.NewHTTPError(http.StatusForbidden, errOrphanOverride)
		}
	}

	// Reconciliation of the overrides: the payload is the complete desired state.
	seen := make(map[int64]bool, len(series.children))
	for _, child := range series.children {
		occ := child.occurrence.Unix()
		seen[occ] = true
		if row, ok := exceptions[occ]; ok {
			if uerr := b.src.UpdateEvent(ctx, calID, row.ID, child.in); uerr != nil {
				return "", mapSourceError(uerr)
			}
			continue
		}
		if series.master == nil && masterRow == nil {
			// New override with no attachable series (orphan resource): never an
			// exception-row created out of nothing.
			return "", webdav.NewHTTPError(http.StatusForbidden, errOrphanOverride)
		}
		in := child.in
		in.UID = series.uid
		in.Sequence = masterSeq
		if _, cerr := b.src.CreateEvent(ctx, calID, in); cerr != nil {
			return "", cerr
		}
	}
	for occ, row := range exceptions {
		if seen[occ] {
			continue
		}
		// The edit of this occurrence was removed on the client side (occurrence
		// deleted — its EXDATE is in the master of the same PUT — or edit
		// cancelled). A row already gone on the Proton side is not an error.
		if derr := b.src.DeleteEvent(ctx, calID, row.ID); derr != nil && !errors.Is(derr, proton.ErrEventNotFound) {
			return "", mapSourceError(derr)
		}
	}

	return anchorID, nil
}

// putResponse re-reads the COMPLETE state of the written group (by UID — the
// write-through cache is already up to date row by row) to return the FOLDED
// resource with its fresh ETag: Apple's immediate re-read must see exactly what
// it just wrote. If the re-read fails, a minimal object dated now (the write
// succeeded, the client will resync).
func (b *Backend) putResponse(ctx context.Context, calID, uid, fallbackID string) (*webcaldav.CalendarObject, error) {
	group, err := b.src.ListEventsByUID(ctx, calID, uid)
	if err == nil && len(group) > 0 {
		if folded, _, ferr := b.foldGroup(group); ferr == nil {
			return folded, nil
		}
	}
	now := time.Now()
	return &webcaldav.CalendarObject{
		Path:    b.objectPath(calID, fallbackID),
		ModTime: now,
		ETag:    strconv.FormatInt(now.Unix(), 10),
	}, nil
}

// invitePlan describes the iMIP notifications due after the successful update of
// an invited event (M5b): the invitee diff (by email, case-insensitive) and the
// significance of the event diff.
type invitePlan struct {
	final       proton.EventInput      // final written state — the base of the REQUEST ICS
	kept        []proton.AttendeeInput // kept invitees (notified if significant)
	added       []proton.AttendeeInput // added invitees (always REQUEST)
	removed     []proton.AttendeeInput // removed invitees (always CANCEL)
	significant bool                   // the WHEN/WHERE changes (bounds, recurrence, EXDATE, location)
	sequence    int                    // Proton SEQUENCE AFTER the update — carried by the iMIP
}

// attendeesChanged says whether the invitee list itself moved.
func (p *invitePlan) attendeesChanged() bool { return len(p.added)+len(p.removed) > 0 }

// planInviteLifecycle computes the invitee diff PUT vs Proton state — the stable
// part of the plan; the event diff (significance/SEQUENCE) is recomputed by
// refreshSignificance on the entry ultimately written.
func (b *Backend) planInviteLifecycle(in proton.EventInput, row proton.Event) *invitePlan {
	p := &invitePlan{}
	rowByEmail := make(map[string]bool, len(row.Attendees))
	for _, at := range row.Attendees {
		rowByEmail[strings.ToLower(at.Email)] = true
	}
	seen := make(map[string]bool, len(in.Attendees))
	for _, at := range in.Attendees {
		key := strings.ToLower(at.Email)
		seen[key] = true
		if rowByEmail[key] {
			p.kept = append(p.kept, at)
		} else {
			p.added = append(p.added, at)
		}
	}
	for _, at := range row.Attendees {
		if !seen[strings.ToLower(at.Email)] {
			p.removed = append(p.removed, proton.AttendeeInput{Email: at.Email, CN: at.CN})
		}
	}
	p.refreshSignificance(in, row)
	return p
}

// refreshSignificance (re)computes the EVENT part of the plan on the entry
// actually written (EXDATE merged, flags set):
//   - significant = the when/where changes — bounds, all-day, RRULE, EXDATE,
//     LOCATION → re-REQUEST to the kept invitees;
//   - cosmetic (SUMMARY/DESCRIPTION/alarms/STATUS) → update without
//     re-notification (the posture of the big calendars);
//   - sequence = mirror of the Proton update path's bump: +1 on a structural
//     change (bounds/RRULE/EXDATE — diffPatches) OR an invitee diff
//     (planAttendeeUpdate). LOCATION alone re-notifies WITHOUT a bump (RFC 5546
//     does not require it; the more recent DTSTAMP is enough for clients).
func (p *invitePlan) refreshSignificance(in proton.EventInput, row proton.Event) {
	structural := !in.Start.Equal(row.Start) || !in.End.Equal(row.End) ||
		in.AllDay != row.AllDay || in.RRule != row.RRule ||
		(in.RRule != "" && !sameInstantSet(in.ExDates, row.ExDates))
	p.significant = structural || in.Location != row.Location
	p.sequence = row.Sequence
	if structural || p.attendeesChanged() {
		p.sequence++
	}
	p.final = in
	if p.final.Organizer == "" {
		// PUT without ORGANIZER (removal of all invitees by a client that also
		// strips the organizer): the Proton address stays the sender.
		p.final.Organizer = row.Organizer
	}
}

// sendLifecycleInvitations emits the iMIP emails due from an update of an
// invited event: CANCEL to the removed, REQUEST to the added, "updated" REQUEST
// to the kept when the when/where has changed. Best-effort by design (the Proton
// sync already succeeded) — a failure is logged per recipient, never a PUT
// failure.
func (b *Backend) sendLifecycleInvitations(ctx context.Context, p *invitePlan) {
	now := time.Now().UTC()
	title := titleOrDefault(p.final.Title)
	if len(p.removed) > 0 {
		cin := p.final
		cin.Attendees = p.removed // the CANCEL ICS lists only the cancelled ones
		b.sendIMIP(ctx, cin, invite.MethodCancel, p.sequence,
			"Cancelled: "+title, cancellationText(cin), p.removed, now)
	}
	if len(p.added) > 0 {
		b.sendIMIP(ctx, p.final, invite.MethodRequest, p.sequence,
			"Invitation: "+title, invitationText(p.final, "Invitation"), p.added, now)
	}
	if p.significant && len(p.kept) > 0 {
		b.sendIMIP(ctx, p.final, invite.MethodRequest, p.sequence,
			"Updated invitation: "+title, invitationText(p.final, "Updated invitation"), p.kept, now)
	}
}

// sendInvitations builds and sends the iMIP REQUEST email of each invitee of an
// outgoing CREATION (M5a).
func (b *Backend) sendInvitations(ctx context.Context, in proton.EventInput) {
	b.sendIMIP(ctx, in, invite.MethodRequest, in.Sequence,
		"Invitation: "+titleOrDefault(in.Title), invitationText(in, "Invitation"),
		in.Attendees, time.Now().UTC())
}

// ---- Outgoing RSVP (M6b) ----

// rsvpReply describes a reply by the account owner to a RECEIVED invitation:
// their invitee row on the Proton side (identity + attendeeID, the key of the
// dedicated endpoint) and their new status (1/2/3 = TENTATIVE/DECLINED/ACCEPTED)
// with the corresponding PARTSTAT.
type rsvpReply struct {
	attendee  proton.Attendee // the account owner's row on the Proton side (ID/Email/CN/Token/Status)
	newStatus int             // 1/2/3
	partstat  string          // corresponding iCal PARTSTAT
}

// detectOwnRSVP recognizes a PUT that changes ONLY the PARTSTAT of the account
// owner's own row (an account address) — the only legitimate delta to propagate
// onto an event organized by a third party. Returns ok=false as soon as
// ANYTHING ELSE moves (bounds, recurrence, title/location, invitee set, a third
// party's PARTSTAT): that case stays a 403 ATTENDEE-FOREIGN refusal (we never
// rewrite the third party's event). in is the master parsed from the PUT, row
// the Proton state.
func (b *Backend) detectOwnRSVP(in proton.EventInput, row proton.Event) (rsvpReply, bool) {
	// 1) Nothing but the PARTSTAT may move.
	if !sameEventShape(in, row) {
		return rsvpReply{}, false
	}
	// 2) The invitee set (by email) must be identical.
	if !sameAttendeeSet(in.Attendees, row.Attendees) {
		return rsvpReply{}, false
	}
	// 3) Exactly ONE row changes status, and it is an account address (the
	//    account owner only replies for themselves) carrying a patchable attendeeID.
	rowByEmail := make(map[string]proton.Attendee, len(row.Attendees))
	for _, at := range row.Attendees {
		rowByEmail[strings.ToLower(at.Email)] = at
	}
	var reply rsvpReply
	changed := 0
	for _, at := range in.Attendees {
		rat, ok := rowByEmail[strings.ToLower(at.Email)]
		if !ok {
			return rsvpReply{}, false
		}
		ns := statusFromPartstat(at.Partstat)
		if ns == rat.Status {
			continue
		}
		changed++
		if changed > 1 || !b.isOwner(at.Email) || rat.ID == "" || ns == 0 {
			// More than one row moves, or the account owner tries to reply for a
			// third party, or no attendeeID (impossible to patch), or a return to
			// NEEDS-ACTION (not a real reply) → not an RSVP.
			return rsvpReply{}, false
		}
		reply = rsvpReply{attendee: rat, newStatus: ns, partstat: partstatFromStatus(ns)}
	}
	if changed != 1 {
		return rsvpReply{}, false
	}
	return reply, true
}

// sameEventShape compares everything that, apart from the PARTSTAT, defines the
// event: bounds, recurrence, texts, STATUS/TRANSP (with defaults applied). A
// single difference forbids the RSVP path (the third party's event must never be
// rewritten).
func sameEventShape(in proton.EventInput, row proton.Event) bool {
	if !in.Start.Equal(row.Start) || !in.End.Equal(row.End) || in.AllDay != row.AllDay {
		return false
	}
	if in.RRule != row.RRule || !sameInstantSet(in.ExDates, row.ExDates) {
		return false
	}
	if in.Title != row.Title || in.Description != row.Description || in.Location != row.Location {
		return false
	}
	return defaulted(in.Status, "CONFIRMED") == defaulted(row.Status, "CONFIRMED") &&
		defaulted(in.Transp, "OPAQUE") == defaulted(row.Transp, "OPAQUE")
}

// defaulted applies a default value to an absent property (mirror of the RFC
// 5545 defaults applied on the proton.statusOrDefault/transpOrDefault side).
func defaulted(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// sameAttendeeSet compares two invitee lists by email (case-insensitive),
// independently of the PARTSTAT and of the order.
func sameAttendeeSet(in []proton.AttendeeInput, row []proton.Attendee) bool {
	if len(in) != len(row) {
		return false
	}
	set := make(map[string]bool, len(row))
	for _, at := range row {
		set[strings.ToLower(at.Email)] = true
	}
	for _, at := range in {
		if !set[strings.ToLower(at.Email)] {
			return false
		}
	}
	return true
}

// handleOutgoingRSVP applies a reply by the account owner (M6b): PATCH of the
// PARTSTAT of their row via the dedicated endpoint (authoritative state first —
// same discipline as M5a: sync then email), THEN an iMIP REPLY to the
// third-party organizer (best-effort). The third party's event is NEVER
// rewritten. The re-read folded resource reflects the new PARTSTAT served to
// Apple.
func (b *Backend) handleOutgoingRSVP(ctx context.Context, calID, uid string, row *proton.Event, reply rsvpReply) (*webcaldav.CalendarObject, error) {
	updater, ok := b.src.(AttendeeStatusUpdater)
	if !ok {
		// The backend cannot patch an attendee: rather than a REPLY emitted
		// without an up-to-date state, an honest refusal (the client reverts
		// cleanly).
		return nil, webdav.NewHTTPError(http.StatusForbidden,
			fmt.Errorf("%w: ATTENDEE-FOREIGN — RSVP not supported by this backend", errICalRefused))
	}
	if err := updater.UpdateAttendeeStatus(ctx, calID, row.ID, reply.attendee.ID, reply.newStatus); err != nil {
		return nil, mapSourceError(err)
	}
	b.sendReply(ctx, *row, reply)
	return b.putResponse(ctx, calID, uid, row.ID)
}

// sendReply builds and sends the iMIP REPLY of a reply by the account owner
// (From = the account owner, To = the third-party organizer). Best-effort by
// design: the Proton status is already up to date, a send failure is logged
// (organizer masked) without failing the PUT. Subject to the same send quota as
// the REQUEST/CANCEL.
func (b *Backend) sendReply(ctx context.Context, row proton.Event, reply rsvpReply) {
	in := eventToInput(row) // UID / third-party ORGANIZER / bounds / title
	ics, err := ReplyICS(in, proton.AttendeeInput{Email: reply.attendee.Email, CN: reply.attendee.CN},
		reply.partstat, row.Sequence, time.Now().UTC())
	if err != nil {
		log.Printf("invite: ERROR building REPLY (uid truncated %.8s…): %v", row.UID, err)
		return
	}
	if !b.inviteQuota.allow() {
		log.Printf("invite: daily send QUOTA reached (%d) — REPLY to %s NOT sent", maxInvitesPerDay, maskEmail(row.Organizer))
		return
	}
	fromName := b.inviteFromName
	if fromName == "" {
		fromName = reply.attendee.CN
	}
	if fromName == "" {
		fromName = reply.attendee.Email
	}
	m := invite.Message{
		FromName: fromName,
		From:     reply.attendee.Email, // the account owner, never the organizer
		To:       row.Organizer,        // the third-party organizer
		Subject:  replyVerb(reply.partstat) + ": " + titleOrDefault(row.Title),
		Text:     replyText(reply.partstat, in),
		ICS:      ics,
		Method:   invite.MethodReply,
	}
	if err := b.inviteSender.Send(ctx, m); err != nil {
		log.Printf("invite: ERROR sending REPLY to %s: %v", maskEmail(row.Organizer), err)
	} else {
		log.Printf("invite: REPLY %s (seq %d) sent to %s (uid truncated %.8s…)", reply.partstat, row.Sequence, maskEmail(row.Organizer), row.UID)
	}
}

// sendIMIP builds ONE iMIP ICS (given method/sequence) and sends it to each
// recipient (one email per invitee, From = ORGANIZER exactly). Best-effort by
// design: the Proton state is already true, a send failure is logged per
// recipient (manual retry possible) and the CalDAV operation succeeds.
func (b *Backend) sendIMIP(ctx context.Context, in proton.EventInput, method string, sequence int, subject, text string, recipients []proton.AttendeeInput, now time.Time) {
	ics, err := InvitationICS(in, method, sequence, now)
	if err != nil {
		log.Printf("invite: ERROR building the %s ICS (uid truncated %.8s…): %v", method, in.UID, err)
		return
	}
	fromName := b.inviteFromName
	if fromName == "" {
		fromName = in.OrganizerCN
	}
	if fromName == "" {
		fromName = in.Organizer
	}
	for _, at := range recipients {
		// SECURITY (audit 2026-07-17): GLOBAL send quota — the per-event ceiling
		// (maxInviteesPerEvent) does not stop an authenticated client from
		// looping over N events for a mass send "as the account owner". Beyond
		// the daily quota, we refuse (the event stays written, only the email is
		// cut — same best-effort posture as the rest).
		if !b.inviteQuota.allow() {
			log.Printf("invite: daily send QUOTA reached (%d) — %s to %s NOT sent", maxInvitesPerDay, method, maskEmail(at.Email))
			continue
		}
		m := invite.Message{
			FromName: fromName,
			From:     in.Organizer,
			To:       at.Email,
			Subject:  subject,
			Text:     text,
			ICS:      ics,
			Method:   method,
		}
		// Emails masked in the logs (personal data — same posture as the
		// truncated UID; audit 2026-07-17).
		if err := b.inviteSender.Send(ctx, m); err != nil {
			log.Printf("invite: ERROR sending %s to %s: %v", method, maskEmail(at.Email), err)
		} else {
			log.Printf("invite: %s (seq %d) sent to %s (uid truncated %.8s…)", method, sequence, maskEmail(at.Email), in.UID)
		}
	}
}

// maskEmail reduces an email to "a…@domain" for the logs (personal data).
func maskEmail(e string) string {
	at := strings.IndexByte(e, '@')
	if at <= 0 {
		return "…"
	}
	return e[:1] + "…" + e[at:]
}

// maxInvitesPerDay bounds the TOTAL number of invitation emails sent over a
// rolling 24 h window, across all events (security audit 2026-07-17,
// anti-amplification). Well above family usage (a few invitations/week).
const maxInvitesPerDay = 200

// inviteRateLimiter is a send counter over a rolling 24 h window.
type inviteRateLimiter struct {
	mu     sync.Mutex
	window time.Time
	count  int
}

// allow increments and reports whether the send is under the daily quota. The
// window resets after 24 h. now injected by the test; time.Now otherwise.
func (r *inviteRateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.Sub(r.window) >= 24*time.Hour {
		r.window = now
		r.count = 0
	}
	if r.count >= maxInvitesPerDay {
		return false
	}
	r.count++
	return true
}

// DeleteCalendarObject deletes the resource: the targeted row, and — when it is
// a master — ALL its same-UID exception-rows (batched in one sync call on the
// proton.DeleteEvent side, group purge on the cache side): zero debris.
func (b *Backend) DeleteCalendarObject(ctx context.Context, urlPath string) error {
	calID, eventID, err := b.parsePath(urlPath)
	if err != nil {
		return err
	}
	if eventID == "" {
		return webdav.NewHTTPError(http.StatusForbidden, errors.New("caldav: cannot DELETE a collection path"))
	}
	// Same alias resolution as GetCalendarObject: a DELETE may target the name
	// chosen by the client before it has picked up the 201's Location.
	if ar, ok := b.src.(AliasResolver); ok {
		if _, kerr := b.src.GetEvent(ctx, calID, eventID); errors.Is(kerr, proton.ErrEventNotFound) {
			if id, found := ar.ResolveAlias(calID, eventID); found {
				eventID = id
			}
		}
	}
	// M5b: the DELETE of an invited event ORGANIZED BY THE ACCOUNT emits an iMIP
	// CANCEL to each invitee AFTER the deletion succeeds — best-effort, same
	// posture as M5a (a send failure never fails the DELETE, log ERROR per
	// recipient). The uncovered cases (third-party organizer, [invite] absent,
	// isolated exception-row) stay traced as WARN: the invitees keep the event in
	// their agenda.
	var cancelIn *proton.EventInput
	cancelSeq := 0
	if ev, gerr := b.src.GetEvent(ctx, calID, eventID); gerr == nil && len(ev.Attendees) > 0 {
		switch {
		case b.inviteSender == nil || !b.isOwner(ev.Organizer):
			log.Printf("caldav: WARN delete of an event with %d invitee(s) (uid truncated %.8s…) — invitees NOT notified (third-party organizer or [invite] absent)",
				len(ev.Attendees), ev.UID)
		case ev.RecurrenceID != 0:
			// Isolated exception-row: a CANCEL without RECURRENCE-ID would cancel
			// the WHOLE series at the invitee — the per-occurrence CANCEL is M6.
			log.Printf("caldav: WARN delete of an exception-row with invitees (uid truncated %.8s…) — invitees NOT notified (per-occurrence CANCEL = M6)", ev.UID)
		default:
			in := eventToInput(*ev)
			cancelIn = &in
			cancelSeq = ev.Sequence + 1 // the CANCEL supersedes the last known REQUEST
		}
	}
	if err := b.src.DeleteEvent(ctx, calID, eventID); err != nil {
		return mapSourceError(err)
	}
	if cancelIn != nil {
		b.sendIMIP(ctx, *cancelIn, invite.MethodCancel, cancelSeq,
			"Cancelled: "+titleOrDefault(cancelIn.Title), cancellationText(*cancelIn),
			cancelIn.Attendees, time.Now().UTC())
	}
	return nil
}

// eventToInput projects a decrypted Proton event into an EventInput — the base
// of the iMIP ICS emitted outside a PUT (CANCEL on DELETE). NEVER used to write.
func eventToInput(ev proton.Event) proton.EventInput {
	in := proton.EventInput{
		UID: ev.UID, Title: ev.Title, Description: ev.Description, Location: ev.Location,
		Start: ev.Start, End: ev.End, TZID: ev.TZ, EndTZID: ev.EndTZ, AllDay: ev.AllDay,
		RRule: ev.RRule, ExDates: ev.ExDates, Sequence: ev.Sequence, Organizer: ev.Organizer,
	}
	for _, at := range ev.Attendees {
		in.Attendees = append(in.Attendees, proton.AttendeeInput{Email: at.Email, CN: at.CN})
	}
	return in
}

// mapSourceError translates the typed errors of internal/proton into honest
// CalDAV statuses: not-found → 404 (clean disappearance — a 500 in the
// multistatus makes dataaccessd loop on the phantom href), re-seal impossible →
// 403 (the client reverts, no silent loss). The rest passes through as-is (500).
func mapSourceError(err error) error {
	switch {
	case errors.Is(err, proton.ErrEventNotFound):
		return webdav.NewHTTPError(http.StatusNotFound, err)
	case errors.Is(err, proton.ErrEventDegraded):
		return webdav.NewHTTPError(http.StatusForbidden, err)
	default:
		return err
	}
}

// ---- Helpers ----

// objectsInWindow lists the resources of the window, FOLDED by UID (RFC 4791: a
// UID = a single resource per collection). Simple events pass through as-is;
// every series (recurring master or exception-row) is re-resolved by UID on the
// COMPLETE store state — exception-rows may live outside the window, and the
// folded resource must be identical in REPORT and in GET (same content, same
// ETag).
func (b *Backend) objectsInWindow(ctx context.Context, calID string, start, end time.Time) ([]webcaldav.CalendarObject, error) {
	events, err := b.src.ListEvents(ctx, calID, start, end)
	if err != nil {
		return nil, err
	}
	// Grouping by UID, first-appearance order preserved (sorted by Start).
	byUID := make(map[string][]proton.Event)
	order := make([]string, 0, len(events))
	for _, ev := range events {
		if _, ok := byUID[ev.UID]; !ok {
			order = append(order, ev.UID)
		}
		byUID[ev.UID] = append(byUID[ev.UID], ev)
	}

	out := make([]webcaldav.CalendarObject, 0, len(order))
	appendObj := func(ev proton.Event) {
		// Lenient on read: an unserializable event (e.g. empty UID after a
		// decryption failure) does not break the collection.
		if obj, oerr := b.toObject(ev); oerr == nil {
			out = append(out, *obj)
		}
	}
	for _, uid := range order {
		g := byUID[uid]
		if len(g) == 1 && g[0].RRule == "" && g[0].RecurrenceID == 0 {
			appendObj(g[0])
			continue
		}
		// Series (or multi-row UID): complete state by UID. Fallback to the
		// window's rows if resolution fails (never a broken collection) — the
		// store already sorts master first.
		group, gerr := b.src.ListEventsByUID(ctx, calID, uid)
		if gerr != nil || len(group) == 0 {
			group = sortSeriesRows(g)
		}
		folded, extras, ferr := b.foldGroup(group)
		if ferr == nil {
			out = append(out, *folded)
		}
		for _, ex := range extras {
			appendObj(ex)
		}
	}
	return out, nil
}

// foldGroup separates a same-UID group (sorted master first) into the FOLDED
// resource — anchored on the master's href, otherwise on the first exception (an
// orphan group, served rather than lost) — and any SUPERNUMERARY masters
// (degenerate data: two rows without a RecurrenceID), served as separate
// resources rather than in an invalid VCALENDAR.
func (b *Backend) foldGroup(group []proton.Event) (*webcaldav.CalendarObject, []proton.Event, error) {
	folded := make([]proton.Event, 0, len(group))
	var extras []proton.Event
	seenMaster := false
	for _, ev := range group {
		if ev.RecurrenceID == 0 {
			if seenMaster {
				extras = append(extras, ev)
				continue
			}
			seenMaster = true
		}
		folded = append(folded, ev)
	}
	obj, err := b.toFoldedObject(folded)
	return obj, extras, err
}

func (b *Backend) toObject(ev proton.Event) (*webcaldav.CalendarObject, error) {
	return b.toFoldedObject([]proton.Event{ev})
}

// toFoldedObject serializes a group (already folded, anchor first) into a CalDAV
// object: the anchor's href, ModTime = last edit of the group, ETag that changes
// as soon as ANY row of the group changes (or disappears).
func (b *Backend) toFoldedObject(group []proton.Event) (*webcaldav.CalendarObject, error) {
	cal, err := SeriesToICal(group)
	if err != nil {
		return nil, err
	}
	anchor := group[0]
	mod := anchor.LastEdit
	for _, ev := range group[1:] {
		if ev.LastEdit.After(mod) {
			mod = ev.LastEdit
		}
	}
	return &webcaldav.CalendarObject{
		Path:    b.objectPath(anchor.CalendarID, anchor.ID),
		ModTime: mod,
		ETag:    groupETag(group),
		Data:    cal,
	}, nil
}

// etagSchemaVersion versions the serialized FORM of the resources in ALL the
// ETag computations. The served content can change without Proton's LastEdit
// moving (v2: TZID + VTIMEZONE rendering instead of bare UTC, 2026-07-16; v3:
// ATTENDEE/ORGANIZER now served, M5a) — incrementing this constant invalidates
// every ETag and forces a full re-download on the paired clients: it is the
// self-healing mechanism for dataaccessd caches contaminated by the old form.
const etagSchemaVersion = 3

// groupETag computes the ETag of a folded resource. A single row stays on the
// readable form (schema version + LastEditTime); a group is hashed over (ID,
// LastEdit) of EACH row: the max of the ModifyTime would not be enough (deleting
// a non-max row would leave the ETag unchanged).
func groupETag(group []proton.Event) string {
	if len(group) == 1 {
		return fmt.Sprintf("v%d-%d", etagSchemaVersion, group[0].LastEdit.Unix())
	}
	h := fnv.New64a()
	fmt.Fprintf(h, "v%d;", etagSchemaVersion)
	for _, ev := range group {
		fmt.Fprintf(h, "%s:%d;", ev.ID, ev.LastEdit.Unix())
	}
	return strconv.FormatUint(h.Sum64(), 16)
}

// mergePastExDates merges the EXDATE of a series PUT with the Proton history:
// union (existing STRICTLY past EXDATE — before the current day's UTC midnight,
// ALWAYS kept) ∪ (the client's list, which stays master for today/future). A
// past occurrence is never "restored" from the Apple UI — the guard therefore
// removes no feature, it only prevents Apple's resync horizon from erasing the
// cancellation history (damage seen on 2026-07-16: 46 past EXDATE lost in
// Proton). Deduplicated by instant, sorted chronologically.
func mergePastExDates(existing, client []time.Time, now time.Time) []time.Time {
	cutoff := now.UTC().Truncate(24 * time.Hour)
	out := make([]time.Time, 0, len(client)+len(existing))
	seen := make(map[int64]bool, len(client)+len(existing))
	for _, ex := range client {
		if !seen[ex.Unix()] {
			seen[ex.Unix()] = true
			out = append(out, ex)
		}
	}
	for _, ex := range existing {
		if !ex.Before(cutoff) {
			continue // today/future: the client is master
		}
		if !seen[ex.Unix()] {
			seen[ex.Unix()] = true
			out = append(out, ex)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// sameInstantSet compares two sets of instants independently of the order —
// the caldav mirror of proton.sameInstants, for the significant diff of the
// invitation plan (EXDATE).
func sameInstantSet(a, b []time.Time) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]time.Time(nil), a...)
	bs := append([]time.Time(nil), b...)
	sort.Slice(as, func(i, j int) bool { return as[i].Before(as[j]) })
	sort.Slice(bs, func(i, j int) bool { return bs[i].Before(bs[j]) })
	for i := range as {
		if !as[i].Equal(bs[i]) {
			return false
		}
	}
	return true
}

// sortSeriesRows sorts same-UID rows in folding order (master first, then
// ascending RecurrenceID) — same contract as proton.Account.ListEventsByUID, for
// the local fallbacks.
func sortSeriesRows(rows []proton.Event) []proton.Event {
	out := append([]proton.Event(nil), rows...)
	sort.Slice(out, func(i, j int) bool {
		if (out[i].RecurrenceID == 0) != (out[j].RecurrenceID == 0) {
			return out[i].RecurrenceID == 0
		}
		if out[i].RecurrenceID != out[j].RecurrenceID {
			return out[i].RecurrenceID < out[j].RecurrenceID
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (b *Backend) calendarPath(calID string) string {
	return b.homeSetPath + calID + "/"
}

func (b *Backend) objectPath(calID, eventID string) string {
	return b.calendarPath(calID) + eventID + ".ics"
}

// parsePath decomposes /{user}/calendars/{calID}[/{evID}.ics]; eventID is empty
// for a collection path.
func (b *Backend) parsePath(urlPath string) (calID, eventID string, err error) {
	p := path.Clean("/" + urlPath)
	rest, ok := strings.CutPrefix(p, strings.TrimSuffix(b.homeSetPath, "/"))
	if !ok || (rest != "" && !strings.HasPrefix(rest, "/")) {
		return "", "", webdav.NewHTTPError(http.StatusNotFound, fmt.Errorf("caldav: path %q outside %s", urlPath, b.homeSetPath))
	}
	rest = strings.Trim(rest, "/")
	if rest == "" {
		return "", "", webdav.NewHTTPError(http.StatusNotFound, errors.New("caldav: home set is not a calendar"))
	}
	parts := strings.Split(rest, "/")
	switch len(parts) {
	case 1:
		return parts[0], "", nil
	case 2:
		evID, ok := strings.CutSuffix(parts[1], ".ics")
		if !ok || evID == "" {
			return "", "", webdav.NewHTTPError(http.StatusNotFound, fmt.Errorf("caldav: %q is not an .ics object", urlPath))
		}
		return parts[0], evID, nil
	default:
		return "", "", webdav.NewHTTPError(http.StatusNotFound, fmt.Errorf("caldav: path %q too deep", urlPath))
	}
}

// timeRange extracts the first time-range of a CompFilter tree (typically
// VCALENDAR > VEVENT).
func timeRange(f webcaldav.CompFilter) (start, end time.Time, ok bool) {
	if !f.Start.IsZero() || !f.End.IsZero() {
		return f.Start, f.End, true
	}
	for _, child := range f.Comps {
		if s, e, ok := timeRange(child); ok {
			return s, e, true
		}
	}
	return time.Time{}, time.Time{}, false
}
